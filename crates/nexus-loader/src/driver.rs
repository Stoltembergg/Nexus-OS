//! Windows NT Kernel Driver (`.sys`) Loader & WDM Host Subsystem.
//!
//! Provides parsing, section mapping, relocation processing, dynamic kernel export binding,
//! native `DriverEntry` execution, IRP dispatching, and safe driver unloading for
//! Windows NT kernel-mode drivers (`IMAGE_SUBSYSTEM_NATIVE`).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};
use nexus_types::driver::{
    DeviceObject, DriverEntryFn, DriverObject, DriverSectionMapping, Irp, KEvent, Kirql,
    UnicodeString, DISPATCH_LEVEL, IMAGE_SUBSYSTEM_NATIVE, IRP_MJ_MAXIMUM_FUNCTION, PASSIVE_LEVEL,
    STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS,
};

use crate::error::LoaderError;
use crate::pe::{PeImage, IMAGE_REL_BASED_DIR64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

/// `IMAGE_FILE_HEADER.Characteristics` flag: base relocations were removed from the file.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

/// Global IRQL tracking register for the NT host executive (software fallback).
pub static CURRENT_IRQL: AtomicU8 = AtomicU8::new(PASSIVE_LEVEL);

/// Hardware IRQL getter callback hook (e.g. reading CR8 / TPR on bare metal).
pub static HARDWARE_IRQL_GETTER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Hardware IRQL setter callback hook (e.g. writing CR8 / TPR on bare metal).
pub static HARDWARE_IRQL_SETTER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Serializes host tests that touch the NT host's process-global state.
#[cfg(not(any(target_os = "uefi", target_os = "none")))]
static NT_HOST_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test support (host builds only): takes exclusive ownership of the NT host's
/// process-global state (software IRQL, hardware IRQL hooks, pool registry) and resets
/// IRQL to `PASSIVE_LEVEL` with no hardware hooks installed.
///
/// `cargo test` runs tests in parallel threads; without this, one test lowering the
/// global IRQL while another holds a spin lock made `standard_wdm`'s spin-lock IOCTL
/// observe the wrong IRQL (audit finding B2, `counter 100 != 101`).
#[doc(hidden)]
#[cfg(not(any(target_os = "uefi", target_os = "none")))]
pub fn lock_nt_host_state_for_tests() -> std::sync::MutexGuard<'static, ()> {
    let guard = NT_HOST_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    HARDWARE_IRQL_GETTER.store(core::ptr::null_mut(), Ordering::SeqCst);
    HARDWARE_IRQL_SETTER.store(core::ptr::null_mut(), Ordering::SeqCst);
    CURRENT_IRQL.store(PASSIVE_LEVEL, Ordering::SeqCst);
    guard
}

/// Maximum number of simultaneously live pool allocations tracked by the host.
pub const POOL_TRACKER_CAPACITY: usize = 256;

/// One live pool block: (address, size in bytes, tag). Address 0 marks a free slot.
type PoolSlot = (usize, usize, u32);

/// Fixed-capacity registry of live pool blocks.
///
/// Frees are validated against this registry instead of reading a header in front of the
/// pointer, so a double free or a foreign pointer is detected without touching freed memory.
/// The registry never allocates, so it does not perturb kernel heap accounting.
struct PoolTracker {
    lock: AtomicBool,
    slots: core::cell::UnsafeCell<[PoolSlot; POOL_TRACKER_CAPACITY]>,
}

// SAFETY: every access to `slots` happens while `lock` is held.
unsafe impl Sync for PoolTracker {}

impl PoolTracker {
    fn with<R>(&self, f: impl FnOnce(&mut [PoolSlot; POOL_TRACKER_CAPACITY]) -> R) -> R {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the spin lock above grants exclusive access.
        let result = f(unsafe { &mut *self.slots.get() });
        self.lock.store(false, Ordering::Release);
        result
    }
}

static POOL_TRACKER: PoolTracker = PoolTracker {
    lock: AtomicBool::new(false),
    slots: core::cell::UnsafeCell::new([(0, 0, 0); POOL_TRACKER_CAPACITY]),
};

/// Count of rejected pool frees (double free, unknown pointer, tag mismatch).
static POOL_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

/// Number of pool blocks currently allocated through `ExAllocatePoolWithTag`.
pub fn live_pool_allocations() -> usize {
    POOL_TRACKER.with(|slots| slots.iter().filter(|s| s.0 != 0).count())
}

/// Number of invalid pool frees observed since boot (monotonic).
pub fn pool_violations() -> usize {
    POOL_VIOLATIONS.load(Ordering::SeqCst)
}

/// Errors encountered while loading, binding, and executing an NT kernel driver.
#[derive(Debug, PartialEq, Eq)]
pub enum NtDriverError {
    Loader(LoaderError),
    InvalidImageFormat,
    NotNativeDriver(u16),
    NoEntryPoint,
    RelocationFailed,
    UnresolvedImport {
        dll: String,
        function: String,
    },
    MemoryAllocationFailed,
    DriverEntryFailed(i32),
    NoUnloadRoutine,
    ProtectionFailed,
    /// The image must be rebased but carries `IMAGE_FILE_RELOCS_STRIPPED`.
    RelocationsStripped,
    /// A section, relocation target or IAT slot falls outside the mapped image.
    ImageOutOfBounds,
    /// A section requests simultaneous write and execute permission (W^X violation).
    WritableExecutableSection,
    /// `DriverUnload` returned with device objects still attached to the driver.
    DevicesLeaked,
    /// `DriverUnload` returned with this many more live pool blocks than before `DriverEntry`.
    PoolLeaked(usize),
    /// The driver performed this many invalid pool frees during its lifetime.
    PoolViolations(usize),
}

impl From<LoaderError> for NtDriverError {
    fn from(err: LoaderError) -> Self {
        Self::Loader(err)
    }
}

/// Buffer for executable kernel driver memory.
pub struct ExecutableBuffer {
    ptr: *mut u8,
    size: usize,
}

unsafe impl Send for ExecutableBuffer {}
unsafe impl Sync for ExecutableBuffer {}

impl core::fmt::Debug for ExecutableBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExecutableBuffer")
            .field("ptr", &self.ptr)
            .field("size", &self.size)
            .finish()
    }
}

#[cfg(windows)]
impl ExecutableBuffer {
    pub fn allocate(size: usize) -> Result<Self, NtDriverError> {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualAlloc(
                lpAddress: *mut c_void,
                dwSize: usize,
                flAllocationType: u32,
                flProtect: u32,
            ) -> *mut c_void;
        }

        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const PAGE_READWRITE: u32 = 0x04;

        let ptr = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if ptr.is_null() {
            return Err(NtDriverError::MemoryAllocationFailed);
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
        })
    }

    pub fn protect_range(
        &self,
        offset: usize,
        size: usize,
        writable: bool,
        executable: bool,
    ) -> Result<(), NtDriverError> {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualProtect(
                lpAddress: *mut c_void,
                dwSize: usize,
                flNewProtect: u32,
                lpflOldProtect: *mut u32,
            ) -> i32;
        }

        // Strict W^X policy: RWX is strictly forbidden!
        let protect = match (writable, executable) {
            (false, false) => 0x02, // PAGE_READONLY
            (false, true) => 0x20,  // PAGE_EXECUTE_READ
            (true, false) => 0x04,  // PAGE_READWRITE
            (true, true) => return Err(NtDriverError::ProtectionFailed),
        };

        let mut old = 0u32;
        let res =
            unsafe { VirtualProtect(self.ptr.add(offset) as *mut c_void, size, protect, &mut old) };

        if res == 0 {
            return Err(NtDriverError::ProtectionFailed);
        }

        Ok(())
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(windows)]
impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
        }

        const MEM_RELEASE: u32 = 0x8000;
        if !self.ptr.is_null() {
            unsafe {
                VirtualFree(self.ptr as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(all(unix, not(windows)))]
impl ExecutableBuffer {
    pub fn allocate(size: usize) -> Result<Self, NtDriverError> {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED || ptr.is_null() {
            return Err(NtDriverError::MemoryAllocationFailed);
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
        })
    }

    pub fn protect_range(
        &self,
        offset: usize,
        size: usize,
        writable: bool,
        executable: bool,
    ) -> Result<(), NtDriverError> {
        let prot = match (writable, executable) {
            (false, false) => libc::PROT_READ,
            (false, true) => libc::PROT_READ | libc::PROT_EXEC,
            (true, false) => libc::PROT_READ | libc::PROT_WRITE,
            (true, true) => return Err(NtDriverError::ProtectionFailed),
        };

        let res = unsafe { libc::mprotect(self.ptr.add(offset) as *mut c_void, size, prot) };
        if res != 0 {
            return Err(NtDriverError::ProtectionFailed);
        }
        Ok(())
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(all(unix, not(windows)))]
impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut c_void, self.size);
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
impl ExecutableBuffer {
    pub fn allocate(size: usize) -> Result<Self, NtDriverError> {
        let layout = alloc::alloc::Layout::from_size_align(size, 4096)
            .map_err(|_| NtDriverError::MemoryAllocationFailed)?;
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(NtDriverError::MemoryAllocationFailed);
        }

        Ok(Self { ptr, size })
    }

    pub fn protect_range(
        &self,
        _offset: usize,
        _size: usize,
        _writable: bool,
        _executable: bool,
    ) -> Result<(), NtDriverError> {
        Ok(())
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(not(any(windows, unix)))]
impl Drop for ExecutableBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let layout = alloc::alloc::Layout::from_size_align(self.size, 4096).unwrap();
            unsafe { alloc::alloc::dealloc(self.ptr, layout) };
        }
    }
}

/// Simulated NT Kernel function table providing fundamental `ntoskrnl.exe` and `hal.dll` exports.
pub struct NtoskrnlTable {
    exports: BTreeMap<(String, String), usize>,
}

impl Default for NtoskrnlTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NtoskrnlTable {
    /// Creates a new kernel export table populated with standard WDM foundation routines.
    pub fn new() -> Self {
        let mut table = Self {
            exports: BTreeMap::new(),
        };

        // Core I/O and Driver Management
        table.register(
            "NTOSKRNL.EXE",
            "DbgPrint",
            stub_dbg_print as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCreateDevice",
            stub_io_create_device as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoDeleteDevice",
            stub_io_delete_device as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCreateSymbolicLink",
            stub_io_create_symbolic_link as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoDeleteSymbolicLink",
            stub_io_delete_symbolic_link as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "IoCompleteRequest",
            stub_io_complete_request as *const () as usize,
        );

        // Hardware / Software IRQL Management
        table.register(
            "NTOSKRNL.EXE",
            "KeGetCurrentIrql",
            stub_ke_get_current_irql as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeRaiseIrql",
            stub_ke_raise_irql as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeLowerIrql",
            stub_ke_lower_irql as *const () as usize,
        );

        // String and Memory Management
        table.register(
            "NTOSKRNL.EXE",
            "RtlInitUnicodeString",
            stub_rtl_init_unicode_string as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "ExAllocatePoolWithTag",
            stub_ex_allocate_pool_with_tag as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "ExFreePoolWithTag",
            stub_ex_free_pool_with_tag as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "ExFreePool",
            stub_ex_free_pool as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "RtlCopyMemory",
            stub_rtl_copy_memory as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "RtlZeroMemory",
            stub_rtl_zero_memory as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "RtlCompareMemory",
            stub_rtl_compare_memory as *const () as usize,
        );

        // Synchronization Primitives (SpinLocks and Events)
        table.register(
            "NTOSKRNL.EXE",
            "KeInitializeSpinLock",
            stub_ke_initialize_spin_lock as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeAcquireSpinLock",
            stub_ke_acquire_spin_lock as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeReleaseSpinLock",
            stub_ke_release_spin_lock as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeInitializeEvent",
            stub_ke_initialize_event as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeSetEvent",
            stub_ke_set_event as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeResetEvent",
            stub_ke_reset_event as *const () as usize,
        );
        table.register(
            "NTOSKRNL.EXE",
            "KeWaitForSingleObject",
            stub_ke_wait_for_single_object as *const () as usize,
        );

        table
    }

    /// Registers a custom kernel function export.
    pub fn register(&mut self, dll: &str, function: &str, address: usize) {
        self.exports
            .insert((dll.to_uppercase(), function.to_string()), address);
    }

    /// Resolves a requested import symbol.
    pub fn resolve(&self, dll: &str, function: &str) -> Option<usize> {
        self.exports
            .get(&(dll.to_uppercase(), function.to_string()))
            .copied()
    }
}

/// A loaded and initialized NT driver instance in kernel memory.
#[derive(Debug)]
pub struct LoadedDriver {
    pub name: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub driver_object: DriverObject,
    pub buffer: ExecutableBuffer,
    pub sections: Vec<DriverSectionMapping>,
    /// Number of `IMAGE_REL_BASED_DIR64` fixups applied while mapping the image.
    pub relocations_applied: usize,
    /// UTF-16 backing storage for `driver_object.driver_name` (must outlive the driver object).
    _driver_name_backing: Vec<u16>,
    /// Live pool blocks and pool violations recorded right before `DriverEntry`.
    pool_baseline: (usize, usize),
}

impl LoadedDriver {
    /// Enforces W^X page protection on the driver's memory layout.
    ///
    /// - Executable sections (.text) are strictly Read+Execute (NOT Writable).
    /// - Data sections (.data, .bss, INIT) are strictly Read+Write (NOT Executable).
    /// - Read-only sections (.rdata, .pdata) and headers are Read-Only (NOT Writable, NOT Executable).
    /// - NO page is left with simultaneous Write and Execute permissions.
    pub fn enforce_wx_protection<F>(&self, mut set_page_flags: F) -> Result<(), NtDriverError>
    where
        F: FnMut(
            u64,  /* va */
            bool, /* writable */
            bool, /* executable */
        ) -> Result<(), ()>,
    {
        // 1. Headers [0 .. first section RVA]: Read-Only (RO, NX)
        let header_end = self.sections.first().map(|s| s.rva as u64).unwrap_or(4096);
        let header_pages = (header_end + 4095) & !4095;
        for offset in (0..header_pages).step_by(4096) {
            set_page_flags(self.image_base + offset, false, false)
                .map_err(|_| NtDriverError::ProtectionFailed)?;
        }

        // 2. Sections
        for sec in &self.sections {
            // Strict W^X assertion: no section can ever be both W and X
            if sec.is_writable && sec.is_executable {
                return Err(NtDriverError::WritableExecutableSection);
            }

            let start = (self.image_base + sec.rva as u64) & !4095;
            let end = (self.image_base + sec.rva as u64 + sec.size as u64 + 4095) & !4095;

            for va in (start..end).step_by(4096) {
                set_page_flags(va, sec.is_writable, sec.is_executable)
                    .map_err(|_| NtDriverError::ProtectionFailed)?;
            }
        }

        Ok(())
    }

    /// Automatically applies platform page permissions matching each section (W^X enforcement).
    pub fn apply_platform_protection(&self) -> Result<(), NtDriverError> {
        #[cfg(any(windows, unix))]
        {
            let header_end = self
                .sections
                .first()
                .map(|s| s.rva as usize)
                .unwrap_or(4096);
            let header_pages = (header_end + 4095) & !4095;
            self.buffer.protect_range(0, header_pages, false, false)?;

            for sec in &self.sections {
                if sec.is_writable && sec.is_executable {
                    return Err(NtDriverError::WritableExecutableSection);
                }
                let start = sec.rva as usize;
                let size = ((sec.size as usize) + 4095) & !4095;
                if start
                    .checked_add(size)
                    .is_none_or(|end| end > self.buffer.len())
                {
                    return Err(NtDriverError::ImageOutOfBounds);
                }
                self.buffer
                    .protect_range(start, size, sec.is_writable, sec.is_executable)?;
            }
        }
        Ok(())
    }

    /// Invokes the native `DriverEntry` routine of the loaded driver.
    ///
    /// # Safety
    ///
    /// The entry point must point to valid native x86_64 code compiled for Ring 0.
    pub unsafe fn init(&mut self, registry_path: &UnicodeString) -> i32 {
        self.pool_baseline = (live_pool_allocations(), pool_violations());
        let entry: DriverEntryFn = core::mem::transmute(self.entry_point);
        let status = entry(&mut self.driver_object, registry_path);
        if status != STATUS_SUCCESS {
            return status;
        }

        // If DriverEntry created device objects, capture the head of the chain
        if !self.driver_object.device_object.is_null() {
            (*self.driver_object.device_object).driver_object = &mut self.driver_object;
        }

        STATUS_SUCCESS
    }

    /// Safely dispatches an IRP to the driver's registered major function handler.
    ///
    /// # Safety
    ///
    /// `device` and `irp` must be valid non-null pointers to WDM structures.
    pub unsafe fn dispatch(
        &self,
        major_function: usize,
        device: *mut DeviceObject,
        irp: *mut Irp,
    ) -> i32 {
        if major_function > IRP_MJ_MAXIMUM_FUNCTION {
            return STATUS_INVALID_PARAMETER;
        }

        if let Some(handler) = self.driver_object.major_function[major_function] {
            handler(device, irp)
        } else {
            STATUS_NOT_IMPLEMENTED
        }
    }

    /// Unloads the driver, invoking its `DriverUnload` routine and releasing resources.
    ///
    /// # Safety
    ///
    /// Must be called at PASSIVE_LEVEL with no outstanding I/O requests.
    ///
    /// The host does not clean up after the driver: after `DriverUnload` returns, every
    /// device object must have been deleted and every pool block allocated since
    /// `DriverEntry` must have been freed, otherwise an error is returned. Pool accounting
    /// is global, so this assumes one driver lifecycle at a time (true for the kernel
    /// validation flow and enforced in host tests by serializing them).
    pub unsafe fn unload(&mut self) -> Result<(), NtDriverError> {
        let unload_fn = self
            .driver_object
            .driver_unload
            .ok_or(NtDriverError::NoUnloadRoutine)?;
        unload_fn(&mut self.driver_object);
        if !self.driver_object.device_object.is_null() {
            return Err(NtDriverError::DevicesLeaked);
        }
        let (live_before, violations_before) = self.pool_baseline;
        let live = live_pool_allocations();
        if live > live_before {
            return Err(NtDriverError::PoolLeaked(live - live_before));
        }
        let violations = pool_violations();
        if violations > violations_before {
            return Err(NtDriverError::PoolViolations(
                violations - violations_before,
            ));
        }
        Ok(())
    }
}

/// Host environment capable of parsing, relocating, and executing NT drivers.
pub struct NtDriverHost {
    kernel_table: NtoskrnlTable,
}

impl Default for NtDriverHost {
    fn default() -> Self {
        Self::new()
    }
}

impl NtDriverHost {
    pub fn new() -> Self {
        Self {
            kernel_table: NtoskrnlTable::new(),
        }
    }

    pub fn kernel_table_mut(&mut self) -> &mut NtoskrnlTable {
        &mut self.kernel_table
    }

    /// Loads, maps, relocates, and binds a PE32+ native kernel driver.
    pub fn load_driver(
        &self,
        sys_bytes: &[u8],
        driver_name: &str,
        _registry_path: &str,
    ) -> Result<LoadedDriver, NtDriverError> {
        let pe = PeImage::parse(sys_bytes)?;

        if pe.subsystem != IMAGE_SUBSYSTEM_NATIVE {
            return Err(NtDriverError::NotNativeDriver(pe.subsystem));
        }

        if pe.entry_point_rva == 0 {
            return Err(NtDriverError::NoEntryPoint);
        }

        // Fail closed: every relocation and import record must parse before any memory
        // is allocated. A corrupted table is a load error, never "no relocations/imports".
        let reloc_blocks = pe.parse_relocations(sys_bytes)?;
        let import_descriptors = pe.parse_imports(sys_bytes)?;

        // W^X is a load-time invariant, not only a property checked by the page-table hook.
        if pe.sections.iter().any(|sec| {
            sec.characteristics & IMAGE_SCN_MEM_WRITE != 0
                && sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        }) {
            return Err(NtDriverError::WritableExecutableSection);
        }

        // 1. Allocate aligned buffer (initially PAGE_READWRITE for relocations and IAT)
        let image_size = (pe.size_of_image as usize + 4095) & !4095;
        let mut buffer = ExecutableBuffer::allocate(image_size)?;

        // 2. Map PE Headers and Sections
        let header_copy_len = pe.size_of_headers as usize;
        if header_copy_len > sys_bytes.len() || header_copy_len > buffer.len() {
            return Err(NtDriverError::ImageOutOfBounds);
        }
        buffer.as_mut_slice()[..header_copy_len].copy_from_slice(&sys_bytes[..header_copy_len]);

        let mut section_mappings = Vec::new();
        for sec in &pe.sections {
            let va_start = sec.virtual_address as usize;
            let raw_start = sec.pointer_to_raw_data as usize;
            let raw_size = sec.size_of_raw_data as usize;

            let src = raw_start
                .checked_add(raw_size)
                .and_then(|end| sys_bytes.get(raw_start..end))
                .ok_or(NtDriverError::ImageOutOfBounds)?;
            let dst_end = va_start
                .checked_add(raw_size)
                .filter(|&end| end <= buffer.len())
                .ok_or(NtDriverError::ImageOutOfBounds)?;
            buffer.as_mut_slice()[va_start..dst_end].copy_from_slice(src);

            let mut name_bytes = [0u8; 8];
            let src_bytes = sec.name.as_bytes();
            let copy_len = src_bytes.len().min(8);
            name_bytes[..copy_len].copy_from_slice(&src_bytes[..copy_len]);

            let is_exec = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_write = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            // PE semantics: a zero VirtualSize means the section spans SizeOfRawData.
            let mapped_size = if sec.virtual_size != 0 {
                sec.virtual_size
            } else {
                sec.size_of_raw_data
            };

            section_mappings.push(DriverSectionMapping {
                name: name_bytes,
                rva: sec.virtual_address,
                size: mapped_size,
                is_executable: is_exec,
                is_writable: is_write,
            });
        }

        // 3. Process Base Relocations
        let actual_base = buffer.as_ptr() as u64;
        let preferred_base = pe.image_base;
        let delta = actual_base.wrapping_sub(preferred_base);
        let mut relocations_applied = 0usize;

        if delta != 0 {
            // Same rule as the NT loader: an image whose relocations were stripped can only
            // run at its preferred base. (An image without a .reloc directory and without the
            // flag has no absolute fixups to apply, e.g. MSVC output that is fully RIP-relative.)
            if pe.file_characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0 {
                return Err(NtDriverError::RelocationsStripped);
            }
            for block in &reloc_blocks {
                for entry in &block.entries {
                    if entry.rel_type != IMAGE_REL_BASED_DIR64 {
                        continue; // IMAGE_REL_BASED_ABSOLUTE padding; others rejected by the parser
                    }
                    let target_rva = (block.page_rva as usize)
                        .checked_add(entry.offset as usize)
                        .ok_or(NtDriverError::RelocationFailed)?;
                    let slot = target_rva
                        .checked_add(8)
                        .and_then(|end| buffer.as_mut_slice().get_mut(target_rva..end))
                        .ok_or(NtDriverError::RelocationFailed)?;
                    let patched = LittleEndian::read_u64(slot).wrapping_add(delta);
                    LittleEndian::write_u64(slot, patched);
                    relocations_applied += 1;
                }
            }
        }

        // 4. Resolve Imports against NtoskrnlTable and patch IAT
        for desc in import_descriptors {
            for func in desc.functions {
                let resolved_addr = self
                    .kernel_table
                    .resolve(&desc.dll_name, &func.name)
                    .ok_or_else(|| NtDriverError::UnresolvedImport {
                        dll: desc.dll_name.clone(),
                        function: func.name.clone(),
                    })?;

                let iat_offset = func.iat_rva as usize;
                let slot = iat_offset
                    .checked_add(8)
                    .and_then(|end| buffer.as_mut_slice().get_mut(iat_offset..end))
                    .ok_or(NtDriverError::ImageOutOfBounds)?;
                LittleEndian::write_u64(slot, resolved_addr as u64);
            }
        }

        // 5. Initialize DRIVER_OBJECT
        let mut driver_obj = DriverObject::default();
        // The backing buffer is moved into LoadedDriver (moving a Vec keeps its heap
        // allocation), so driver_object.driver_name never dangles.
        let (driver_name_ustr, driver_name_backing) = UnicodeString::from_str_vec(driver_name);

        driver_obj.driver_name = driver_name_ustr;
        driver_obj.driver_start = buffer.as_mut_ptr() as *mut c_void;
        driver_obj.driver_size = image_size as u32;

        let entry_va = actual_base + pe.entry_point_rva as u64;

        let loaded = LoadedDriver {
            name: driver_name.to_string(),
            image_base: actual_base,
            entry_point: entry_va,
            driver_object: driver_obj,
            buffer,
            sections: section_mappings,
            relocations_applied,
            _driver_name_backing: driver_name_backing,
            pool_baseline: (0, 0),
        };

        // 6. Enforce W^X platform page protection (Code -> RX, Data -> RW/RO, Headers -> RO)
        loaded.apply_platform_protection()?;

        Ok(loaded)
    }
}

// ---------------------------------------------------------------------------
// Standard WDM Kernel Function Stubs
// ---------------------------------------------------------------------------

/// WDM DbgPrint export stub.
///
/// # Safety
///
/// `format_ptr` must point to a valid null-terminated ASCII/UTF-8 format string if non-null.
pub unsafe extern "win64" fn stub_dbg_print(_format_ptr: *const u8) -> i32 {
    STATUS_SUCCESS
}

/// WDM KeGetCurrentIrql export stub.
///
/// # Safety
///
/// Safe to call in any context. Queries hardware CR8 if hook is set, or software fallback.
pub unsafe extern "win64" fn stub_ke_get_current_irql() -> Kirql {
    let fn_ptr = HARDWARE_IRQL_GETTER.load(Ordering::Acquire);
    if !fn_ptr.is_null() {
        let getter: fn() -> u8 = core::mem::transmute(fn_ptr);
        getter()
    } else {
        CURRENT_IRQL.load(Ordering::SeqCst)
    }
}

/// WDM KeRaiseIrql export stub.
///
/// # Safety
///
/// If `old_irql` is non-null, it must be writable for a single byte.
pub unsafe extern "win64" fn stub_ke_raise_irql(new_irql: Kirql, old_irql: *mut Kirql) {
    let current = stub_ke_get_current_irql();
    if !old_irql.is_null() {
        *old_irql = current;
    }
    let fn_ptr = HARDWARE_IRQL_SETTER.load(Ordering::Acquire);
    if !fn_ptr.is_null() {
        let setter: unsafe fn(u8) = core::mem::transmute(fn_ptr);
        setter(new_irql);
    }
    CURRENT_IRQL.store(new_irql, Ordering::SeqCst);
}

/// WDM KeLowerIrql export stub.
///
/// # Safety
///
/// Restores previously recorded hardware or software IRQL.
pub unsafe extern "win64" fn stub_ke_lower_irql(new_irql: Kirql) {
    let fn_ptr = HARDWARE_IRQL_SETTER.load(Ordering::Acquire);
    if !fn_ptr.is_null() {
        let setter: unsafe fn(u8) = core::mem::transmute(fn_ptr);
        setter(new_irql);
    }
    CURRENT_IRQL.store(new_irql, Ordering::SeqCst);
}

/// WDM RtlInitUnicodeString export stub.
///
/// # Safety
///
/// `dest` must point to valid writable `UnicodeString` memory. `source` if non-null
/// must point to a valid null-terminated UTF-16 buffer.
pub unsafe extern "win64" fn stub_rtl_init_unicode_string(
    dest: *mut UnicodeString,
    source: *const u16,
) {
    if dest.is_null() {
        return;
    }
    if source.is_null() {
        (*dest).length = 0;
        (*dest).maximum_length = 0;
        (*dest).buffer = core::ptr::null_mut();
        return;
    }
    let mut len = 0usize;
    while *source.add(len) != 0 {
        len += 1;
    }
    (*dest).length = (len * 2) as u16;
    (*dest).maximum_length = ((len + 1) * 2) as u16;
    (*dest).buffer = source as *mut u16;
}

/// WDM IoCreateDevice export stub.
///
/// # Safety
///
/// `driver_object` must point to a valid `DriverObject`. `device_object` must point
/// to writable pointer storage.
pub unsafe extern "win64" fn stub_io_create_device(
    driver_object: *mut DriverObject,
    _device_extension_size: u32,
    _device_name: *mut UnicodeString,
    device_type: u32,
    characteristics: u32,
    _exclusive: u8,
    device_object: *mut *mut DeviceObject,
) -> i32 {
    if driver_object.is_null() || device_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let dev = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(DeviceObject {
        driver_object,
        device_type,
        characteristics,
        ..Default::default()
    }));

    if (*driver_object).device_object.is_null() {
        (*driver_object).device_object = dev;
    } else {
        let mut cur = (*driver_object).device_object;
        while !(*cur).next_device.is_null() {
            cur = (*cur).next_device;
        }
        (*cur).next_device = dev;
    }

    *device_object = dev;
    STATUS_SUCCESS
}

/// WDM IoDeleteDevice export stub.
///
/// # Safety
///
/// `device_object` must point to an active `DeviceObject` allocated via `IoCreateDevice`.
pub unsafe extern "win64" fn stub_io_delete_device(device_object: *mut DeviceObject) {
    if !device_object.is_null() {
        let drv = (*device_object).driver_object;
        if !drv.is_null() && (*drv).device_object == device_object {
            (*drv).device_object = (*device_object).next_device;
        }
        let _ = alloc::boxed::Box::from_raw(device_object);
    }
}

/// WDM IoCreateSymbolicLink export stub.
///
/// # Safety
///
/// Parameters must point to valid UnicodeString structures.
pub unsafe extern "win64" fn stub_io_create_symbolic_link(
    _symbolic_link_name: *mut UnicodeString,
    _device_name: *mut UnicodeString,
) -> i32 {
    STATUS_SUCCESS
}

/// WDM IoDeleteSymbolicLink export stub.
///
/// # Safety
///
/// Parameter must point to valid UnicodeString structure.
pub unsafe extern "win64" fn stub_io_delete_symbolic_link(
    _symbolic_link_name: *mut UnicodeString,
) -> i32 {
    STATUS_SUCCESS
}

/// WDM IoCompleteRequest export stub.
///
/// # Safety
///
/// `irp` must point to an active `Irp` instance being processed by a driver.
pub unsafe extern "win64" fn stub_io_complete_request(irp: *mut Irp, _priority_boost: i8) {
    if !irp.is_null() {
        (*irp).pending_returned = 0;
    }
}

/// WDM ExAllocatePoolWithTag export stub.
///
/// # Safety
///
/// Allocates zeroed, 16-byte aligned memory and records it in the pool registry.
/// Returns null when the size is invalid, memory is exhausted or the registry is full.
pub unsafe extern "win64" fn stub_ex_allocate_pool_with_tag(
    _pool_type: u32,
    number_of_bytes: usize,
    tag: u32,
) -> *mut c_void {
    if number_of_bytes == 0 || number_of_bytes > 0x1000_0000 {
        return core::ptr::null_mut();
    }
    let layout = match alloc::alloc::Layout::from_size_align(number_of_bytes, 16) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };
    let ptr = alloc::alloc::alloc_zeroed(layout);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    let recorded = POOL_TRACKER.with(|slots| {
        slots.iter_mut().find(|s| s.0 == 0).map(|slot| {
            *slot = (ptr as usize, number_of_bytes, tag);
        })
    });
    if recorded.is_none() {
        alloc::alloc::dealloc(ptr, layout);
        return core::ptr::null_mut();
    }
    ptr as *mut c_void
}

/// WDM ExFreePoolWithTag export stub.
///
/// # Safety
///
/// Frees only blocks present in the pool registry. Unknown pointers (including double
/// frees) and tag mismatches are rejected without dereferencing `p` and counted in
/// [`pool_violations`]; the block is then left allocated (so it also shows up as a leak).
pub unsafe extern "win64" fn stub_ex_free_pool_with_tag(p: *mut c_void, tag: u32) {
    if p.is_null() {
        return;
    }
    let removed = POOL_TRACKER.with(|slots| {
        let slot = slots.iter_mut().find(|s| s.0 == p as usize)?;
        if tag != 0 && slot.2 != tag {
            return None;
        }
        let size = slot.1;
        *slot = (0, 0, 0);
        Some(size)
    });
    match removed {
        Some(size) => {
            if let Ok(layout) = alloc::alloc::Layout::from_size_align(size, 16) {
                alloc::alloc::dealloc(p as *mut u8, layout);
            }
        }
        None => {
            POOL_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// WDM ExFreePool export stub.
///
/// # Safety
///
/// Deallocates pool memory without strict tag check.
pub unsafe extern "win64" fn stub_ex_free_pool(p: *mut c_void) {
    stub_ex_free_pool_with_tag(p, 0);
}

/// WDM RtlCopyMemory export stub.
///
/// # Safety
///
/// Memory buffers must be valid and non-overlapping.
pub unsafe extern "win64" fn stub_rtl_copy_memory(
    destination: *mut c_void,
    source: *const c_void,
    length: usize,
) {
    if !destination.is_null() && !source.is_null() && length > 0 {
        core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length);
    }
}

/// WDM RtlZeroMemory export stub.
///
/// # Safety
///
/// Buffer must be valid and writable for `length` bytes.
pub unsafe extern "win64" fn stub_rtl_zero_memory(destination: *mut c_void, length: usize) {
    if !destination.is_null() && length > 0 {
        core::ptr::write_bytes(destination as *mut u8, 0, length);
    }
}

/// WDM RtlCompareMemory export stub.
///
/// # Safety
///
/// Buffers must be valid for `length` bytes.
pub unsafe extern "win64" fn stub_rtl_compare_memory(
    source1: *const c_void,
    source2: *const c_void,
    length: usize,
) -> usize {
    if source1.is_null() || source2.is_null() || length == 0 {
        return 0;
    }
    let s1 = core::slice::from_raw_parts(source1 as *const u8, length);
    let s2 = core::slice::from_raw_parts(source2 as *const u8, length);
    let mut match_len = 0;
    for (b1, b2) in s1.iter().zip(s2.iter()) {
        if *b1 == *b2 {
            match_len += 1;
        } else {
            break;
        }
    }
    match_len
}

/// WDM KeInitializeSpinLock export stub.
///
/// # Safety
///
/// Spinlock pointer must be valid and writable.
pub unsafe extern "win64" fn stub_ke_initialize_spin_lock(spin_lock: *mut usize) {
    if !spin_lock.is_null() {
        *spin_lock = 0;
    }
}

/// WDM KeAcquireSpinLock export stub.
///
/// # Safety
///
/// Raises IRQL to `DISPATCH_LEVEL` and acquires spinlock atomically.
pub unsafe extern "win64" fn stub_ke_acquire_spin_lock(
    spin_lock: *mut usize,
    old_irql: *mut Kirql,
) {
    stub_ke_raise_irql(DISPATCH_LEVEL, old_irql);
    if !spin_lock.is_null() {
        let lock_ptr = spin_lock as *const core::sync::atomic::AtomicUsize;
        while (*lock_ptr)
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }
}

/// WDM KeReleaseSpinLock export stub.
///
/// # Safety
///
/// Releases spinlock and lowers IRQL back to `new_irql`.
pub unsafe extern "win64" fn stub_ke_release_spin_lock(spin_lock: *mut usize, new_irql: Kirql) {
    if !spin_lock.is_null() {
        let lock_ptr = spin_lock as *const core::sync::atomic::AtomicUsize;
        (*lock_ptr).store(0, Ordering::Release);
    }
    stub_ke_lower_irql(new_irql);
}

/// WDM KeInitializeEvent export stub.
///
/// # Safety
///
/// Initializes `KEvent` structure with specified type and state.
pub unsafe extern "win64" fn stub_ke_initialize_event(
    event: *mut KEvent,
    event_type: u32,
    initial_state: u8,
) {
    if !event.is_null() {
        (*event).header_type = event_type as u8;
        (*event).header_signaled = initial_state;
        (*event).header_size = core::mem::size_of::<KEvent>() as u8;
        (*event).header_reserved = 0;
        (*event).signal_state = if initial_state != 0 { 1 } else { 0 };
        (*event).wait_list_blink = core::ptr::null_mut();
        (*event).wait_list_flink = core::ptr::null_mut();
    }
}

/// WDM KeSetEvent export stub.
///
/// # Safety
///
/// Signals `KEvent` and returns previous state.
pub unsafe extern "win64" fn stub_ke_set_event(
    event: *mut KEvent,
    _increment: i32,
    _wait: u8,
) -> i32 {
    if event.is_null() {
        return 0;
    }
    let prev = (*event).signal_state;
    (*event).signal_state = 1;
    (*event).header_signaled = 1;
    prev
}

/// WDM KeResetEvent export stub.
///
/// # Safety
///
/// Clears signaled state of `KEvent`.
pub unsafe extern "win64" fn stub_ke_reset_event(event: *mut KEvent) -> i32 {
    if event.is_null() {
        return 0;
    }
    let prev = (*event).signal_state;
    (*event).signal_state = 0;
    (*event).header_signaled = 0;
    prev
}

/// WDM KeWaitForSingleObject export stub.
///
/// # Safety
///
/// Verifies object signal state and returns `STATUS_SUCCESS`.
pub unsafe extern "win64" fn stub_ke_wait_for_single_object(
    object: *mut c_void,
    _wait_reason: u32,
    _wait_mode: u8,
    _alertable: u8,
    _timeout: *const i64,
) -> i32 {
    if object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let event = object as *mut KEvent;
    if (*event).signal_state > 0 {
        STATUS_SUCCESS
    } else {
        0x00000102 // STATUS_TIMEOUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::driver::{
        IoStackLocation, ParametersDeviceIoControl, IOCTL_NEXUS_ECHO, IOCTL_NEXUS_GET_VERSION,
        IOCTL_NEXUS_RAISE_IRQL_TEST, IOCTL_WDM_SAMPLE_EVENT_TEST, IOCTL_WDM_SAMPLE_MEM_TEST,
        IOCTL_WDM_SAMPLE_SPINLOCK_IRQL, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ,
    };

    const REAL_DRIVER_BYTES: &[u8] =
        include_bytes!("../../../tests/fixtures/nt_driver/nexus_driver.sys");
    const STANDARD_WDM_BYTES: &[u8] =
        include_bytes!("../../../tests/fixtures/nt_driver/standard_wdm.sys");

    #[test]
    fn test_driver_loader_validates_native_subsystem() {
        let _host_state = lock_nt_host_state_for_tests();
        let host = NtDriverHost::new();

        // 1. Verify real native driver loads successfully
        let driver = host
            .load_driver(REAL_DRIVER_BYTES, "\\Driver\\NexusTest", "\\Registry\\Test")
            .expect("Failed to load native driver");
        assert_eq!(driver.name, "\\Driver\\NexusTest");
        assert_eq!(driver.driver_object.type_, 4);

        // 2. Corrupt subsystem to 3 (Windows CUI / console) and verify rejection
        let mut bad_bytes = REAL_DRIVER_BYTES.to_vec();
        let pe_off = LittleEndian::read_u32(&bad_bytes[60..64]) as usize;
        let opt_off = pe_off + 24;
        LittleEndian::write_u16(&mut bad_bytes[opt_off + 68..opt_off + 70], 3);

        let err = host
            .load_driver(&bad_bytes, "\\Driver\\BadDriver", "\\Registry\\Test")
            .unwrap_err();
        assert_eq!(err, NtDriverError::NotNativeDriver(3));
    }

    #[test]
    fn test_real_nt_driver_execution_ring0_lifecycle() {
        // Serialized and reset to PASSIVE_LEVEL (B2). On the host the IRQL stubs use the
        // software fallback; the CR8 path is covered by test_irql_stubs_route_through_hardware_hooks
        // and, for real, in the QEMU guest.
        let _host_state = lock_nt_host_state_for_tests();
        let host = NtDriverHost::new();

        // 1. Load real MSVC-compiled WDM driver
        let mut driver = host
            .load_driver(
                REAL_DRIVER_BYTES,
                "\\Driver\\NexusRealDriver",
                "\\Registry\\Machine\\System",
            )
            .expect("Real driver load failed");

        // 2. Call native DriverEntry in executable memory
        let (reg_ustr, _reg_backing) = UnicodeString::from_str_vec(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NexusDrv0",
        );
        let init_status = unsafe { driver.init(&reg_ustr) };
        assert_eq!(
            init_status, STATUS_SUCCESS,
            "DriverEntry must succeed with 0"
        );

        // 3. Verify device object was dynamically created by DriverEntry
        let dev_ptr = driver.driver_object.device_object;
        assert!(
            !dev_ptr.is_null(),
            "DriverEntry must have created DeviceObject"
        );

        // 4. Test IRP_MJ_CREATE dispatching
        let mut create_irp = Irp::default();
        let mut create_stack = IoStackLocation {
            major_function: IRP_MJ_CREATE as u8,
            device_object: dev_ptr,
            ..Default::default()
        };
        create_irp.current_stack_location = &mut create_stack;

        let status = unsafe { driver.dispatch(IRP_MJ_CREATE, dev_ptr, &mut create_irp) };
        assert_eq!(
            status, STATUS_SUCCESS,
            "IRP_MJ_CREATE dispatch must return STATUS_SUCCESS"
        );
        assert_eq!(create_irp.io_status.status, STATUS_SUCCESS);

        // 5. Test IOCTL_NEXUS_GET_VERSION
        let mut ver_output: u32 = 0;
        let mut ioctl_irp_ver = Irp {
            user_buffer: &mut ver_output as *mut u32 as *mut c_void,
            ..Default::default()
        };
        let mut ioctl_stack_ver = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_NEXUS_GET_VERSION,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        ioctl_irp_ver.current_stack_location = &mut ioctl_stack_ver;

        let status = unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_ver) };
        assert_eq!(
            status, STATUS_SUCCESS,
            "IOCTL_NEXUS_GET_VERSION dispatch failed"
        );
        assert_eq!(ioctl_irp_ver.io_status.status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_ver.io_status.information, 4);
        assert_eq!(ver_output, 0x0003_0600);

        // 6. Test IOCTL_NEXUS_ECHO
        let mut text_buf = *b"Hello Nexus OS Kernel!\0";
        let mut ioctl_irp_echo = Irp {
            user_buffer: text_buf.as_mut_ptr() as *mut c_void,
            ..Default::default()
        };
        let mut ioctl_stack_echo = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 22,
                input_buffer_length: 22,
                io_control_code: IOCTL_NEXUS_ECHO,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        ioctl_irp_echo.current_stack_location = &mut ioctl_stack_echo;

        let status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_echo) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_echo.io_status.information, 22);
        assert_eq!(&text_buf[..22], b"hELLO nEXUS os kERNEL!");

        // 7. Test IOCTL_NEXUS_RAISE_IRQL_TEST
        let mut irql_test_result: u32 = 0;
        let mut ioctl_irp_irql = Irp {
            user_buffer: &mut irql_test_result as *mut u32 as *mut c_void,
            ..Default::default()
        };
        let mut ioctl_stack_irql = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_NEXUS_RAISE_IRQL_TEST,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        ioctl_irp_irql.current_stack_location = &mut ioctl_stack_irql;

        let status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_irql) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(ioctl_irp_irql.io_status.status, STATUS_SUCCESS);
        assert_eq!(
            irql_test_result, 0x1337C0DE,
            "IRQL raise/lower test must succeed"
        );
        assert_eq!(CURRENT_IRQL.load(Ordering::SeqCst), PASSIVE_LEVEL);

        // 8. Test IRP_MJ_READ
        let mut read_buf = [0u8; 32];
        let mut read_irp = Irp {
            user_buffer: read_buf.as_mut_ptr() as *mut c_void,
            ..Default::default()
        };
        let mut read_stack = IoStackLocation {
            major_function: IRP_MJ_READ as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 32,
                ..Default::default()
            },
            ..Default::default()
        };
        read_irp.current_stack_location = &mut read_stack;

        let status = unsafe { driver.dispatch(IRP_MJ_READ, dev_ptr, &mut read_irp) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(read_irp.io_status.information, 25);
        assert_eq!(
            &read_buf[..25],
            b"NEXUS_OS_WDM_READ_SUCCESS",
            "Read payload mismatch"
        );

        // 9. Test safe driver unload. unload() no longer clears device_object itself, so
        // this only passes if the driver's own DriverUnload deleted its device (FP3/M3),
        // and unload() fails if pool blocks leaked.
        let pool_before = live_pool_allocations();
        unsafe {
            driver.unload().expect("DriverUnload must succeed");
        }
        assert!(
            driver.driver_object.device_object.is_null(),
            "DriverUnload must have deleted its DeviceObject"
        );
        assert!(live_pool_allocations() <= pool_before);
    }

    #[test]
    fn test_standard_wdm_driver_execution_and_pools() {
        let _host_state = lock_nt_host_state_for_tests();
        let host = NtDriverHost::new();

        // 1. Load authentic standard WDM driver
        let mut driver = host
            .load_driver(
                STANDARD_WDM_BYTES,
                "\\Driver\\StandardWdm0",
                "\\Registry\\Machine\\System",
            )
            .expect("Standard WDM driver load failed");

        // 2. Validate section mappings for W^X
        assert!(
            driver.sections.len() >= 4,
            "Driver must have standard sections"
        );
        let text_sec = driver
            .sections
            .iter()
            .find(|s| s.name.starts_with(b".text"))
            .expect(".text section missing");
        assert!(
            text_sec.is_executable && !text_sec.is_writable,
            ".text must be RX"
        );

        let data_sec = driver
            .sections
            .iter()
            .find(|s| s.name.starts_with(b".data"))
            .expect(".data section missing");
        assert!(
            !data_sec.is_executable && data_sec.is_writable,
            ".data must be RW"
        );

        // 3. Initialize via DriverEntry
        let (reg_ustr, _backing) = UnicodeString::from_str_vec(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\StandardWdm0",
        );
        let init_status = unsafe { driver.init(&reg_ustr) };
        assert_eq!(
            init_status, STATUS_SUCCESS,
            "Standard WDM DriverEntry failed"
        );

        let dev_ptr = driver.driver_object.device_object;
        assert!(!dev_ptr.is_null(), "DeviceObject must be created");

        // 4. Test Pool Allocation & Memory Verification IOCTL
        let mut pool_test_val: u32 = 0;
        let mut ioctl_irp_mem = Irp {
            user_buffer: &mut pool_test_val as *mut u32 as *mut c_void,
            ..Default::default()
        };
        let mut ioctl_stack_mem = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_WDM_SAMPLE_MEM_TEST,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        ioctl_irp_mem.current_stack_location = &mut ioctl_stack_mem;

        let status = unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_mem) };
        assert_eq!(status, STATUS_SUCCESS, "Pool test IOCTL failed");
        assert_eq!(pool_test_val, 0x504F4F4C, "Pool test result must be 'POOL'");

        // 5. Test SpinLock & Hardware IRQL IOCTL
        let mut counter_val: u32 = 0;
        let mut ioctl_irp_spin = Irp {
            user_buffer: &mut counter_val as *mut u32 as *mut c_void,
            ..Default::default()
        };
        let mut ioctl_stack_spin = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_WDM_SAMPLE_SPINLOCK_IRQL,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        ioctl_irp_spin.current_stack_location = &mut ioctl_stack_spin;

        let status =
            unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_spin) };
        assert_eq!(status, STATUS_SUCCESS, "SpinLock test IOCTL failed");
        assert_eq!(counter_val, 101, "SpinLock counter increment verified");
        assert_eq!(CURRENT_IRQL.load(Ordering::SeqCst), PASSIVE_LEVEL);

        // 6. Event IOCTL. NOTE (FP5): the driver signals the event and only then waits, so
        // this exercises the KeSetEvent/KeWaitForSingleObject call path on a signaled
        // event. It does NOT prove blocking or wake-up semantics (no waiters exist yet).
        let mut event_val: u32 = 0;
        let mut ioctl_irp_evt = Irp {
            user_buffer: &mut event_val as *mut u32 as *mut c_void,
            ..Default::default()
        };
        let mut ioctl_stack_evt = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                input_buffer_length: 0,
                io_control_code: IOCTL_WDM_SAMPLE_EVENT_TEST,
                _padding: 0,
                type3_input_buffer: core::ptr::null_mut(),
            },
            ..Default::default()
        };
        ioctl_irp_evt.current_stack_location = &mut ioctl_stack_evt;

        let status = unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut ioctl_irp_evt) };
        assert_eq!(status, STATUS_SUCCESS, "Event test IOCTL failed");
        assert_eq!(event_val, 0xCAFEFEED, "Event synchronization verified");

        // 7. Test Read Payload
        let mut read_buf = [0u8; 32];
        let mut read_irp = Irp {
            user_buffer: read_buf.as_mut_ptr() as *mut c_void,
            ..Default::default()
        };
        let mut read_stack = IoStackLocation {
            major_function: IRP_MJ_READ as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 32,
                ..Default::default()
            },
            ..Default::default()
        };
        read_irp.current_stack_location = &mut read_stack;

        let status = unsafe { driver.dispatch(IRP_MJ_READ, dev_ptr, &mut read_irp) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(read_irp.io_status.information, 27);
        assert_eq!(
            &read_buf[..27],
            b"STANDARD_WDM_DEVICE_PAYLOAD",
            "Read payload mismatch"
        );

        // 8. Test Safe Unload: fails with DevicesLeaked/PoolLeaked if the driver did not
        // release what it created (the host no longer hides it).
        unsafe {
            driver
                .unload()
                .expect("Standard WDM DriverUnload must succeed");
        }
        assert!(driver.driver_object.device_object.is_null());
    }

    #[test]
    fn test_wx_protection_and_section_isolation() {
        let _host_state = lock_nt_host_state_for_tests();
        let host = NtDriverHost::new();
        let driver = host
            .load_driver(
                STANDARD_WDM_BYTES,
                "\\Driver\\WxCheck",
                "\\Registry\\Machine\\System",
            )
            .expect("Load failed");

        let mut rx_count = 0;
        let mut rw_count = 0;
        let mut ro_count = 0;

        let res = driver.enforce_wx_protection(|_va, writable, executable| {
            assert!(
                !(writable && executable),
                "W^X Violation: page cannot be both writable and executable!"
            );
            if executable {
                rx_count += 1;
            } else if writable {
                rw_count += 1;
            } else {
                ro_count += 1;
            }
            Ok(())
        });

        assert!(res.is_ok(), "W^X enforcement failed");
        assert!(rx_count > 0, "Must have RX pages for code");
        assert!(rw_count > 0, "Must have RW pages for data");
        assert!(ro_count > 0, "Must have RO pages for headers/rdata");

        // FP2: the callback above only checks the arguments it is given. The real proof is
        // the OS page protection of the mapped image, read back below (Linux: /proc/self/maps,
        // Windows: VirtualQuery). The guest's PTE-level check lives in nexus-kernel driver_host.
        #[cfg(target_os = "linux")]
        {
            let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
            let perms_at = |va: u64| -> String {
                for line in maps.lines() {
                    let mut it = line.split_whitespace();
                    let range = it.next().unwrap();
                    let perms = it.next().unwrap();
                    let (lo, hi) = range.split_once('-').unwrap();
                    let lo = u64::from_str_radix(lo, 16).unwrap();
                    let hi = u64::from_str_radix(hi, 16).unwrap();
                    if (lo..hi).contains(&va) {
                        return perms[..3].to_string();
                    }
                }
                panic!("address {va:#x} not mapped");
            };
            assert_eq!(
                perms_at(driver.image_base),
                "r--",
                "headers must be read-only"
            );
            let mut checked = 0;
            for sec in &driver.sections {
                let expected = match (sec.is_writable, sec.is_executable) {
                    (false, true) => "r-x",
                    (true, false) => "rw-",
                    (false, false) => "r--",
                    (true, true) => unreachable!("W+X sections are rejected at load"),
                };
                let start = driver.image_base + sec.rva as u64;
                let end = start + (sec.size as u64).max(1);
                for va in (start & !4095..end).step_by(4096) {
                    assert_eq!(perms_at(va), expected, "section {:?}", sec.name);
                    checked += 1;
                }
            }
            assert!(checked >= 4, "must have verified every section page");
        }

        // Verify with Windows OS memory query that .text is indeed PAGE_EXECUTE_READ (0x20)
        #[cfg(windows)]
        unsafe {
            #[repr(C)]
            struct MemoryBasicInformation {
                base_address: *mut c_void,
                allocation_base: *mut c_void,
                allocation_protect: u32,
                partition_id: u16,
                region_size: usize,
                state: u32,
                protect: u32,
                type_: u32,
            }
            #[link(name = "kernel32")]
            extern "system" {
                fn VirtualQuery(
                    lpAddress: *const c_void,
                    lpBuffer: *mut MemoryBasicInformation,
                    dwLength: usize,
                ) -> usize;
            }

            let mut mbi: MemoryBasicInformation = core::mem::zeroed();
            let text_va = (driver.image_base + 0x1000) as *const c_void;
            let q_res = VirtualQuery(
                text_va,
                &mut mbi,
                core::mem::size_of::<MemoryBasicInformation>(),
            );
            assert!(q_res > 0);
            assert_eq!(
                mbi.protect, 0x20,
                ".text section must be PAGE_EXECUTE_READ (0x20)"
            );

            let data_va = (driver.image_base + 0x3000) as *const c_void;
            let q_res2 = VirtualQuery(
                data_va,
                &mut mbi,
                core::mem::size_of::<MemoryBasicInformation>(),
            );
            assert!(q_res2 > 0);
            assert_eq!(
                mbi.protect, 0x04,
                ".data section must be PAGE_READWRITE (0x04)"
            );
        }
    }

    #[test]
    fn test_pool_tag_verification_and_double_free() {
        let _host_state = lock_nt_host_state_for_tests();
        let live0 = live_pool_allocations();
        let violations0 = pool_violations();
        unsafe {
            let ptr = stub_ex_allocate_pool_with_tag(0, 128, 0x41424344);
            assert!(!ptr.is_null(), "Allocation failed");
            assert_eq!(ptr as usize % 16, 0, "pool blocks are 16-byte aligned");
            assert_eq!(live_pool_allocations(), live0 + 1);
            let bytes = core::slice::from_raw_parts(ptr as *const u8, 128);
            assert!(bytes.iter().all(|&b| b == 0), "pool must be zeroed");

            // Mismatched tag: rejected, counted, block stays allocated.
            stub_ex_free_pool_with_tag(ptr, 0x99999999);
            assert_eq!(pool_violations(), violations0 + 1);
            assert_eq!(live_pool_allocations(), live0 + 1);

            // Matching tag: freed.
            stub_ex_free_pool_with_tag(ptr, 0x41424344);
            assert_eq!(live_pool_allocations(), live0);
            assert_eq!(pool_violations(), violations0 + 1);

            // Double free: rejected via the registry, without reading freed memory.
            stub_ex_free_pool_with_tag(ptr, 0x41424344);
            assert_eq!(pool_violations(), violations0 + 2);
            assert_eq!(live_pool_allocations(), live0);

            // Pointer never returned by the pool.
            let mut local = [0u8; 32];
            stub_ex_free_pool(local.as_mut_ptr() as *mut c_void);
            assert_eq!(pool_violations(), violations0 + 3);

            // Invalid sizes fail instead of allocating.
            assert!(stub_ex_allocate_pool_with_tag(0, 0, 1).is_null());
            assert!(stub_ex_allocate_pool_with_tag(0, 0x1000_0001, 1).is_null());
            assert_eq!(live_pool_allocations(), live0);
        }
    }

    unsafe extern "win64" fn unload_that_deletes_nothing(_driver: *mut DriverObject) {}

    #[test]
    fn test_unload_reports_leaked_devices_and_pool() {
        // Negative controls for unload(): previously it nulled device_object itself, so
        // these leaks were invisible (FP3/M3).
        let _host_state = lock_nt_host_state_for_tests();
        let host = NtDriverHost::new();
        let (reg, _backing) = UnicodeString::from_str_vec("\\Registry\\Leak");

        // 1. DriverUnload that forgets IoDeleteDevice -> DevicesLeaked.
        let mut driver = host
            .load_driver(REAL_DRIVER_BYTES, "\\Driver\\Leak", "\\Registry\\Leak")
            .unwrap();
        assert_eq!(unsafe { driver.init(&reg) }, STATUS_SUCCESS);
        let real_unload = driver.driver_object.driver_unload;
        driver.driver_object.driver_unload = Some(unload_that_deletes_nothing);
        assert_eq!(
            unsafe { driver.unload() },
            Err(NtDriverError::DevicesLeaked)
        );
        // Clean up with the driver's real routine.
        driver.driver_object.driver_unload = real_unload;
        unsafe { driver.unload() }.expect("real DriverUnload cleans up");

        // 2. Pool block allocated during the driver's lifetime and never freed -> PoolLeaked.
        let mut driver = host
            .load_driver(REAL_DRIVER_BYTES, "\\Driver\\Leak", "\\Registry\\Leak")
            .unwrap();
        assert_eq!(unsafe { driver.init(&reg) }, STATUS_SUCCESS);
        let leaked = unsafe { stub_ex_allocate_pool_with_tag(0, 64, 0x4B41454C) };
        assert!(!leaked.is_null());
        assert_eq!(
            unsafe { driver.unload() },
            Err(NtDriverError::PoolLeaked(1))
        );
        unsafe { stub_ex_free_pool_with_tag(leaked, 0x4B41454C) };

        // 3. Invalid free during the driver's lifetime -> PoolViolations.
        let mut driver = host
            .load_driver(REAL_DRIVER_BYTES, "\\Driver\\Leak", "\\Registry\\Leak")
            .unwrap();
        assert_eq!(unsafe { driver.init(&reg) }, STATUS_SUCCESS);
        let mut not_pool = [0u8; 16];
        unsafe { stub_ex_free_pool(not_pool.as_mut_ptr() as *mut c_void) };
        assert_eq!(
            unsafe { driver.unload() },
            Err(NtDriverError::PoolViolations(1))
        );
    }

    static FAKE_CR8: AtomicU8 = AtomicU8::new(0);
    static FAKE_CR8_MAX: AtomicU8 = AtomicU8::new(0);
    fn fake_cr8_get() -> u8 {
        FAKE_CR8.load(Ordering::SeqCst)
    }
    unsafe fn fake_cr8_set(irql: u8) {
        FAKE_CR8.store(irql, Ordering::SeqCst);
        FAKE_CR8_MAX.fetch_max(irql, Ordering::SeqCst);
    }

    #[test]
    fn test_irql_stubs_route_through_hardware_hooks() {
        // FP6: the other host tests only see the software CURRENT_IRQL. This proves that,
        // once the kernel installs its CR8 hooks, the driver's KeRaiseIrql/KeLowerIrql and
        // KeAcquire/ReleaseSpinLock reach the hook (in the guest the hook writes CR8).
        // It does not prove interrupt masking: there are no interrupts yet (Phase 4).
        let _host_state = lock_nt_host_state_for_tests();
        FAKE_CR8.store(PASSIVE_LEVEL, Ordering::SeqCst);
        FAKE_CR8_MAX.store(PASSIVE_LEVEL, Ordering::SeqCst);
        HARDWARE_IRQL_GETTER.store(fake_cr8_get as *mut (), Ordering::SeqCst);
        HARDWARE_IRQL_SETTER.store(fake_cr8_set as *mut (), Ordering::SeqCst);

        let host = NtDriverHost::new();
        let mut driver = host
            .load_driver(STANDARD_WDM_BYTES, "\\Driver\\Cr8", "\\Registry\\Cr8")
            .unwrap();
        let (reg, _backing) = UnicodeString::from_str_vec("\\Registry\\Cr8");
        assert_eq!(unsafe { driver.init(&reg) }, STATUS_SUCCESS);
        let dev_ptr = driver.driver_object.device_object;
        let mut counter_val: u32 = 0;
        let mut stack = IoStackLocation {
            major_function: IRP_MJ_DEVICE_CONTROL as u8,
            device_object: dev_ptr,
            parameters: ParametersDeviceIoControl {
                output_buffer_length: 4,
                io_control_code: IOCTL_WDM_SAMPLE_SPINLOCK_IRQL,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut irp = Irp {
            user_buffer: &mut counter_val as *mut u32 as *mut c_void,
            current_stack_location: &mut stack,
            ..Default::default()
        };
        let status = unsafe { driver.dispatch(IRP_MJ_DEVICE_CONTROL, dev_ptr, &mut irp) };
        assert_eq!(status, STATUS_SUCCESS);
        // 101 only if KeGetCurrentIrql (through the getter hook) saw DISPATCH_LEVEL.
        assert_eq!(counter_val, 101);
        assert_eq!(FAKE_CR8_MAX.load(Ordering::SeqCst), DISPATCH_LEVEL);
        assert_eq!(FAKE_CR8.load(Ordering::SeqCst), PASSIVE_LEVEL);
        unsafe { driver.unload() }.unwrap();
    }
}
