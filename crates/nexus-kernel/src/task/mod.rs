//! Hybrid Process and Thread Execution Infrastructure (Ring 0 / Ring 3).
//!
//! Provides unified executive management for both Windows NT (PE32+) and Linux (ELF64)
//! processes, independent address spaces, per-thread contexts, TEB/PEB setup,
//! and cooperative/preemptive scheduling across personality boundaries.

pub mod elf_payload;
pub mod pe_payload;
pub mod syscall;

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(all(target_arch = "x86_64", not(test)))]
use crate::arch::x86_64::{set_kernel_stack, set_user_fs_base, set_user_gs_base};
use crate::mem::pmm::PhysicalMemoryManager;
use crate::mem::vmm::{AddressSpace, PageTableFlags};
use nexus_loader::pe::{
    PeImage, IMAGE_REL_BASED_DIR64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use nexus_types::{
    Peb, PhysicalAddress, ProcessId, ProcessPersonality, Teb, ThreadId, VirtualAddress,
    PAGE_SIZE_4KB,
};
use spin::Mutex;

pub const YIELD_EXIT_CODE: i32 = 0x7FFF_0001;
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
pub const PEB_USER_VADDR: u64 = 0x0000_7FFF_FFF0_0000;
pub const TEB_USER_VADDR: u64 = 0x0000_7FFF_FFF1_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Yielded,
    Terminated(i32),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProcessError {
    PmmExhausted,
    VmmError,
    InvalidBinary,
    ExecutionFailed,
    Fault(u64), // Hardware exception vector that caused termination
}

pub struct Process {
    pub pid: ProcessId,
    pub name: String,
    pub personality: ProcessPersonality,
    pub address_space: AddressSpace,
    pub state: ProcessState,
    pub entry_point: VirtualAddress,
    pub user_stack_base: VirtualAddress,
    pub threads: Vec<Thread>,
}

pub struct Thread {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub user_rsp: u64,
    pub user_rip: u64,
    pub gs_base: u64,
    pub fs_base: u64,
    pub state: ProcessState,
}

impl Process {
    /// Creates a new isolated process with its own AddressSpace (PML4).
    pub fn new(
        pid: ProcessId,
        name: impl Into<String>,
        personality: ProcessPersonality,
        address_space: AddressSpace,
    ) -> Self {
        Self {
            pid,
            name: name.into(),
            personality,
            address_space,
            state: ProcessState::Ready,
            entry_point: VirtualAddress::new(0),
            user_stack_base: VirtualAddress::new(0),
            threads: Vec::new(),
        }
    }

    /// Spawns an isolated process from an ELF binary image with dedicated AddressSpace and user stack.
    pub fn spawn_elf(
        pid: ProcessId,
        name: impl Into<String>,
        elf_bytes: &[u8],
        kernel_as: &AddressSpace,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<Self, ProcessError> {
        let address_space =
            AddressSpace::new_user(kernel_as, pmm).map_err(|_| ProcessError::VmmError)?;
        let personality = ProcessPersonality::Linux {
            image_base: VirtualAddress::new(elf_payload::ELF_USER_BASE_VADDR),
            entry_point: VirtualAddress::new(elf_payload::ELF_USER_ENTRY_VADDR),
            brk_point: VirtualAddress::new(elf_payload::ELF_USER_BASE_VADDR + 0x10000),
        };
        let mut proc = Self::new(pid, name, personality, address_space);
        let stack_top = proc.setup_user_stack(pmm)?;
        proc.load_elf(elf_bytes, pmm)?;

        // Create initial thread for Linux process
        let main_thread = Thread {
            tid: ThreadId(1),
            pid,
            user_rsp: stack_top.as_u64(),
            user_rip: proc.entry_point.as_u64(),
            gs_base: 0,
            fs_base: 0,
            state: ProcessState::Ready,
        };
        proc.threads.push(main_thread);

        Ok(proc)
    }

    /// Spawns an isolated process from a PE32+ (x86_64) binary image with dedicated AddressSpace,
    /// base relocations applied, user stack, and Windows TEB/PEB mapped in user space.
    pub fn spawn_pe(
        pid: ProcessId,
        name: impl Into<String>,
        pe_bytes: &[u8],
        kernel_as: &AddressSpace,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<Self, ProcessError> {
        let pe = PeImage::parse(pe_bytes).map_err(|_| ProcessError::InvalidBinary)?;
        let mut address_space =
            AddressSpace::new_user(kernel_as, pmm).map_err(|_| ProcessError::VmmError)?;

        // 1. Map PE Headers (Page-aligned at image_base)
        let headers_size = (pe.size_of_headers as u64).max(PAGE_SIZE_4KB);
        let header_pages = headers_size.div_ceil(PAGE_SIZE_4KB);

        for i in 0..header_pages {
            let vaddr = VirtualAddress::new(pe.image_base + i * PAGE_SIZE_4KB);
            let frame = pmm
                .allocate_zeroed_frame()
                .ok_or(ProcessError::PmmExhausted)?;

            let src_off = (i * PAGE_SIZE_4KB) as usize;
            if src_off < pe_bytes.len() {
                let to_copy = (pe_bytes.len() - src_off).min(PAGE_SIZE_4KB as usize);
                #[cfg(all(target_arch = "x86_64", not(test)))]
                unsafe {
                    let dst = frame.as_u64() as *mut u8;
                    core::ptr::copy_nonoverlapping(pe_bytes[src_off..].as_ptr(), dst, to_copy);
                }
                #[cfg(any(not(target_arch = "x86_64"), test))]
                let _ = (frame, src_off, to_copy);
            }

            address_space
                .map_page(
                    vaddr,
                    frame,
                    PageTableFlags::PRESENT | PageTableFlags::USER,
                    pmm,
                )
                .map_err(|_| ProcessError::VmmError)?;
        }

        // 2. Map PE Sections
        for sec in &pe.sections {
            let sec_va = pe.image_base + sec.virtual_address as u64;
            let mem_size = sec.virtual_size.max(sec.size_of_raw_data) as u64;
            let pages = mem_size.div_ceil(PAGE_SIZE_4KB);

            let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER;
            if (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
                flags |= PageTableFlags::WRITABLE;
            }
            if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 {
                // If execute disabled
            }

            for i in 0..pages {
                let page_va = VirtualAddress::new(sec_va + i * PAGE_SIZE_4KB);
                let frame = pmm
                    .allocate_zeroed_frame()
                    .ok_or(ProcessError::PmmExhausted)?;

                let raw_start = sec.pointer_to_raw_data as usize + (i as usize * 4096);
                if raw_start < pe_bytes.len() && (i as usize * 4096) < sec.size_of_raw_data as usize
                {
                    let to_copy = (sec.size_of_raw_data as usize - (i as usize * 4096))
                        .min(PAGE_SIZE_4KB as usize)
                        .min(pe_bytes.len() - raw_start);

                    #[cfg(all(target_arch = "x86_64", not(test)))]
                    unsafe {
                        let dst = frame.as_u64() as *mut u8;
                        core::ptr::copy_nonoverlapping(
                            pe_bytes[raw_start..].as_ptr(),
                            dst,
                            to_copy,
                        );
                    }
                    #[cfg(any(not(target_arch = "x86_64"), test))]
                    let _ = (frame, raw_start, to_copy);
                }

                address_space
                    .map_page(page_va, frame, flags, pmm)
                    .map_err(|_| ProcessError::VmmError)?;
            }
        }

        // 3. Process Base Relocations if loaded base != preferred base
        let relocs = pe.parse_relocations(pe_bytes).unwrap_or_default();
        let delta = pe.image_base.wrapping_sub(pe.image_base); // When relocations needed for ASLR
        if delta != 0 {
            for block in relocs {
                for entry in block.entries {
                    if entry.rel_type == IMAGE_REL_BASED_DIR64 {
                        let target_va = VirtualAddress::new(
                            pe.image_base + block.page_rva as u64 + entry.offset as u64,
                        );
                        if let Some(paddr) = address_space.translate(target_va) {
                            let frame_base = paddr.as_u64();
                            let offset_in_frame = target_va.as_u64() & 0xFFF;
                            #[cfg(all(target_arch = "x86_64", not(test)))]
                            unsafe {
                                let ptr = (frame_base + offset_in_frame) as *mut u64;
                                *ptr = (*ptr).wrapping_add(delta);
                            }
                            #[cfg(any(not(target_arch = "x86_64"), test))]
                            let _ = (frame_base, offset_in_frame);
                        }
                    }
                }
            }
        }

        // 4. Setup 16KB User Stack at 0x0000_7FFF_FFFF_0000
        let stack_top = USER_STACK_TOP;
        let stack_pages = 4;
        let stack_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER;

        for i in 0..stack_pages {
            let vaddr = VirtualAddress::new(stack_top - (i + 1) * PAGE_SIZE_4KB);
            let frame = pmm
                .allocate_zeroed_frame()
                .ok_or(ProcessError::PmmExhausted)?;
            address_space
                .map_page(vaddr, frame, stack_flags, pmm)
                .map_err(|_| ProcessError::VmmError)?;
        }

        // 5. Setup PEB and TEB for Windows NT ABI
        let peb_vaddr = VirtualAddress::new(PEB_USER_VADDR);
        let teb_vaddr = VirtualAddress::new(TEB_USER_VADDR);

        let peb_frame = pmm
            .allocate_zeroed_frame()
            .ok_or(ProcessError::PmmExhausted)?;
        let teb_frame = pmm
            .allocate_zeroed_frame()
            .ok_or(ProcessError::PmmExhausted)?;

        address_space
            .map_page(peb_vaddr, peb_frame, stack_flags, pmm)
            .map_err(|_| ProcessError::VmmError)?;
        address_space
            .map_page(teb_vaddr, teb_frame, stack_flags, pmm)
            .map_err(|_| ProcessError::VmmError)?;

        // Initialize PEB & TEB contents directly into the zeroed frames
        let peb = Peb::new(pe.image_base);
        let teb = Teb::new(teb_vaddr.as_u64(), peb_vaddr.as_u64(), stack_top, pid.0, 1);

        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            let peb_dst = peb_frame.as_u64() as *mut Peb;
            core::ptr::write(peb_dst, peb);

            let teb_dst = teb_frame.as_u64() as *mut Teb;
            core::ptr::write(teb_dst, teb);
        }
        #[cfg(any(not(target_arch = "x86_64"), test))]
        let _ = (peb, teb);

        let personality = ProcessPersonality::Windows {
            image_base: VirtualAddress::new(pe.image_base),
            entry_point: pe.entry_point_va(),
            subsystem: pe.subsystem,
            teb_address: teb_vaddr,
            peb_address: peb_vaddr,
        };

        let mut proc = Self::new(pid, name, personality, address_space);
        proc.entry_point = pe.entry_point_va();
        proc.user_stack_base = VirtualAddress::new(stack_top);

        let main_thread = Thread {
            tid: ThreadId(1),
            pid,
            user_rsp: stack_top,
            user_rip: proc.entry_point.as_u64(),
            gs_base: teb_vaddr.as_u64(),
            fs_base: 0,
            state: ProcessState::Ready,
        };
        proc.threads.push(main_thread);

        Ok(proc)
    }

    /// Sets up a 16KB user-mode stack at the top of canonical user space (0x0000_7FFF_FFFF_0000).
    pub fn setup_user_stack(
        &mut self,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<VirtualAddress, ProcessError> {
        let stack_top = USER_STACK_TOP;
        let stack_pages = 4; // 16 KB user stack
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER;

        for i in 0..stack_pages {
            let vaddr = VirtualAddress::new(stack_top - (i + 1) * PAGE_SIZE_4KB);
            let frame = pmm
                .allocate_zeroed_frame()
                .ok_or(ProcessError::PmmExhausted)?;
            self.address_space
                .map_page(vaddr, frame, flags, pmm)
                .map_err(|_| ProcessError::VmmError)?;
        }

        self.user_stack_base = VirtualAddress::new(stack_top);
        Ok(self.user_stack_base)
    }

    /// Loads an ELF64 binary image into this process's isolated address space.
    pub fn load_elf(
        &mut self,
        elf_bytes: &[u8],
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), ProcessError> {
        let elf =
            nexus_loader::ElfImage::parse(elf_bytes).map_err(|_| ProcessError::InvalidBinary)?;

        for ph in &elf.program_headers {
            if ph.p_type == 1 {
                // PT_LOAD
                let vaddr_start = ph.p_vaddr & !0xFFF;
                let vaddr_end = (ph.p_vaddr + ph.p_memsz + 0xFFF) & !0xFFF;
                let pages = (vaddr_end - vaddr_start) / PAGE_SIZE_4KB;

                let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER;
                if (ph.p_flags & 2) != 0 {
                    // PF_W
                    flags |= PageTableFlags::WRITABLE;
                }

                for i in 0..pages {
                    let page_vaddr = VirtualAddress::new(vaddr_start + i * PAGE_SIZE_4KB);
                    let frame = pmm
                        .allocate_zeroed_frame()
                        .ok_or(ProcessError::PmmExhausted)?;

                    let file_start = ph.p_offset as usize + (i as usize * PAGE_SIZE_4KB as usize);
                    if file_start < elf_bytes.len() {
                        let to_copy = (elf_bytes.len() - file_start).min(PAGE_SIZE_4KB as usize);
                        #[cfg(all(target_arch = "x86_64", not(test)))]
                        unsafe {
                            let dst = frame.as_u64() as *mut u8;
                            core::ptr::copy_nonoverlapping(
                                elf_bytes[file_start..].as_ptr(),
                                dst,
                                to_copy,
                            );
                        }
                        #[cfg(any(not(target_arch = "x86_64"), test))]
                        let _ = to_copy;
                    }

                    self.address_space
                        .map_page(page_vaddr, frame, flags, pmm)
                        .map_err(|_| ProcessError::VmmError)?;
                }
            }
        }

        self.entry_point = VirtualAddress::new(elf.entry_point);
        Ok(())
    }
}

static ACTIVE_AS: Mutex<AddressSpace> =
    Mutex::new(AddressSpace::from_pml4(PhysicalAddress::new(0)));

pub fn get_active_address_space() -> AddressSpace {
    *ACTIVE_AS.lock()
}

pub fn set_active_address_space(aspace: AddressSpace) {
    let mut guard = ACTIVE_AS.lock();
    *guard = aspace;
}

static ACTIVE_PERSONALITY: Mutex<ProcessPersonality> = Mutex::new(ProcessPersonality::Linux {
    image_base: VirtualAddress::new(0),
    entry_point: VirtualAddress::new(0),
    brk_point: VirtualAddress::new(0),
});

pub fn get_active_personality() -> ProcessPersonality {
    ACTIVE_PERSONALITY.lock().clone()
}

pub fn set_active_personality(pers: ProcessPersonality) {
    let mut guard = ACTIVE_PERSONALITY.lock();
    *guard = pers;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SavedThreadRegisters {
    pub user_rip: u64,
    pub user_rsp: u64,
    pub has_saved: bool,
}

pub static SAVED_THREAD_REGS: Mutex<SavedThreadRegisters> = Mutex::new(SavedThreadRegisters {
    user_rip: 0,
    user_rsp: 0,
    has_saved: false,
});

pub fn save_active_thread_registers(frame: &syscall::SyscallFrame) {
    let mut guard = SAVED_THREAD_REGS.lock();
    guard.user_rip = frame.rcx;
    guard.user_rsp = frame.rsp;
    guard.has_saved = true;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelSavedContext {
    pub rsp: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

pub static mut KERNEL_SAVED_CTX: KernelSavedContext = KernelSavedContext {
    rsp: 0,
    rbp: 0,
    rbx: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    rip: 0,
};

#[cfg(all(target_arch = "x86_64", not(test)))]
extern "win64" {
    fn nexus_enter_user(
        ctx: *mut KernelSavedContext,
        user_rsp: u64,
        user_rip: u64,
        gs_base: u64,
    ) -> i32;
    fn trigger_user_abort_asm(ctx: *const KernelSavedContext, exit_code: i32) -> !;
}

#[cfg(all(target_arch = "x86_64", not(test)))]
core::arch::global_asm!(
    r#"
    .global nexus_enter_user
    nexus_enter_user:
        // Win64 ABI: rcx = ctx, rdx = user_rsp, r8 = user_rip, r9 = user_gs_base
        mov [rcx + 0x00], rsp
        mov [rcx + 0x08], rbp
        mov [rcx + 0x10], rbx
        mov [rcx + 0x18], r12
        mov [rcx + 0x20], r13
        mov [rcx + 0x28], r14
        mov [rcx + 0x30], r15
        lea rax, [rip + .Lreturn_point]
        mov [rcx + 0x38], rax

        // Preserve input arguments across selector reloading
        mov r12, rdx  // user_rsp
        mov r13, r8   // user_rip
        mov r14, r9   // user_gs_base

        // Load Ring 3 data selectors (0x1B)
        mov ax, 0x1b
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax

        // Explicitly set IA32_GS_BASE (0xC0000101) after loading selector
        test r14, r14
        jz 1f
        mov ecx, 0xC0000101
        mov eax, r14d
        mov rdx, r14
        shr rdx, 32
        wrmsr
    1:

        // Build hardware iretq frame: SS, RSP, RFLAGS, CS, RIP
        push 0x1b  // SS
        push r12   // RSP
        push 0x202 // RFLAGS
        push 0x23  // CS
        push r13   // RIP
        iretq

    .Lreturn_point:
        // Land here upon trigger_user_abort_asm!
        // EAX contains exit code
        mov cx, 0x10
        mov ds, cx
        mov es, cx
        mov ss, cx
        ret

    .global trigger_user_abort_asm
    trigger_user_abort_asm:
        // Win64 ABI: rcx = ctx, edx = exit_code
        mov eax, edx
        mov rsp, [rcx + 0x00]
        mov rbp, [rcx + 0x08]
        mov rbx, [rcx + 0x10]
        mov r12, [rcx + 0x18]
        mov r13, [rcx + 0x20]
        mov r14, [rcx + 0x28]
        mov r15, [rcx + 0x30]
        jmp qword ptr [rcx + 0x38]
    "#
);

/// Triggers safe unwinding from Ring 3 exception or syscall exit back to kernel.
pub fn trigger_user_abort(exit_code: i32) {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        trigger_user_abort_asm(&raw const KERNEL_SAVED_CTX, exit_code);
    }
    #[cfg(any(not(target_arch = "x86_64"), test))]
    let _ = exit_code;
}

/// Triggers yield unwinding back to kernel scheduler without terminating the process.
pub fn trigger_user_yield() {
    trigger_user_abort(YIELD_EXIT_CODE);
}

/// Hybrid Preemptive & Cooperative Scheduler.
pub struct Scheduler {
    pub processes: Vec<Process>,
    pub current_idx: usize,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
            current_idx: 0,
        }
    }

    pub fn add_process(&mut self, proc: Process) {
        self.processes.push(proc);
    }

    /// Runs all queued processes in an interleaved, round-robin manner until all terminate.
    pub fn run_all(&mut self, kernel_as: &AddressSpace) -> Result<(), ProcessError> {
        let mut completed = 0;
        let total = self.processes.len();

        while completed < total {
            let proc_idx = self.current_idx % self.processes.len();
            self.current_idx += 1;

            let proc = &mut self.processes[proc_idx];
            if proc.state == ProcessState::Ready || proc.state == ProcessState::Yielded {
                serial_println!(
                    "[*] [Scheduler] Dispatching PID {} ('{}', {}) in Ring 3...",
                    proc.pid.0,
                    proc.name,
                    proc.personality.name()
                );

                set_active_personality(proc.personality.clone());
                set_active_address_space(proc.address_space);

                let (user_rsp, user_rip, gs_base, fs_base) = {
                    let thread = &proc.threads[0];
                    (
                        thread.user_rsp,
                        thread.user_rip,
                        thread.gs_base,
                        thread.fs_base,
                    )
                };

                #[cfg(all(target_arch = "x86_64", not(test)))]
                let exit_code = unsafe {
                    // 1. Setup kernel stack in TSS
                    let kstack = &raw mut crate::arch::x86_64::KERNEL_STACK;
                    let kstack_top = (kstack as u64) + 16384;
                    set_kernel_stack(kstack_top);
                    syscall::KERNEL_RSP_SCRATCH = kstack_top;

                    // 2. Set MSRs for FS/GS base
                    set_user_gs_base(gs_base);
                    set_user_fs_base(fs_base);

                    // 3. Switch to process AddressSpace (CR3)
                    proc.address_space.switch_to();

                    // 4. Enter user mode
                    let res =
                        nexus_enter_user(&raw mut KERNEL_SAVED_CTX, user_rsp, user_rip, gs_base);

                    // 5. Restore Kernel CR3 immediately upon return
                    kernel_as.switch_to();
                    set_active_address_space(*kernel_as);

                    res
                };

                #[cfg(any(not(target_arch = "x86_64"), test))]
                let exit_code = {
                    let _ = (kernel_as, user_rsp, user_rip, gs_base, fs_base);
                    0
                };

                if exit_code == YIELD_EXIT_CODE {
                    serial_println!(
                        "[+] [Scheduler] PID {} yielded CPU cooperatively. Saving thread state.",
                        proc.pid.0
                    );
                    let mut guard = SAVED_THREAD_REGS.lock();
                    if guard.has_saved {
                        proc.threads[0].user_rip = guard.user_rip;
                        proc.threads[0].user_rsp = guard.user_rsp;
                        guard.has_saved = false;
                    }
                    proc.state = ProcessState::Yielded;
                } else if exit_code >= 0 {
                    serial_println!(
                        "[+] [Scheduler] PID {} terminated cleanly with code {}.",
                        proc.pid.0,
                        exit_code
                    );
                    proc.state = ProcessState::Terminated(exit_code);
                    completed += 1;
                } else {
                    let vector = (-exit_code) as u64;
                    serial_println!(
                        "[-] [Scheduler] PID {} terminated by hardware exception (Vector {}).",
                        proc.pid.0,
                        vector
                    );
                    proc.state = ProcessState::Terminated(exit_code);
                    completed += 1;
                }
            }
        }

        Ok(())
    }
}

/// Executes a single user process in Ring 3, returning when the process exits or faults.
pub fn run_user_process(
    process: &mut Process,
    kernel_as: &AddressSpace,
) -> Result<i32, ProcessError> {
    serial_println!(
        "[*] Launching Process '{}' (PID {}) in Ring 3...",
        process.name,
        process.pid.0
    );
    serial_println!("    - Entry RIP: {:#018X}", process.entry_point.as_u64());
    serial_println!(
        "    - User RSP:  {:#018X}",
        process.user_stack_base.as_u64()
    );

    set_active_personality(process.personality.clone());
    set_active_address_space(process.address_space);

    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        // Setup thread-specific kernel stack in TSS
        let kstack = &raw mut crate::arch::x86_64::KERNEL_STACK;
        let kstack_top = (kstack as u64) + 16384;
        set_kernel_stack(kstack_top);
        syscall::KERNEL_RSP_SCRATCH = kstack_top;

        let gs_base = if let ProcessPersonality::Windows { teb_address, .. } = process.personality {
            teb_address.as_u64()
        } else {
            0
        };

        // Switch to user address space
        process.address_space.switch_to();

        let user_entry = process.entry_point.as_u64();
        let user_stack = process.user_stack_base.as_u64();

        // Enter user mode and await exit or fault abort
        let exit_code =
            nexus_enter_user(&raw mut KERNEL_SAVED_CTX, user_stack, user_entry, gs_base);

        // Restore Kernel CR3
        kernel_as.switch_to();
        set_active_address_space(*kernel_as);

        let is_fault = exit_code > 0 && exit_code <= 32;
        if is_fault {
            let fault_vector = exit_code as u64;
            process.state = ProcessState::Terminated(exit_code);
            return Err(ProcessError::Fault(fault_vector));
        }

        process.state = ProcessState::Terminated(exit_code);
        Ok(exit_code)
    }

    #[cfg(any(not(target_arch = "x86_64"), test))]
    {
        let _ = (process, kernel_as);
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_creation() {
        let dummy_as = AddressSpace::from_pml4(PhysicalAddress::new(0x5000));
        let proc = Process::new(
            ProcessId(1),
            "test_proc",
            ProcessPersonality::Linux {
                image_base: VirtualAddress::new(0x400000),
                entry_point: VirtualAddress::new(0x401000),
                brk_point: VirtualAddress::new(0x405000),
            },
            dummy_as,
        );
        assert_eq!(proc.pid.0, 1);
        assert!(proc.personality.is_linux());
    }
}
