//! Unified process execution. Cooperative, single CPU; no preemption/SMP claims.
pub mod elf_payload;
pub mod pe_payload;
pub mod syscall;

use crate::mem::pmm::PhysicalMemoryManager;
use crate::mem::vmm::{AddressSpace, PageTableFlags};
use core::sync::atomic::{AtomicU64, Ordering};
use nexus_loader::{ElfImage, PeImage};
#[cfg(any(target_os = "uefi", target_os = "none"))]
use nexus_types::{Peb, Teb};
use nexus_types::{PhysicalAddress, ProcessId, ProcessPersonality, ThreadId, VirtualAddress};
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
    UnsupportedExecution,
    Fault(u64),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Exit(i32),
    Yield,
    Fault(u64),
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
    pub outcome: Option<RunOutcome>,
    frames: Vec<PhysicalAddress>,
}
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxState(pub [u8; 512]);
impl Default for FxState {
    fn default() -> Self {
        let mut bytes = [0; 512];
        bytes[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        bytes[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        Self(bytes)
    }
}
pub struct Thread {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub user_rsp: u64,
    pub user_rip: u64,
    pub gs_base: u64,
    pub fs_base: u64,
    pub state: ProcessState,
    pub registers: syscall::SyscallFrame,
    pub fx: FxState,
}
impl Process {
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
            frames: Vec::new(),
            outcome: None,
        }
    }
    fn frame(&mut self, pmm: &mut PhysicalMemoryManager) -> Result<PhysicalAddress, ProcessError> {
        self.frames
            .try_reserve(1)
            .map_err(|_| ProcessError::PmmExhausted)?;
        let frame = pmm
            .allocate_zeroed_frame()
            .ok_or(ProcessError::PmmExhausted)?;
        self.frames.push(frame);
        Ok(frame)
    }
    /// Map exactly the file-backed bytes; prefix and BSS remain zero, including unaligned segments.
    fn map_segment(
        &mut self,
        va: u64,
        memsz: u64,
        bytes: &[u8],
        flags: PageTableFlags,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), ProcessError> {
        if memsz == 0 {
            return Ok(());
        }
        let start = va & !4095;
        let end = va
            .checked_add(memsz)
            .and_then(|v| v.checked_add(4095))
            .ok_or(ProcessError::InvalidBinary)?
            & !4095;
        for page in (start..end).step_by(4096) {
            let frame = self.frame(pmm)?;
            let copy_start = page.max(va);
            let copy_end = (page + 4096).min(va + bytes.len() as u64);
            if copy_start < copy_end {
                let offset = (copy_start - va) as usize;
                let count = (copy_end - copy_start) as usize;
                #[cfg(any(target_os = "uefi", target_os = "none"))]
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes[offset..offset + count].as_ptr(),
                        (frame.as_u64() + copy_start - page) as *mut u8,
                        count,
                    );
                }
                #[cfg(not(any(target_os = "uefi", target_os = "none")))]
                let _ = (offset, count);
            }
            self.address_space
                .map_page(VirtualAddress::new(page), frame, flags, pmm)
                .map_err(|_| ProcessError::VmmError)?;
        }
        Ok(())
    }
    fn initial_thread(&mut self, stack: u64, fs: u64, gs: u64) {
        let registers = syscall::SyscallFrame {
            rcx: self.entry_point.as_u64(),
            rsp: stack,
            r11: 2,
            fs_base: fs,
            gs_base: gs,
            ..Default::default()
        };
        self.threads.push(Thread {
            tid: ThreadId(1),
            pid: self.pid,
            user_rsp: stack,
            user_rip: registers.rcx,
            fs_base: fs,
            gs_base: gs,
            state: ProcessState::Ready,
            registers,
            fx: FxState::default(),
        });
    }
    pub fn spawn_elf(
        pid: ProcessId,
        name: impl Into<String>,
        bytes: &[u8],
        kernel: &AddressSpace,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<Self, ProcessError> {
        let elf = ElfImage::parse(bytes).map_err(|_| ProcessError::InvalidBinary)?;
        // Dynamic interpreter/TLS startup and executable stacks are not implemented.
        if elf.elf_type != 2
            || elf.program_headers.iter().any(|p| {
                matches!(p.p_type, 2 | 3 | 7)
                    || (p.p_type == 0x6474e551 && p.p_flags & 1 != 0)
                    || (p.p_type == 1 && p.p_flags & 3 == 3)
            })
        {
            return Err(ProcessError::InvalidBinary);
        }
        let base = elf
            .loadable_segments()
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0);
        let brk = elf
            .loadable_segments()
            .map(|p| p.p_vaddr + p.p_memsz)
            .max()
            .unwrap_or(0)
            .div_ceil(4096)
            * 4096;
        let personality = ProcessPersonality::Linux {
            image_base: VirtualAddress::new(base),
            entry_point: elf.entry_point_va(),
            brk_point: VirtualAddress::new(brk),
        };
        let space = AddressSpace::new_user(kernel, pmm).map_err(|_| ProcessError::VmmError)?;
        let mut proc = Self::new(pid, name, personality, space);
        let result = (|| {
            proc.load_elf(bytes, pmm)?;
            proc.setup_user_stack(pmm)?;
            // Empty argc/argv/envp/auxv, not a libc-compatible complete startup environment.
            let stack = USER_STACK_TOP - 48;
            proc.initial_thread(stack, 0, 0);
            Ok(())
        })();
        if let Err(error) = result {
            proc.release(pmm)?;
            return Err(error);
        }
        Ok(proc)
    }
    pub fn spawn_pe(
        pid: ProcessId,
        name: impl Into<String>,
        bytes: &[u8],
        kernel: &AddressSpace,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<Self, ProcessError> {
        let pe = PeImage::parse(bytes).map_err(|_| ProcessError::InvalidBinary)?;
        // Fail closed: no IAT resolver, TLS callbacks or delayed imports.
        if [1usize, 9, 13].iter().any(|&i| {
            pe.data_directories[i].size != 0 || pe.data_directories[i].virtual_address != 0
        }) || pe
            .sections
            .iter()
            .any(|s| s.characteristics & 0xa0000000 == 0xa0000000)
        {
            return Err(ProcessError::InvalidBinary);
        }
        pe.parse_relocations(bytes)
            .map_err(|_| ProcessError::InvalidBinary)?;
        let personality = ProcessPersonality::Windows {
            image_base: VirtualAddress::new(pe.image_base),
            entry_point: pe.entry_point_va(),
            subsystem: pe.subsystem,
            teb_address: VirtualAddress::new(TEB_USER_VADDR),
            peb_address: VirtualAddress::new(PEB_USER_VADDR),
        };
        let space = AddressSpace::new_user(kernel, pmm).map_err(|_| ProcessError::VmmError)?;
        let mut proc = Self::new(pid, name, personality, space);
        let result = (|| {
            proc.map_segment(
                pe.image_base,
                pe.size_of_headers as u64,
                &bytes[..pe.size_of_headers as usize],
                PageTableFlags::USER | PageTableFlags::NO_EXECUTE,
                pmm,
            )?;
            for section in &pe.sections {
                let mut flags = PageTableFlags::USER;
                if section.characteristics & 0x80000000 != 0 {
                    flags |= PageTableFlags::WRITABLE;
                }
                if section.characteristics & 0x20000000 == 0 {
                    flags |= PageTableFlags::NO_EXECUTE;
                }
                let off = section.pointer_to_raw_data as usize;
                let len = section.size_of_raw_data as usize;
                proc.map_segment(
                    pe.image_base + section.virtual_address as u64,
                    section.virtual_size.max(section.size_of_raw_data) as u64,
                    &bytes[off..off + len],
                    flags,
                    pmm,
                )?;
            }
            proc.entry_point = pe.entry_point_va();
            proc.setup_user_stack(pmm)?;
            let flags =
                PageTableFlags::USER | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
            let peb_frame = proc.frame(pmm)?;
            proc.address_space
                .map_page(VirtualAddress::new(PEB_USER_VADDR), peb_frame, flags, pmm)
                .map_err(|_| ProcessError::VmmError)?;
            let teb_frame = proc.frame(pmm)?;
            proc.address_space
                .map_page(VirtualAddress::new(TEB_USER_VADDR), teb_frame, flags, pmm)
                .map_err(|_| ProcessError::VmmError)?;
            #[cfg(any(target_os = "uefi", target_os = "none"))]
            unsafe {
                core::ptr::write(peb_frame.as_u64() as *mut Peb, Peb::new(pe.image_base));
                core::ptr::write(
                    teb_frame.as_u64() as *mut Teb,
                    Teb::new(TEB_USER_VADDR, PEB_USER_VADDR, USER_STACK_TOP, pid.0, 1),
                );
            }
            proc.initial_thread(USER_STACK_TOP - 8, 0, TEB_USER_VADDR);
            Ok(())
        })();
        if let Err(error) = result {
            proc.release(pmm)?;
            return Err(error);
        }
        Ok(proc)
    }
    pub fn setup_user_stack(
        &mut self,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<VirtualAddress, ProcessError> {
        self.map_segment(
            USER_STACK_TOP - 16384,
            16384,
            &[],
            PageTableFlags::USER | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            pmm,
        )?;
        self.user_stack_base = VirtualAddress::new(USER_STACK_TOP);
        Ok(self.user_stack_base)
    }
    pub fn load_elf(
        &mut self,
        bytes: &[u8],
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), ProcessError> {
        let elf = ElfImage::parse(bytes).map_err(|_| ProcessError::InvalidBinary)?;
        for ph in elf.loadable_segments() {
            let mut flags = PageTableFlags::USER;
            if ph.p_flags & 2 != 0 {
                flags |= PageTableFlags::WRITABLE;
            }
            if ph.p_flags & 1 == 0 {
                flags |= PageTableFlags::NO_EXECUTE;
            }
            let off = ph.p_offset as usize;
            let len = ph.p_filesz as usize;
            self.map_segment(ph.p_vaddr, ph.p_memsz, &bytes[off..off + len], flags, pmm)?;
        }
        self.entry_point = elf.entry_point_va();
        Ok(())
    }
    #[cfg(feature = "hardening-tests")]
    pub fn map_validation_page(
        &mut self,
        va: u64,
        initial: &[u8],
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<(), ProcessError> {
        self.map_segment(
            va,
            4096,
            initial,
            PageTableFlags::USER | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            pmm,
        )
    }
    /// Explicit reaping. Never free a currently active CR3 or a running thread.
    pub fn release(&mut self, pmm: &mut PhysicalMemoryManager) -> Result<(), ProcessError> {
        if self.state == ProcessState::Running || self.address_space.is_active() {
            return Err(ProcessError::ExecutionFailed);
        }
        self.address_space
            .destroy(pmm)
            .map_err(|_| ProcessError::VmmError)?;
        for frame in self.frames.drain(..) {
            pmm.free_frame(frame);
        }
        self.threads.clear();
        self.state = ProcessState::Terminated(match self.outcome {
            Some(RunOutcome::Exit(code)) => code,
            Some(RunOutcome::Fault(vector)) => -(vector as i32),
            _ => -1,
        });
        Ok(())
    }
}

static ACTIVE_ROOT: AtomicU64 = AtomicU64::new(0);
pub fn get_active_address_space() -> AddressSpace {
    AddressSpace::from_pml4(PhysicalAddress::new(ACTIVE_ROOT.load(Ordering::Relaxed)))
}
pub fn set_active_address_space(space: &AddressSpace) {
    ACTIVE_ROOT.store(space.pml4_frame().as_u64(), Ordering::Relaxed);
}
static ACTIVE_PERSONALITY: Mutex<ProcessPersonality> = Mutex::new(ProcessPersonality::Linux {
    image_base: VirtualAddress::new(0),
    entry_point: VirtualAddress::new(0),
    brk_point: VirtualAddress::new(0),
});
pub fn get_active_personality() -> ProcessPersonality {
    ACTIVE_PERSONALITY.lock().clone()
}
pub fn set_active_personality(personality: ProcessPersonality) {
    *ACTIVE_PERSONALITY.lock() = personality;
}
static SAVED_REGISTERS: Mutex<Option<syscall::SyscallFrame>> = Mutex::new(None);
static LAST_OUTCOME: Mutex<Option<RunOutcome>> = Mutex::new(None);
pub fn save_active_thread_registers(frame: &syscall::SyscallFrame) {
    *SAVED_REGISTERS.lock() = Some(*frame);
}

#[repr(C, align(16))]
pub struct KernelSavedContext {
    pub rsp: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rflags: u64,
    pub padding: u64,
    pub fx: FxState,
}
#[no_mangle]
pub static mut KERNEL_SAVED_CTX: KernelSavedContext = KernelSavedContext {
    rsp: 0,
    rbp: 0,
    rbx: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    rip: 0,
    rdi: 0,
    rsi: 0,
    rflags: 0,
    padding: 0,
    fx: FxState([0; 512]),
};
#[no_mangle]
pub static mut USER_FX: FxState = FxState([0; 512]);

#[cfg(any(target_os = "uefi", target_os = "none"))]
extern "win64" {
    fn nexus_enter_user(
        ctx: *mut KernelSavedContext,
        registers: *const syscall::SyscallFrame,
        fx: *const FxState,
    );
    fn trigger_user_abort_asm(ctx: *const KernelSavedContext) -> !;
}

#[cfg(any(target_os = "uefi", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .global nexus_enter_user
    nexus_enter_user:
        mov [rcx + 0x00], rsp
        mov [rcx + 0x08], rbp
        mov [rcx + 0x10], rbx
        mov [rcx + 0x18], r12
        mov [rcx + 0x20], r13
        mov [rcx + 0x28], r14
        mov [rcx + 0x30], r15
        lea rax, [rip + .Lreturn_point]
        mov [rcx + 0x38], rax
        mov [rcx + 0x40], rdi
        mov [rcx + 0x48], rsi
        pushfq
        pop qword ptr [rcx + 0x50]
        fxsave64 [rcx + 0x60]

        mov r12, rdx
        mov r13, r8
        mov ax, 0x1b
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax
        mov ecx, 0xc0000100
        mov rdx, [r12 + 0x80]
        mov eax, edx
        shr rdx, 32
        wrmsr
        mov ecx, 0xc0000101
        mov rdx, [r12 + 0x88]
        mov eax, edx
        shr rdx, 32
        wrmsr
        push qword ptr [r12 + 0x78]
        push qword ptr [r12 + 0x70]
        push qword ptr [r12 + 0x68]
        push qword ptr [r12 + 0x60]
        push qword ptr [r12 + 0x58]
        push qword ptr [r12 + 0x50]
        push qword ptr [r12 + 0x48]
        push qword ptr [r12 + 0x40]
        push qword ptr [r12 + 0x38]
        push qword ptr [r12 + 0x30]
        push qword ptr [r12 + 0x28]
        push qword ptr [r12 + 0x20]
        push qword ptr [r12 + 0x18]
        push qword ptr [r12 + 0x10]
        push qword ptr [r12 + 0x08]
        push qword ptr [r12 + 0x00]
        fxrstor64 [r13]
        jmp asm_restore_user_frame
    .Lreturn_point:
        mov cx, 0x10
        mov ds, cx
        mov es, cx
        mov ss, cx
        xor ecx, ecx
        mov fs, cx
        mov gs, cx
        ret

    .global trigger_user_abort_asm
    trigger_user_abort_asm:
        fxrstor64 [rcx + 0x60]
        push qword ptr [rcx + 0x50]
        popfq
        mov rsp, [rcx + 0x00]
        mov rbp, [rcx + 0x08]
        mov rbx, [rcx + 0x10]
        mov r12, [rcx + 0x18]
        mov r13, [rcx + 0x20]
        mov r14, [rcx + 0x28]
        mov r15, [rcx + 0x30]
        mov rdi, [rcx + 0x40]
        mov rsi, [rcx + 0x48]
        jmp qword ptr [rcx + 0x38]
"#
);

pub fn finish_user(outcome: RunOutcome) {
    *LAST_OUTCOME.lock() = Some(outcome);
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    unsafe {
        trigger_user_abort_asm(&raw const KERNEL_SAVED_CTX);
    }
}
pub fn trigger_user_abort(vector: i32) {
    finish_user(RunOutcome::Fault(vector as u64));
}
pub fn trigger_user_yield() {
    finish_user(RunOutcome::Yield);
}

fn execute_step(process: &mut Process, kernel: &AddressSpace) -> Result<RunOutcome, ProcessError> {
    #[cfg(not(any(target_os = "uefi", target_os = "none")))]
    {
        let _ = (process, kernel);
        Err(ProcessError::UnsupportedExecution)
    }
    #[cfg(any(target_os = "uefi", target_os = "none"))]
    unsafe {
        if !matches!(process.state, ProcessState::Ready | ProcessState::Yielded)
            || process.threads.len() != 1
        {
            return Err(ProcessError::ExecutionFailed);
        }
        let thread = &mut process.threads[0];
        if syscall::validate_return_context(&thread.registers, &process.address_space).is_err() {
            return Err(ProcessError::ExecutionFailed);
        }
        *LAST_OUTCOME.lock() = None;
        *SAVED_REGISTERS.lock() = None;
        process.state = ProcessState::Running;
        thread.state = ProcessState::Running;
        set_active_personality(process.personality.clone());
        set_active_address_space(&process.address_space);
        let stack = (&raw mut crate::arch::x86_64::KERNEL_STACK as u64) + 16384;
        crate::arch::x86_64::set_kernel_stack(stack);
        syscall::KERNEL_RSP_SCRATCH = stack;
        process.address_space.switch_to();
        nexus_enter_user(&raw mut KERNEL_SAVED_CTX, &thread.registers, &thread.fx);
        kernel.switch_to();
        set_active_address_space(kernel);
        crate::arch::x86_64::set_user_fs_base(0);
        crate::arch::x86_64::set_user_gs_base(0);
        let outcome = LAST_OUTCOME
            .lock()
            .take()
            .ok_or(ProcessError::ExecutionFailed)?;
        match outcome {
            RunOutcome::Yield => {
                thread.registers = SAVED_REGISTERS
                    .lock()
                    .take()
                    .ok_or(ProcessError::ExecutionFailed)?;
                thread.fx = core::ptr::read(&raw const USER_FX);
                thread.fs_base = thread.registers.fs_base;
                thread.gs_base = thread.registers.gs_base;
                thread.user_rip = thread.registers.rcx;
                thread.user_rsp = thread.registers.rsp;
                process.state = ProcessState::Yielded;
            }
            RunOutcome::Exit(code) => process.state = ProcessState::Terminated(code),
            RunOutcome::Fault(vector) => process.state = ProcessState::Terminated(-(vector as i32)),
        }
        thread.state = process.state;
        process.outcome = Some(outcome);
        Ok(outcome)
    }
}

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
    pub fn add_process(&mut self, process: Process) {
        self.processes.push(process);
    }
    pub fn run_all(&mut self, kernel: &AddressSpace) -> Result<(), ProcessError> {
        while self
            .processes
            .iter()
            .any(|p| !matches!(p.state, ProcessState::Terminated(_)))
        {
            // Windows NT architectural rule: Preemption / thread dispatching is strictly forbidden
            // when hardware IRQL >= DISPATCH_LEVEL (2).
            if crate::arch::x86_64::read_cr8_irql() >= nexus_types::driver::DISPATCH_LEVEL {
                return Err(ProcessError::UnsupportedExecution);
            }
            let idx = self.current_idx % self.processes.len();
            self.current_idx = self.current_idx.wrapping_add(1);
            let process = &mut self.processes[idx];
            if matches!(process.state, ProcessState::Terminated(_)) {
                continue;
            }
            let outcome = execute_step(process, kernel)?;
            if outcome != RunOutcome::Yield {
                process.release(&mut crate::mem::pmm::PMM.lock())?;
            }
        }
        Ok(())
    }
}
pub fn run_user_process(process: &mut Process, kernel: &AddressSpace) -> Result<i32, ProcessError> {
    match execute_step(process, kernel)? {
        RunOutcome::Exit(code) => Ok(code),
        RunOutcome::Yield => Ok(YIELD_EXIT_CODE),
        RunOutcome::Fault(vector) => Err(ProcessError::Fault(vector)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_process_creation_and_host_execution_is_explicitly_unsupported() {
        let mut proc = Process::new(
            ProcessId(1),
            "test",
            ProcessPersonality::Linux {
                image_base: VirtualAddress::new(0x400000),
                entry_point: VirtualAddress::new(0x401000),
                brk_point: VirtualAddress::new(0x405000),
            },
            AddressSpace::from_pml4(PhysicalAddress::new(0x5000)),
        );
        assert_eq!(proc.pid.0, 1);
        let kernel = AddressSpace::from_pml4(PhysicalAddress::new(0x6000));
        assert_eq!(
            run_user_process(&mut proc, &kernel),
            Err(ProcessError::UnsupportedExecution)
        );
        assert_eq!(proc.state, ProcessState::Ready);
        let mut scheduler = Scheduler::new();
        assert!(scheduler.run_all(&kernel).is_ok());
    }
    #[test]
    fn context_layout_matches_assembly_and_fx_initial_state() {
        assert_eq!(core::mem::offset_of!(KernelSavedContext, fx), 0x60);
        assert_eq!(core::mem::align_of::<FxState>(), 16);
        let fx = FxState::default();
        assert_eq!(&fx.0[24..28], &0x1f80u32.to_le_bytes());
    }
}
