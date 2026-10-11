//! Hybrid Process and Thread Execution Infrastructure (Ring 0 / Ring 3).

pub mod elf_payload;
pub mod syscall;

#[cfg(all(target_arch = "x86_64", not(test)))]
use crate::arch::x86_64::set_kernel_stack;
use crate::mem::pmm::PhysicalMemoryManager;
use crate::mem::vmm::{AddressSpace, PageTableFlags};
use nexus_types::{
    PhysicalAddress, ProcessId, ProcessPersonality, ThreadId, VirtualAddress, PAGE_SIZE_4KB,
};
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
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
    pub name: &'static str,
    pub personality: ProcessPersonality,
    pub address_space: AddressSpace,
    pub state: ProcessState,
    pub entry_point: VirtualAddress,
    pub user_stack_base: VirtualAddress,
}

impl Process {
    /// Creates a new isolated process with its own AddressSpace (PML4).
    pub fn new(
        pid: ProcessId,
        name: &'static str,
        personality: ProcessPersonality,
        address_space: AddressSpace,
    ) -> Self {
        Self {
            pid,
            name,
            personality,
            address_space,
            state: ProcessState::Ready,
            entry_point: VirtualAddress::new(0),
            user_stack_base: VirtualAddress::new(0),
        }
    }

    /// Spawns an isolated process from an ELF binary image with dedicated AddressSpace and user stack.
    pub fn spawn_elf(
        pid: ProcessId,
        name: &'static str,
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
        proc.setup_user_stack(pmm)?;
        proc.load_elf(elf_bytes, pmm)?;
        Ok(proc)
    }

    /// Sets up a 16KB user-mode stack at the top of canonical user space (0x0000_7FFF_FFFF_0000).
    pub fn setup_user_stack(
        &mut self,
        pmm: &mut PhysicalMemoryManager,
    ) -> Result<VirtualAddress, ProcessError> {
        let stack_top = 0x0000_7FFF_FFFF_0000_u64;
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

                    // Copy file segment content if applicable
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
                        {
                            let _ = to_copy;
                        }
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

pub struct Thread {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub user_rsp: u64,
    pub user_rip: u64,
    pub kernel_stack_top: u64,
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
extern "C" {
    fn nexus_enter_user(ctx: *mut KernelSavedContext, user_rsp: u64, user_rip: u64) -> i32;
    fn trigger_user_abort_asm(ctx: *const KernelSavedContext, exit_code: i32) -> !;
}

#[cfg(all(target_arch = "x86_64", not(test)))]
core::arch::global_asm!(
    r#"
    .global nexus_enter_user
    nexus_enter_user:
        // rcx = ctx, rdx = user_rsp, r8 = user_rip
        mov [rcx + 0x00], rsp
        mov [rcx + 0x08], rbp
        mov [rcx + 0x10], rbx
        mov [rcx + 0x18], r12
        mov [rcx + 0x20], r13
        mov [rcx + 0x28], r14
        mov [rcx + 0x30], r15
        lea rax, [rip + .Lreturn_point]
        mov [rcx + 0x38], rax

        // Load Ring 3 data selectors (0x1B)
        mov ax, 0x1b
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax

        // Build hardware iretq frame
        push 0x1b  // SS
        push rdx   // RSP
        push 0x202 // RFLAGS
        push 0x23  // CS
        push r8    // RIP
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
        // rcx = ctx, edx = exit_code
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
    {
        let _ = exit_code;
    }
}

/// Executes a user process in Ring 3, returning when the process exits or faults.
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

    set_active_address_space(process.address_space);

    #[cfg(all(target_arch = "x86_64", not(test)))]
    unsafe {
        // Setup thread-specific kernel stack in TSS
        let kstack = &raw mut crate::arch::x86_64::KERNEL_STACK;
        let kstack_top = (kstack as u64) + 16384;
        set_kernel_stack(kstack_top);
        syscall::KERNEL_RSP_SCRATCH = kstack_top;

        // Switch to user address space
        process.address_space.switch_to();

        let user_entry = process.entry_point.as_u64();
        let user_stack = process.user_stack_base.as_u64();

        // Enter user mode and await exit or fault abort
        let exit_code = nexus_enter_user(&raw mut KERNEL_SAVED_CTX, user_stack, user_entry);

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
                brk_point: VirtualAddress::new(0x410000),
            },
            dummy_as,
        );

        assert_eq!(proc.pid.0, 1);
        assert_eq!(proc.name, "test_proc");
        assert!(proc.personality.is_linux());
        assert_eq!(proc.state, ProcessState::Ready);
    }
}
