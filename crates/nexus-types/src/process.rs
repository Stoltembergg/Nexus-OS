//! Hybrid Process and Thread abstractions.

use crate::address::VirtualAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProcessId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ThreadId(pub u64);

/// Target binary and subsystem personality of an execution context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessPersonality {
    /// Native Windows PE32+ application environment (NT Executive & Win32)
    Windows {
        image_base: VirtualAddress,
        entry_point: VirtualAddress,
        subsystem: u16, // 2 = GUI, 3 = Console
        teb_address: VirtualAddress,
        peb_address: VirtualAddress,
    },
    /// Native Linux ELF64 application environment (POSIX Pico Subsystem)
    Linux {
        image_base: VirtualAddress,
        entry_point: VirtualAddress,
        brk_point: VirtualAddress,
    },
}

impl ProcessPersonality {
    pub fn is_windows(&self) -> bool {
        matches!(self, Self::Windows { .. })
    }

    pub fn is_linux(&self) -> bool {
        matches!(self, Self::Linux { .. })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Windows { .. } => "Windows (PE32+)",
            Self::Linux { .. } => "Linux (ELF64)",
        }
    }
}

/// Saved CPU Register Context for preemptive and cooperative context switching.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

/// Minimal 64-bit Thread Environment Block (TEB) for Windows NT ABI.
/// Located at the address stored in MSR IA32_GS_BASE (0xC0000101).
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct Teb {
    pub exception_list: u64,                   // 0x00: Head of SEH chain
    pub stack_base: u64,                       // 0x08: Top of user stack
    pub stack_limit: u64,                      // 0x10: Bottom of user stack
    pub sub_system_tib: u64,                   // 0x18
    pub fiber_data: u64,                       // 0x20
    pub arbitrary_user_pointer: u64,           // 0x28
    pub teb_self: u64,                         // 0x30: Must point to TEB itself (gs:[0x30])
    pub environment_pointer: u64,              // 0x38
    pub client_id_pid: u64,                    // 0x40: ProcessId
    pub client_id_tid: u64,                    // 0x48: ThreadId
    pub rpc_handle: u64,                       // 0x50
    pub tls_storage: u64,                      // 0x58
    pub peb: u64,                              // 0x60: Pointer to PEB (gs:[0x60])
    pub last_error_value: u32,                 // 0x68: Win32 LastError
    pub count_of_owned_critical_sections: u32, // 0x6C
}

impl Default for Teb {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0)
    }
}

impl Teb {
    pub const fn new(teb_self: u64, peb: u64, stack_base: u64, pid: u64, tid: u64) -> Self {
        Self {
            exception_list: 0,
            stack_base,
            stack_limit: stack_base.saturating_sub(16384),
            sub_system_tib: 0,
            fiber_data: 0,
            arbitrary_user_pointer: 0,
            teb_self,
            environment_pointer: 0,
            client_id_pid: pid,
            client_id_tid: tid,
            rpc_handle: 0,
            tls_storage: 0,
            peb,
            last_error_value: 0,
            count_of_owned_critical_sections: 0,
        }
    }
}

/// Minimal 64-bit Process Environment Block (PEB) for Windows NT ABI.
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
pub struct Peb {
    pub inherited_address_space: u8,      // 0x00
    pub read_image_file_exec_options: u8, // 0x01
    pub being_debugged: u8,               // 0x02
    pub bit_field: u8,                    // 0x03
    pub padding: [u8; 4],                 // 0x04..0x08
    pub mutant: u64,                      // 0x08
    pub image_base_address: u64,          // 0x10: Base address of executable
    pub ldr: u64,                         // 0x18: PEB_LDR_DATA pointer
    pub process_parameters: u64,          // 0x20: RTL_USER_PROCESS_PARAMETERS
    pub sub_system_data: u64,             // 0x28
    pub process_heap: u64,                // 0x30
    pub fast_peb_lock: u64,               // 0x38
    pub os_major_version: u32,            // 0x40
    pub os_minor_version: u32,            // 0x44
    pub os_build_number: u16,             // 0x48
    pub os_platform_id: u16,              // 0x4A (VER_PLATFORM_WIN32_NT = 2)
}

impl Default for Peb {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Peb {
    pub const fn new(image_base_address: u64) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            padding: [0; 4],
            mutant: 0,
            image_base_address,
            ldr: 0,
            process_parameters: 0,
            sub_system_data: 0,
            process_heap: 0,
            fast_peb_lock: 0,
            os_major_version: 10,
            os_minor_version: 0,
            os_build_number: 19041,
            os_platform_id: 2,
        }
    }
}

/// Metadata descriptor for a hybrid process running in the kernel.
#[derive(Debug, Clone)]
pub struct HybridProcessDescriptor {
    pub pid: ProcessId,
    pub name: String,
    pub personality: ProcessPersonality,
    pub active_threads: usize,
}

impl HybridProcessDescriptor {
    pub fn new(pid: ProcessId, name: String, personality: ProcessPersonality) -> Self {
        Self {
            pid,
            name,
            personality,
            active_threads: 1,
        }
    }
}
