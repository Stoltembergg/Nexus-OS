//! Hybrid Process and Thread abstractions.

use crate::address::VirtualAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u64);

/// Target binary and subsystem personality of an execution context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessPersonality {
    /// Native Windows PE32+ application environment (NT Executive & Win32)
    Windows {
        image_base: VirtualAddress,
        entry_point: VirtualAddress,
        subsystem: u16, // 2 = GUI, 3 = Console
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
