//! Dual-Personality Syscall Multiplexer.

use crate::context::RegisterContext;
use crate::linux::dispatch_linux_syscall;
use crate::nt::dispatch_nt_syscall;
use nexus_types::process::ProcessPersonality;

#[derive(Debug, Default)]
pub struct SyscallRouter {
    pub nt_call_count: u64,
    pub linux_call_count: u64,
}

impl SyscallRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Dispatches a system call based on the calling process personality.
    pub fn dispatch(&mut self, personality: &ProcessPersonality, ctx: &mut RegisterContext) {
        match personality {
            ProcessPersonality::Windows { .. } => {
                self.nt_call_count += 1;
                let _status = dispatch_nt_syscall(ctx);
            }
            ProcessPersonality::Linux { .. } => {
                self.linux_call_count += 1;
                let _ret = dispatch_linux_syscall(ctx);
            }
        }
    }
}
