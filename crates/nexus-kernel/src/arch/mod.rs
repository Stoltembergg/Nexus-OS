//! CPU Architecture Abstraction Layer.

#[macro_use]
pub mod x86_64;

pub use x86_64::init_arch;
