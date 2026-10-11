//! Loader error types.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum LoaderError {
    #[error("Buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },

    #[error("Invalid DOS signature: expected 0x5A4D ('MZ'), got {0:#06X}")]
    InvalidDosSignature(u16),

    #[error("Invalid PE signature: expected 'PE\\0\\0', got {0:#010X}")]
    InvalidPeSignature(u32),

    #[error("Unsupported machine architecture: expected x86_64 ({expected:#06X}), got {actual:#06X}")]
    UnsupportedMachine { expected: u16, actual: u16 },

    #[error("Invalid PE magic: expected 0x020B (PE32+ 64-bit), got {0:#06X}")]
    InvalidPeMagic(u16),

    #[error("Invalid ELF magic: expected 0x7F 'ELF', got {0:?}")]
    InvalidElfMagic([u8; 4]),

    #[error("Unsupported ELF class: expected 64-bit (Class 2), got {0}")]
    UnsupportedElfClass(u8),

    #[error("Unsupported ELF endianness: expected Little Endian (1), got {0}")]
    UnsupportedElfEndian(u8),

    #[error("Unsupported ELF machine: expected EM_X86_64 (62), got {0}")]
    UnsupportedElfMachine(u16),

    #[error("Section out of file bounds: offset {offset} + size {size} > file size {file_size}")]
    SectionOutOfBounds {
        offset: usize,
        size: usize,
        file_size: usize,
    },

    #[error("Memory mapping overlap detected at virtual address {0:#018X}")]
    AddressOverlap(u64),

    #[error("Unknown or corrupted binary format")]
    CorruptedBinary,
}
