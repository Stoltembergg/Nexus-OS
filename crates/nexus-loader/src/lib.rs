//! Nexus OS Binary Loader Engine (PE32+ & ELF64).
//!
//! Provides parsing, validation, segment extraction, address mapping,
//! and NT kernel-mode driver hosting for both Windows NT and Linux 64-bit binaries.

pub mod driver;
pub mod elf;
pub mod error;
pub mod mapper;
pub mod pe;

pub use driver::{LoadedDriver, NtDriverError, NtDriverHost, NtoskrnlTable};
pub use elf::ElfImage;
pub use error::LoaderError;
pub use mapper::{LoadedImage, MappedSegment};
pub use pe::PeImage;

use byteorder::{ByteOrder, LittleEndian};

/// Detects the executable format from raw file bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe32Plus,
    Elf64,
    Unknown,
}

pub fn detect_format(bytes: &[u8]) -> BinaryFormat {
    if bytes.len() >= 4
        && bytes[0..4] == elf::ELF_MAGIC
        && bytes.len() > 5
        && bytes[4] == elf::ELF_CLASS_64
    {
        return BinaryFormat::Elf64;
    }

    if bytes.len() >= 2 && LittleEndian::read_u16(&bytes[0..2]) == pe::IMAGE_DOS_SIGNATURE {
        return BinaryFormat::Pe32Plus;
    }

    BinaryFormat::Unknown
}

/// Automatically detects binary format, parses it, and maps it to virtual segments.
pub fn load_binary(bytes: &[u8]) -> Result<LoadedImage, LoaderError> {
    match detect_format(bytes) {
        BinaryFormat::Pe32Plus => {
            let pe = PeImage::parse(bytes)?;
            LoadedImage::from_pe(&pe, bytes)
        }
        BinaryFormat::Elf64 => {
            let elf = ElfImage::parse(bytes)?;
            LoadedImage::from_elf(&elf, bytes)
        }
        BinaryFormat::Unknown => Err(LoaderError::CorruptedBinary),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_unknown() {
        assert_eq!(detect_format(&[0x00, 0x11, 0x22]), BinaryFormat::Unknown);
    }
}
