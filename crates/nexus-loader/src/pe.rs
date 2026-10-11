//! Windows PE32+ (x86_64) Parser and Loader.

use crate::error::LoaderError;
use byteorder::{ByteOrder, LittleEndian};
use nexus_types::{MemoryFlags, VirtualAddress};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x86_64
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B; // PE32+

// Section characteristics
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl PeSection {
    pub fn memory_flags(&self) -> MemoryFlags {
        let mut flags = MemoryFlags::USER;
        if (self.characteristics & IMAGE_SCN_MEM_READ) != 0 {
            flags |= MemoryFlags::READ;
        }
        if (self.characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
            flags |= MemoryFlags::WRITE;
        }
        if (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {
            flags |= MemoryFlags::EXECUTE;
        }
        flags
    }
}

#[derive(Debug, Clone)]
pub struct PeImage {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: u16,
    pub sections: Vec<PeSection>,
}

impl PeImage {
    /// Parses a raw PE32+ byte buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoaderError> {
        if bytes.len() < 64 {
            return Err(LoaderError::BufferTooSmall {
                expected: 64,
                actual: bytes.len(),
            });
        }

        // 1. Verify DOS Header
        let dos_magic = LittleEndian::read_u16(&bytes[0..2]);
        if dos_magic != IMAGE_DOS_SIGNATURE {
            return Err(LoaderError::InvalidDosSignature(dos_magic));
        }

        let e_lfanew = LittleEndian::read_u32(&bytes[60..64]) as usize;
        if bytes.len() < e_lfanew + 264 {
            return Err(LoaderError::BufferTooSmall {
                expected: e_lfanew + 264,
                actual: bytes.len(),
            });
        }

        // 2. Verify PE Signature
        let pe_sig = LittleEndian::read_u32(&bytes[e_lfanew..e_lfanew + 4]);
        if pe_sig != IMAGE_NT_SIGNATURE {
            return Err(LoaderError::InvalidPeSignature(pe_sig));
        }

        let file_header_offset = e_lfanew + 4;
        let machine = LittleEndian::read_u16(&bytes[file_header_offset..file_header_offset + 2]);
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(LoaderError::UnsupportedMachine {
                expected: IMAGE_FILE_MACHINE_AMD64,
                actual: machine,
            });
        }

        let num_sections =
            LittleEndian::read_u16(&bytes[file_header_offset + 2..file_header_offset + 4]) as usize;
        let size_of_opt_header =
            LittleEndian::read_u16(&bytes[file_header_offset + 16..file_header_offset + 18])
                as usize;

        // 3. Verify Optional Header (PE32+ 64-bit)
        let opt_header_offset = file_header_offset + 20;
        let opt_magic = LittleEndian::read_u16(&bytes[opt_header_offset..opt_header_offset + 2]);
        if opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(LoaderError::InvalidPeMagic(opt_magic));
        }

        let entry_point_rva =
            LittleEndian::read_u32(&bytes[opt_header_offset + 16..opt_header_offset + 20]);
        let image_base =
            LittleEndian::read_u64(&bytes[opt_header_offset + 24..opt_header_offset + 32]);
        let section_alignment =
            LittleEndian::read_u32(&bytes[opt_header_offset + 32..opt_header_offset + 36]);
        let file_alignment =
            LittleEndian::read_u32(&bytes[opt_header_offset + 36..opt_header_offset + 40]);
        let size_of_image =
            LittleEndian::read_u32(&bytes[opt_header_offset + 56..opt_header_offset + 60]);
        let size_of_headers =
            LittleEndian::read_u32(&bytes[opt_header_offset + 60..opt_header_offset + 64]);
        let subsystem =
            LittleEndian::read_u16(&bytes[opt_header_offset + 68..opt_header_offset + 70]);

        // 4. Parse Sections
        let section_table_offset = opt_header_offset + size_of_opt_header;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let offset = section_table_offset + (i * 40);
            if bytes.len() < offset + 40 {
                return Err(LoaderError::BufferTooSmall {
                    expected: offset + 40,
                    actual: bytes.len(),
                });
            }

            let name_bytes = &bytes[offset..offset + 8];
            let name_end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

            let virtual_size = LittleEndian::read_u32(&bytes[offset + 8..offset + 12]);
            let virtual_address = LittleEndian::read_u32(&bytes[offset + 12..offset + 16]);
            let size_of_raw_data = LittleEndian::read_u32(&bytes[offset + 16..offset + 20]);
            let pointer_to_raw_data = LittleEndian::read_u32(&bytes[offset + 20..offset + 24]);
            let characteristics = LittleEndian::read_u32(&bytes[offset + 36..offset + 40]);

            sections.push(PeSection {
                name,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                characteristics,
            });
        }

        Ok(Self {
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            subsystem,
            sections,
        })
    }

    /// Absolute entry point virtual address based on image base.
    pub fn entry_point_va(&self) -> VirtualAddress {
        VirtualAddress::new(self.image_base + self.entry_point_rva as u64)
    }
}
