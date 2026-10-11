//! Windows PE32+ (x86_64) Parser and Loader.

use crate::error::LoaderError;
use byteorder::{ByteOrder, LittleEndian};
use nexus_types::{MemoryFlags, VirtualAddress};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x86_64
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B; // PE32+

// Section characteristics
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Directory Indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

// Relocation Types
pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

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
pub struct PeRelocationBlock {
    pub page_rva: u32,
    pub entries: Vec<PeRelocationEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeRelocationEntry {
    pub rel_type: u8,
    pub offset: u16,
}

#[derive(Debug, Clone)]
pub struct PeImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub first_thunk: u32,
    pub dll_name: String,
    pub functions: Vec<PeImportFunction>,
}

#[derive(Debug, Clone)]
pub struct PeImportFunction {
    pub ordinal_or_hint: u16,
    pub name: String,
    pub iat_rva: u32,
}

#[derive(Debug, Clone)]
pub struct PeImage {
    /// `IMAGE_FILE_HEADER.Characteristics` (e.g. `IMAGE_FILE_RELOCS_STRIPPED`).
    pub file_characteristics: u16,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: u16,
    pub data_directories: [ImageDataDirectory; 16],
    pub sections: Vec<PeSection>,
}

impl PeImage {
    /// Parses and validates a PE32+ (x86_64) binary from raw bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoaderError> {
        // 1. Verify DOS Header
        if bytes.len() < 64 {
            return Err(LoaderError::BufferTooSmall {
                expected: 64,
                actual: bytes.len(),
            });
        }

        let dos_magic = LittleEndian::read_u16(&bytes[0..2]);
        if dos_magic != IMAGE_DOS_SIGNATURE {
            return Err(LoaderError::InvalidDosSignature(dos_magic));
        }

        let e_lfanew = LittleEndian::read_u32(&bytes[60..64]) as usize;

        // 2. Verify NT Signature & File Header
        if bytes.len() < e_lfanew + 24 {
            return Err(LoaderError::BufferTooSmall {
                expected: e_lfanew + 24,
                actual: bytes.len(),
            });
        }

        let nt_signature = LittleEndian::read_u32(&bytes[e_lfanew..e_lfanew + 4]);
        if nt_signature != IMAGE_NT_SIGNATURE {
            return Err(LoaderError::InvalidPeSignature(nt_signature));
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
        let file_characteristics =
            LittleEndian::read_u16(&bytes[file_header_offset + 18..file_header_offset + 20]);
        let size_of_opt_header =
            LittleEndian::read_u16(&bytes[file_header_offset + 16..file_header_offset + 18])
                as usize;

        // 3. Verify Optional Header (PE32+ 64-bit)
        let opt_header_offset = file_header_offset + 20;
        if size_of_opt_header < 112
            || size_of_opt_header > bytes.len().saturating_sub(opt_header_offset)
            || num_sections == 0
            || num_sections > 96
        {
            return Err(LoaderError::CorruptedBinary);
        }
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

        // Parse Data Directories (up to 16)
        let num_rva_sizes = if size_of_opt_header >= 112 {
            LittleEndian::read_u32(&bytes[opt_header_offset + 108..opt_header_offset + 112])
                as usize
        } else {
            0
        };

        let mut data_directories = [ImageDataDirectory::default(); 16];
        let num_dirs = num_rva_sizes.min(16);
        if num_rva_sizes > 16 || 112 + num_dirs * 8 > size_of_opt_header {
            return Err(LoaderError::CorruptedBinary);
        }
        let dirs_start = opt_header_offset + 112;

        for (i, dir) in data_directories.iter_mut().enumerate().take(num_dirs) {
            let dir_offset = dirs_start + (i * 8);
            if bytes.len() >= dir_offset + 8 {
                *dir = ImageDataDirectory {
                    virtual_address: LittleEndian::read_u32(&bytes[dir_offset..dir_offset + 4]),
                    size: LittleEndian::read_u32(&bytes[dir_offset + 4..dir_offset + 8]),
                };
            }
        }

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

        let image = Self {
            file_characteristics,
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            subsystem,
            data_directories,
            sections,
        };
        if (image.size_of_headers as usize) < section_table_offset + num_sections * 40 {
            return Err(LoaderError::CorruptedBinary);
        }
        image.validate(bytes)?;
        Ok(image)
    }

    pub fn validate(&self, bytes: &[u8]) -> Result<(), LoaderError> {
        let end = self
            .image_base
            .checked_add(self.size_of_image as u64)
            .ok_or(LoaderError::CorruptedBinary)?;
        if self.image_base == 0
            || !self.image_base.is_multiple_of(4096)
            || end > 0x0000_8000_0000_0000
            || self.size_of_image == 0
            || self.size_of_image > 64 * 1024 * 1024
            || !self.size_of_image.is_multiple_of(4096)
            || self.section_alignment < 4096
            || !self.section_alignment.is_power_of_two()
            || !self.file_alignment.is_power_of_two()
            || self.file_alignment > self.section_alignment
            || self.size_of_headers == 0
            || self.size_of_headers as usize > bytes.len()
            || self.size_of_headers > self.size_of_image
        {
            return Err(LoaderError::CorruptedBinary);
        }
        let headers_end = (self.size_of_headers as u64).div_ceil(4096) * 4096;
        let mut executable_entry = false;
        for (i, sec) in self.sections.iter().enumerate() {
            let size = sec.virtual_size.max(sec.size_of_raw_data) as u64;
            let start = sec.virtual_address as u64;
            let end = start + size;
            let file_end = sec.pointer_to_raw_data as u64 + sec.size_of_raw_data as u64;
            if !start.is_multiple_of(self.section_alignment as u64)
                || start < headers_end
                || end > self.size_of_image as u64
                || file_end > bytes.len() as u64
                || (sec.size_of_raw_data > 0 && sec.pointer_to_raw_data < self.size_of_headers)
            {
                return Err(LoaderError::CorruptedBinary);
            }
            if size == 0 {
                continue;
            }
            for other in &self.sections[..i] {
                let other_size = other.virtual_size.max(other.size_of_raw_data) as u64;
                if other_size != 0
                    && start < (other.virtual_address as u64 + other_size).div_ceil(4096) * 4096
                    && (other.virtual_address as u64) < end.div_ceil(4096) * 4096
                {
                    return Err(LoaderError::AddressOverlap(self.image_base + start));
                }
            }
            executable_entry |= sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                && (start..end).contains(&(self.entry_point_rva as u64));
        }
        if !executable_entry {
            return Err(LoaderError::CorruptedBinary);
        }
        Ok(())
    }

    /// Absolute entry point virtual address based on image base.
    pub fn entry_point_va(&self) -> VirtualAddress {
        VirtualAddress::new(self.image_base + self.entry_point_rva as u64)
    }

    /// Translates a Relative Virtual Address (RVA) to file offset within raw PE buffer.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let sec_start = sec.virtual_address;
            let sec_len = sec.virtual_size.max(sec.size_of_raw_data);
            if rva >= sec_start && (rva as u64) < sec_start as u64 + sec_len as u64 {
                let offset_in_sec = rva - sec_start;
                if offset_in_sec < sec.size_of_raw_data {
                    return Some(sec.pointer_to_raw_data as usize + offset_in_sec as usize);
                }
            }
        }
        (rva < self.size_of_headers).then_some(rva as usize)
    }

    /// Retrieves an ImageDataDirectory by standard directory index.
    pub fn data_directory(&self, index: usize) -> Option<&ImageDataDirectory> {
        self.data_directories.get(index)
    }

    fn rva_bytes<'a>(&self, bytes: &'a [u8], rva: u32) -> Result<&'a [u8], LoaderError> {
        if rva < self.size_of_headers {
            return bytes
                .get(rva as usize..self.size_of_headers as usize)
                .ok_or(LoaderError::CorruptedBinary);
        }
        for section in &self.sections {
            if rva >= section.virtual_address {
                let offset = (rva - section.virtual_address) as usize;
                if offset < section.size_of_raw_data as usize {
                    let start = section.pointer_to_raw_data as usize;
                    let end = start
                        .checked_add(section.size_of_raw_data as usize)
                        .ok_or(LoaderError::CorruptedBinary)?;
                    return bytes
                        .get(start + offset..end)
                        .ok_or(LoaderError::CorruptedBinary);
                }
            }
        }
        Err(LoaderError::CorruptedBinary)
    }
    fn c_string(&self, bytes: &[u8], rva: u32) -> Result<String, LoaderError> {
        let tail = self.rva_bytes(bytes, rva)?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(LoaderError::CorruptedBinary)?;
        if end == 0 || end > 1024 {
            return Err(LoaderError::CorruptedBinary);
        }
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    }
    pub fn parse_relocations(&self, bytes: &[u8]) -> Result<Vec<PeRelocationBlock>, LoaderError> {
        self.validate(bytes)?;
        let dir = self.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if dir.virtual_address == 0 && dir.size == 0 {
            return Ok(Vec::new());
        }
        let data = self
            .rva_bytes(bytes, dir.virtual_address)?
            .get(..dir.size as usize)
            .ok_or(LoaderError::CorruptedBinary)?;
        let mut blocks = Vec::new();
        let mut cursor = 0usize;
        while cursor < data.len() {
            let header = data
                .get(cursor..cursor + 8)
                .ok_or(LoaderError::CorruptedBinary)?;
            let page_rva = LittleEndian::read_u32(&header[..4]);
            let size = LittleEndian::read_u32(&header[4..8]) as usize;
            if size < 8 || !size.is_multiple_of(2) || page_rva % 4096 != 0 {
                return Err(LoaderError::CorruptedBinary);
            }
            let block = data
                .get(
                    cursor
                        ..cursor
                            .checked_add(size)
                            .ok_or(LoaderError::CorruptedBinary)?,
                )
                .ok_or(LoaderError::CorruptedBinary)?;
            let mut entries = Vec::new();
            for word in block[8..].as_chunks::<2>().0 {
                let raw = LittleEndian::read_u16(word);
                let rel_type = (raw >> 12) as u8;
                let offset = raw & 4095;
                let target = page_rva as u64 + offset as u64;
                if !matches!(rel_type, IMAGE_REL_BASED_ABSOLUTE | IMAGE_REL_BASED_DIR64)
                    || (rel_type == IMAGE_REL_BASED_DIR64
                        && !self.sections.iter().any(|s| {
                            target >= s.virtual_address as u64
                                && target + 8
                                    <= s.virtual_address as u64
                                        + s.virtual_size.max(s.size_of_raw_data) as u64
                        }))
                {
                    return Err(LoaderError::CorruptedBinary);
                }
                entries.push(PeRelocationEntry { rel_type, offset });
            }
            blocks.push(PeRelocationBlock { page_rva, entries });
            cursor += size;
        }
        if blocks.is_empty() {
            return Err(LoaderError::CorruptedBinary);
        }
        Ok(blocks)
    }
    pub fn parse_imports(&self, bytes: &[u8]) -> Result<Vec<PeImportDescriptor>, LoaderError> {
        self.validate(bytes)?;
        let dir = self.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if dir.virtual_address == 0 && dir.size == 0 {
            return Ok(Vec::new());
        }
        let data = self
            .rva_bytes(bytes, dir.virtual_address)?
            .get(..dir.size as usize)
            .ok_or(LoaderError::CorruptedBinary)?;
        let mut descriptors = Vec::new();
        for descriptor in data.as_chunks::<20>().0 {
            if descriptor.iter().all(|&b| b == 0) {
                return Ok(descriptors);
            }
            if descriptors.len() >= 96 {
                return Err(LoaderError::CorruptedBinary);
            }
            let orig = LittleEndian::read_u32(&descriptor[..4]);
            let timestamp = LittleEndian::read_u32(&descriptor[4..8]);
            let forwarder = LittleEndian::read_u32(&descriptor[8..12]);
            let name_rva = LittleEndian::read_u32(&descriptor[12..16]);
            let first = LittleEndian::read_u32(&descriptor[16..20]);
            if first == 0 {
                return Err(LoaderError::CorruptedBinary);
            }
            let dll_name = self.c_string(bytes, name_rva)?;
            let thunks = self.rva_bytes(bytes, if orig != 0 { orig } else { first })?;
            let mut functions = Vec::new();
            let mut terminated = false;
            for (index, word) in thunks.as_chunks::<8>().0.iter().enumerate() {
                let thunk = LittleEndian::read_u64(word);
                if thunk == 0 {
                    terminated = true;
                    break;
                }
                if index >= 4096 {
                    return Err(LoaderError::CorruptedBinary);
                }
                let (ordinal_or_hint, name) = if thunk & (1 << 63) != 0 {
                    (
                        (thunk & 0xffff) as u16,
                        format!("Ordinal_{}", thunk & 0xffff),
                    )
                } else {
                    let rva = u32::try_from(thunk).map_err(|_| LoaderError::CorruptedBinary)?;
                    let hint = self
                        .rva_bytes(bytes, rva)?
                        .get(..2)
                        .ok_or(LoaderError::CorruptedBinary)?;
                    (
                        LittleEndian::read_u16(hint),
                        self.c_string(
                            bytes,
                            rva.checked_add(2).ok_or(LoaderError::CorruptedBinary)?,
                        )?,
                    )
                };
                let iat_rva = first
                    .checked_add((index as u32) * 8)
                    .ok_or(LoaderError::CorruptedBinary)?;
                self.rva_bytes(bytes, iat_rva)?
                    .get(..8)
                    .ok_or(LoaderError::CorruptedBinary)?;
                functions.push(PeImportFunction {
                    ordinal_or_hint,
                    name,
                    iat_rva,
                });
            }
            if !terminated {
                return Err(LoaderError::CorruptedBinary);
            }
            descriptors.push(PeImportDescriptor {
                original_first_thunk: orig,
                time_date_stamp: timestamp,
                forwarder_chain: forwarder,
                name_rva,
                first_thunk: first,
                dll_name,
                functions,
            });
        }
        Err(LoaderError::CorruptedBinary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_optional_header_returns_error_without_panicking() {
        let mut bytes = vec![0; 152];
        LittleEndian::write_u16(&mut bytes[0..2], IMAGE_DOS_SIGNATURE);
        LittleEndian::write_u32(&mut bytes[60..64], 128);
        LittleEndian::write_u32(&mut bytes[128..132], IMAGE_NT_SIGNATURE);
        LittleEndian::write_u16(&mut bytes[132..134], IMAGE_FILE_MACHINE_AMD64);
        LittleEndian::write_u16(&mut bytes[148..150], 240);
        let result = std::panic::catch_unwind(|| PeImage::parse(&bytes));
        assert!(result.is_ok(), "untrusted PE must not panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_pe_image_parse_dummy() {
        let mut buf = vec![0u8; 8192];
        LittleEndian::write_u16(&mut buf[0..2], IMAGE_DOS_SIGNATURE);
        LittleEndian::write_u32(&mut buf[60..64], 128); // e_lfanew = 128

        let pe_off = 128;
        LittleEndian::write_u32(&mut buf[pe_off..pe_off + 4], IMAGE_NT_SIGNATURE);
        LittleEndian::write_u16(&mut buf[pe_off + 4..pe_off + 6], IMAGE_FILE_MACHINE_AMD64);
        LittleEndian::write_u16(&mut buf[pe_off + 6..pe_off + 8], 1); // 1 section
        LittleEndian::write_u16(&mut buf[pe_off + 20..pe_off + 22], 240); // SizeOfOptionalHeader = 240

        let opt_off = pe_off + 24;
        LittleEndian::write_u16(
            opt_off_slice(&mut buf, opt_off, 0, 2),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        );
        LittleEndian::write_u32(opt_off_slice(&mut buf, opt_off, 16, 20), 0x1000); // EntryPoint = 0x1000
        LittleEndian::write_u64(opt_off_slice(&mut buf, opt_off, 24, 32), 0x140000000); // ImageBase
        LittleEndian::write_u32(opt_off_slice(&mut buf, opt_off, 32, 36), 4096);
        LittleEndian::write_u32(opt_off_slice(&mut buf, opt_off, 36, 40), 512);
        LittleEndian::write_u32(opt_off_slice(&mut buf, opt_off, 56, 60), 8192);
        LittleEndian::write_u32(opt_off_slice(&mut buf, opt_off, 60, 64), 512);
        LittleEndian::write_u32(opt_off_slice(&mut buf, opt_off, 108, 112), 16); // NumberOfRvaAndSizes

        let sec_off = opt_off + 240;
        buf[sec_off..sec_off + 5].copy_from_slice(b".text");
        LittleEndian::write_u32(&mut buf[sec_off + 8..sec_off + 12], 0x1000); // VirtualSize
        LittleEndian::write_u32(&mut buf[sec_off + 12..sec_off + 16], 0x1000); // VirtualAddress
        LittleEndian::write_u32(&mut buf[sec_off + 16..sec_off + 20], 0x1000); // SizeOfRawData
        LittleEndian::write_u32(&mut buf[sec_off + 20..sec_off + 24], 512); // PointerToRawData
        LittleEndian::write_u32(
            &mut buf[sec_off + 36..sec_off + 40],
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        );

        let pe = PeImage::parse(&buf).expect("Failed to parse dummy PE");
        assert_eq!(pe.image_base, 0x140000000);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.entry_point_va().as_u64(), 0x140001000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
    }

    fn opt_off_slice(buf: &mut [u8], opt_off: usize, start: usize, end: usize) -> &mut [u8] {
        &mut buf[opt_off + start..opt_off + end]
    }
}
