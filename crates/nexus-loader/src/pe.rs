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

        // Parse Data Directories (up to 16)
        let num_rva_sizes = if size_of_opt_header >= 112 {
            LittleEndian::read_u32(&bytes[opt_header_offset + 108..opt_header_offset + 112])
                as usize
        } else {
            0
        };

        let mut data_directories = [ImageDataDirectory::default(); 16];
        let num_dirs = num_rva_sizes.min(16);
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

        Ok(Self {
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            subsystem,
            data_directories,
            sections,
        })
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
            if rva >= sec_start && rva < sec_start + sec_len {
                let offset_in_sec = rva - sec_start;
                if offset_in_sec < sec.size_of_raw_data {
                    return Some((sec.pointer_to_raw_data + offset_in_sec) as usize);
                }
            }
        }
        None
    }

    /// Retrieves an ImageDataDirectory by standard directory index.
    pub fn data_directory(&self, index: usize) -> Option<&ImageDataDirectory> {
        self.data_directories.get(index)
    }

    /// Parses the Base Relocation Table from the PE raw bytes.
    pub fn parse_relocations(&self, bytes: &[u8]) -> Result<Vec<PeRelocationBlock>, LoaderError> {
        let dir = match self.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            Some(d) if d.virtual_address != 0 && d.size > 0 => d,
            _ => return Ok(Vec::new()),
        };

        let start_offset = match self.rva_to_file_offset(dir.virtual_address) {
            Some(off) => off,
            None => return Ok(Vec::new()),
        };

        let mut blocks = Vec::new();
        let mut curr_offset = start_offset;
        let end_offset = start_offset + dir.size as usize;

        while curr_offset + 8 <= end_offset && curr_offset + 8 <= bytes.len() {
            let page_rva = LittleEndian::read_u32(&bytes[curr_offset..curr_offset + 4]);
            let block_size =
                LittleEndian::read_u32(&bytes[curr_offset + 4..curr_offset + 8]) as usize;

            if block_size < 8 || curr_offset + block_size > bytes.len() {
                break;
            }

            let num_entries = (block_size - 8) / 2;
            let mut entries = Vec::with_capacity(num_entries);

            for i in 0..num_entries {
                let entry_offset = curr_offset + 8 + (i * 2);
                let entry_val = LittleEndian::read_u16(&bytes[entry_offset..entry_offset + 2]);
                let rel_type = (entry_val >> 12) as u8;
                let offset = entry_val & 0x0FFF;

                entries.push(PeRelocationEntry { rel_type, offset });
            }

            blocks.push(PeRelocationBlock { page_rva, entries });
            curr_offset += block_size;
        }

        Ok(blocks)
    }

    /// Parses the Import Directory and resolves imported functions and DLL names.
    pub fn parse_imports(&self, bytes: &[u8]) -> Result<Vec<PeImportDescriptor>, LoaderError> {
        let dir = match self.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(d) if d.virtual_address != 0 && d.size > 0 => d,
            _ => return Ok(Vec::new()),
        };

        let start_offset = match self.rva_to_file_offset(dir.virtual_address) {
            Some(off) => off,
            None => return Ok(Vec::new()),
        };

        let mut descriptors = Vec::new();
        let mut curr_offset = start_offset;

        while curr_offset + 20 <= bytes.len() {
            let orig_first_thunk = LittleEndian::read_u32(&bytes[curr_offset..curr_offset + 4]);
            let time_date_stamp = LittleEndian::read_u32(&bytes[curr_offset + 4..curr_offset + 8]);
            let forwarder_chain = LittleEndian::read_u32(&bytes[curr_offset + 8..curr_offset + 12]);
            let name_rva = LittleEndian::read_u32(&bytes[curr_offset + 12..curr_offset + 16]);
            let first_thunk = LittleEndian::read_u32(&bytes[curr_offset + 16..curr_offset + 20]);

            // All zeroes signifies termination
            if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            let dll_name = if let Some(name_off) = self.rva_to_file_offset(name_rva) {
                let mut end = name_off;
                while end < bytes.len() && bytes[end] != 0 {
                    end += 1;
                }
                String::from_utf8_lossy(&bytes[name_off..end]).to_string()
            } else {
                String::new()
            };

            // Parse imported functions from ILT (or IAT fallback)
            let thunk_rva = if orig_first_thunk != 0 {
                orig_first_thunk
            } else {
                first_thunk
            };

            let mut functions = Vec::new();
            if let Some(mut thunk_file_off) = self.rva_to_file_offset(thunk_rva) {
                let mut iat_entry_rva = first_thunk;
                while thunk_file_off + 8 <= bytes.len() {
                    let thunk_data =
                        LittleEndian::read_u64(&bytes[thunk_file_off..thunk_file_off + 8]);
                    if thunk_data == 0 {
                        break;
                    }

                    let (ordinal_or_hint, fn_name) = if (thunk_data & (1 << 63)) != 0 {
                        // Import by ordinal
                        (
                            (thunk_data & 0xFFFF) as u16,
                            format!("Ordinal_{}", thunk_data & 0xFFFF),
                        )
                    } else {
                        // Import by name (RVA to Hint/Name table)
                        let hint_name_rva = (thunk_data & 0x7FFF_FFFF) as u32;
                        if let Some(hn_off) = self.rva_to_file_offset(hint_name_rva) {
                            if hn_off + 2 < bytes.len() {
                                let hint = LittleEndian::read_u16(&bytes[hn_off..hn_off + 2]);
                                let mut fn_end = hn_off + 2;
                                while fn_end < bytes.len() && bytes[fn_end] != 0 {
                                    fn_end += 1;
                                }
                                (
                                    hint,
                                    String::from_utf8_lossy(&bytes[hn_off + 2..fn_end]).to_string(),
                                )
                            } else {
                                (0, String::new())
                            }
                        } else {
                            (0, String::new())
                        }
                    };

                    functions.push(PeImportFunction {
                        ordinal_or_hint,
                        name: fn_name,
                        iat_rva: iat_entry_rva,
                    });

                    thunk_file_off += 8;
                    iat_entry_rva += 8;
                }
            }

            descriptors.push(PeImportDescriptor {
                original_first_thunk: orig_first_thunk,
                time_date_stamp,
                forwarder_chain,
                name_rva,
                first_thunk,
                dll_name,
                functions,
            });

            curr_offset += 20;
        }

        Ok(descriptors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_image_parse_dummy() {
        let mut buf = vec![0u8; 1024];
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
