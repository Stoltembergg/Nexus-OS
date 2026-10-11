//! Linux ELF64 (x86_64) Parser and Loader.

use crate::error::LoaderError;
use byteorder::{ByteOrder, LittleEndian};
use nexus_types::{MemoryFlags, VirtualAddress};

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_DATA_2LSB: u8 = 1; // Little-endian
pub const EM_X86_64: u16 = 62; // 0x3E

// Segment Types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;

// Segment Flags
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

#[derive(Debug, Clone)]
pub struct ElfProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        LittleEndian::write_u16(&mut bytes[16..18], 2);
        LittleEndian::write_u16(&mut bytes[18..20], EM_X86_64);
        LittleEndian::write_u32(&mut bytes[20..24], 1);
        LittleEndian::write_u64(&mut bytes[24..32], 0x401000);
        LittleEndian::write_u64(&mut bytes[32..40], 64);
        LittleEndian::write_u16(&mut bytes[52..54], 64);
        LittleEndian::write_u16(&mut bytes[54..56], 56);
        LittleEndian::write_u16(&mut bytes[56..58], 1);
        LittleEndian::write_u32(&mut bytes[64..68], PT_LOAD);
        LittleEndian::write_u32(&mut bytes[68..72], PF_R | PF_X);
        LittleEndian::write_u64(&mut bytes[72..80], 0);
        LittleEndian::write_u64(&mut bytes[80..88], 0x401000);
        LittleEndian::write_u64(&mut bytes[96..104], 4096);
        LittleEndian::write_u64(&mut bytes[104..112], 4096);
        LittleEndian::write_u64(&mut bytes[112..120], 4096);
        bytes
    }

    #[test]
    fn program_header_offset_overflow_is_rejected_without_panic() {
        let mut bytes = image();
        LittleEndian::write_u64(&mut bytes[32..40], u64::MAX - 7);
        let result = std::panic::catch_unwind(|| ElfImage::parse(&bytes));
        assert!(result.is_ok(), "untrusted ELF must not panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn rejects_truncated_segments_filesz_exceeding_memsz_and_bad_entry() {
        for field in [72, 96, 104, 24] {
            let mut bytes = image();
            LittleEndian::write_u64(
                &mut bytes[field..field + 8],
                if field == 104 { 1 } else { u64::MAX - 4095 },
            );
            assert!(
                ElfImage::parse(&bytes).is_err(),
                "accepted bad field {field}"
            );
        }
    }

    #[test]
    fn rejects_invalid_program_header_size_alignment_and_overlaps() {
        let mut bytes = image();
        LittleEndian::write_u16(&mut bytes[54..56], 0);
        assert!(ElfImage::parse(&bytes).is_err());
        let mut bytes = image();
        LittleEndian::write_u64(&mut bytes[112..120], 3);
        assert!(ElfImage::parse(&bytes).is_err());
        let mut bytes = image();
        LittleEndian::write_u16(&mut bytes[56..58], 2);
        let ph = bytes[64..120].to_vec();
        bytes[120..176].copy_from_slice(&ph);
        assert!(ElfImage::parse(&bytes).is_err());
    }
}

impl ElfProgramHeader {
    pub fn memory_flags(&self) -> MemoryFlags {
        let mut flags = MemoryFlags::USER;
        if (self.p_flags & PF_R) != 0 {
            flags |= MemoryFlags::READ;
        }
        if (self.p_flags & PF_W) != 0 {
            flags |= MemoryFlags::WRITE;
        }
        if (self.p_flags & PF_X) != 0 {
            flags |= MemoryFlags::EXECUTE;
        }
        flags
    }
}

#[derive(Debug, Clone)]
pub struct ElfImage {
    pub entry_point: u64,
    pub elf_type: u16,
    pub program_headers: Vec<ElfProgramHeader>,
}

impl ElfImage {
    /// Parses a raw ELF64 byte buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoaderError> {
        if bytes.len() < 64 {
            return Err(LoaderError::BufferTooSmall {
                expected: 64,
                actual: bytes.len(),
            });
        }

        // 1. Verify Magic
        if bytes[0..4] != ELF_MAGIC {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&bytes[0..4]);
            return Err(LoaderError::InvalidElfMagic(magic));
        }

        // 2. Class and Endianness
        if bytes[4] != ELF_CLASS_64 {
            return Err(LoaderError::UnsupportedElfClass(bytes[4]));
        }
        if bytes[5] != ELF_DATA_2LSB {
            return Err(LoaderError::UnsupportedElfEndian(bytes[5]));
        }

        // 3. Header fields
        let elf_type = LittleEndian::read_u16(&bytes[16..18]);
        let machine = LittleEndian::read_u16(&bytes[18..20]);
        if machine != EM_X86_64 {
            return Err(LoaderError::UnsupportedElfMachine(machine));
        }

        let entry_point = LittleEndian::read_u64(&bytes[24..32]);
        let phoff = LittleEndian::read_u64(&bytes[32..40]) as usize;
        let phentsize = LittleEndian::read_u16(&bytes[54..56]) as usize;
        let phnum = LittleEndian::read_u16(&bytes[56..58]) as usize;

        if bytes[6] != 1
            || LittleEndian::read_u32(&bytes[20..24]) != 1
            || LittleEndian::read_u16(&bytes[52..54]) != 64
            || !matches!(elf_type, 2 | 3)
            || phentsize != 56
            || phnum == 0
            || phnum > 128
        {
            return Err(LoaderError::CorruptedBinary);
        }
        let table_end = phoff
            .checked_add(
                phnum
                    .checked_mul(phentsize)
                    .ok_or(LoaderError::CorruptedBinary)?,
            )
            .ok_or(LoaderError::CorruptedBinary)?;
        if phoff < 64 || table_end > bytes.len() {
            return Err(LoaderError::CorruptedBinary);
        }

        // 4. Parse Program Headers
        let mut program_headers = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let offset = phoff + (i * phentsize);
            if bytes.len() < offset + 56 {
                return Err(LoaderError::BufferTooSmall {
                    expected: offset + 56,
                    actual: bytes.len(),
                });
            }

            let p_type = LittleEndian::read_u32(&bytes[offset..offset + 4]);
            let p_flags = LittleEndian::read_u32(&bytes[offset + 4..offset + 8]);
            let p_offset = LittleEndian::read_u64(&bytes[offset + 8..offset + 16]);
            let p_vaddr = LittleEndian::read_u64(&bytes[offset + 16..offset + 24]);
            let p_paddr = LittleEndian::read_u64(&bytes[offset + 24..offset + 32]);
            let p_filesz = LittleEndian::read_u64(&bytes[offset + 32..offset + 40]);
            let p_memsz = LittleEndian::read_u64(&bytes[offset + 40..offset + 48]);
            let p_align = LittleEndian::read_u64(&bytes[offset + 48..offset + 56]);

            program_headers.push(ElfProgramHeader {
                p_type,
                p_flags,
                p_offset,
                p_vaddr,
                p_paddr,
                p_filesz,
                p_memsz,
                p_align,
            });
        }

        let image = Self {
            entry_point,
            elf_type,
            program_headers,
        };
        image.validate(bytes)?;
        Ok(image)
    }

    /// Checks loader invariants even for callers constructing an image directly.
    pub fn validate(&self, bytes: &[u8]) -> Result<(), LoaderError> {
        let mut total = 0u64;
        let mut executable_entry = false;
        for (i, ph) in self
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.p_type == PT_LOAD)
        {
            let file_end = ph
                .p_offset
                .checked_add(ph.p_filesz)
                .ok_or(LoaderError::CorruptedBinary)?;
            let end = ph
                .p_vaddr
                .checked_add(ph.p_memsz)
                .ok_or(LoaderError::CorruptedBinary)?;
            if ph.p_filesz > ph.p_memsz
                || file_end > bytes.len() as u64
                || ph.p_vaddr == 0
                || end > 0x0000_8000_0000_0000
                || ph.p_memsz > 64 * 1024 * 1024
                || ph.p_flags & !7 != 0
                || (ph.p_align > 1
                    && (!ph.p_align.is_power_of_two()
                        || ph.p_vaddr % ph.p_align != ph.p_offset % ph.p_align))
            {
                return Err(LoaderError::CorruptedBinary);
            }
            total = total
                .checked_add(ph.p_memsz)
                .ok_or(LoaderError::CorruptedBinary)?;
            if total > 64 * 1024 * 1024 {
                return Err(LoaderError::CorruptedBinary);
            }
            if ph.p_memsz != 0 {
                for other in self.program_headers[..i]
                    .iter()
                    .filter(|p| p.p_type == PT_LOAD && p.p_memsz != 0)
                {
                    let other_end = other
                        .p_vaddr
                        .checked_add(other.p_memsz)
                        .ok_or(LoaderError::CorruptedBinary)?;
                    if (ph.p_vaddr & !4095) < other_end.div_ceil(4096) * 4096
                        && (other.p_vaddr & !4095) < end.div_ceil(4096) * 4096
                    {
                        return Err(LoaderError::AddressOverlap(ph.p_vaddr));
                    }
                }
                executable_entry |=
                    ph.p_flags & PF_X != 0 && (ph.p_vaddr..end).contains(&self.entry_point);
            }
        }
        if !executable_entry {
            return Err(LoaderError::CorruptedBinary);
        }
        Ok(())
    }

    pub fn entry_point_va(&self) -> VirtualAddress {
        VirtualAddress::new(self.entry_point)
    }

    pub fn loadable_segments(&self) -> impl Iterator<Item = &ElfProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
    }
}
