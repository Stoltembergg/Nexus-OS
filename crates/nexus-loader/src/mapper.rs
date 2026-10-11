//! Unified virtual memory segment mapper for PE and ELF binaries.

use crate::elf::ElfImage;
use crate::error::LoaderError;
use crate::pe::PeImage;
use nexus_types::{MemoryFlags, ProcessPersonality, VirtualAddress, PAGE_SIZE_4KB};

/// A contiguous chunk of virtual memory allocated to a binary segment.
#[derive(Debug, Clone)]
pub struct MappedSegment {
    pub base_va: VirtualAddress,
    pub size: usize,
    pub flags: MemoryFlags,
    pub data: Vec<u8>,
    pub tag: String,
}

impl MappedSegment {
    pub fn end_va(&self) -> VirtualAddress {
        VirtualAddress::new(self.base_va.as_u64() + self.size as u64)
    }

    pub fn overlaps_with(&self, other: &MappedSegment) -> bool {
        let self_start = self.base_va.as_u64();
        let self_end = self.end_va().as_u64();
        let other_start = other.base_va.as_u64();
        let other_end = other.end_va().as_u64();

        self_start < other_end && other_start < self_end
    }
}

/// A loaded binary ready for execution in the hybrid address space.
#[derive(Debug, Clone)]
pub struct LoadedImage {
    pub personality: ProcessPersonality,
    pub entry_point: VirtualAddress,
    pub segments: Vec<MappedSegment>,
}

impl LoadedImage {
    /// Loads a PE32+ image into virtual segments from raw file bytes.
    pub fn from_pe(pe: &PeImage, raw_bytes: &[u8]) -> Result<Self, LoaderError> {
        pe.validate(raw_bytes)?;
        let mut segments = Vec::new();

        // 1. Headers segment (mapped at image_base)
        let headers_size = (pe.size_of_headers as usize).min(raw_bytes.len());
        let headers_aligned =
            ((headers_size as u64 + PAGE_SIZE_4KB - 1) & !(PAGE_SIZE_4KB - 1)) as usize;
        let mut header_data = vec![0u8; headers_aligned];
        header_data[..headers_size].copy_from_slice(&raw_bytes[..headers_size]);

        segments.push(MappedSegment {
            base_va: VirtualAddress::new(pe.image_base),
            size: headers_aligned,
            flags: MemoryFlags::READ | MemoryFlags::USER,
            data: header_data,
            tag: "PE_HEADERS".to_string(),
        });

        // 2. Map each section
        for sec in &pe.sections {
            let sec_va = VirtualAddress::new(pe.image_base + sec.virtual_address as u64);
            let mem_size = ((sec.virtual_size.max(sec.size_of_raw_data) as u64 + PAGE_SIZE_4KB - 1)
                & !(PAGE_SIZE_4KB - 1)) as usize;
            let mut sec_data = vec![0u8; mem_size];

            let raw_offset = sec.pointer_to_raw_data as usize;
            let raw_size = sec.size_of_raw_data as usize;

            if raw_size > 0 && raw_offset + raw_size <= raw_bytes.len() {
                sec_data[..raw_size].copy_from_slice(&raw_bytes[raw_offset..raw_offset + raw_size]);
            }

            segments.push(MappedSegment {
                base_va: sec_va,
                size: mem_size,
                flags: sec.memory_flags(),
                data: sec_data,
                tag: format!("PE_{}", sec.name),
            });
        }

        let personality = ProcessPersonality::Windows {
            image_base: VirtualAddress::new(pe.image_base),
            entry_point: pe.entry_point_va(),
            subsystem: pe.subsystem,
            teb_address: VirtualAddress::new(0),
            peb_address: VirtualAddress::new(0),
        };

        Ok(Self {
            personality,
            entry_point: pe.entry_point_va(),
            segments,
        })
    }

    /// Loads an ELF64 image into virtual segments from raw file bytes.
    pub fn from_elf(elf: &ElfImage, raw_bytes: &[u8]) -> Result<Self, LoaderError> {
        elf.validate(raw_bytes)?;
        let mut segments = Vec::new();
        let mut min_va = u64::MAX;
        let mut max_va = 0u64;

        for ph in elf.loadable_segments() {
            let seg_va = VirtualAddress::new(ph.p_vaddr);
            let mem_size = ((ph.p_memsz + PAGE_SIZE_4KB - 1) & !(PAGE_SIZE_4KB - 1)) as usize;
            let mut seg_data = vec![0u8; mem_size];

            let file_offset = ph.p_offset as usize;
            let file_size = ph.p_filesz as usize;

            if file_size > 0 && file_offset + file_size <= raw_bytes.len() {
                seg_data[..file_size]
                    .copy_from_slice(&raw_bytes[file_offset..file_offset + file_size]);
            }

            if ph.p_vaddr < min_va {
                min_va = ph.p_vaddr;
            }
            let end = ph.p_vaddr + ph.p_memsz;
            if end > max_va {
                max_va = end;
            }

            segments.push(MappedSegment {
                base_va: seg_va,
                size: mem_size,
                flags: ph.memory_flags(),
                data: seg_data,
                tag: format!("ELF_PT_LOAD_{:#X}", ph.p_vaddr),
            });
        }

        let image_base = if min_va == u64::MAX { 0 } else { min_va };
        let brk_point = VirtualAddress::new((max_va + PAGE_SIZE_4KB - 1) & !(PAGE_SIZE_4KB - 1));

        let personality = ProcessPersonality::Linux {
            image_base: VirtualAddress::new(image_base),
            entry_point: elf.entry_point_va(),
            brk_point,
        };

        Ok(Self {
            personality,
            entry_point: elf.entry_point_va(),
            segments,
        })
    }
}
