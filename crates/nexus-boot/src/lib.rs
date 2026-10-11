//! Nexus OS UEFI Boot Services Handoff Protocol & Memory Map Descriptors.

pub mod proto;

pub use nexus_types::{
    BootHandoverInfo, FramebufferInfo, MemoryDescriptor, PhysicalAddress, UefiMemoryType,
    VirtualAddress,
};
use proto::EfiMemoryDescriptorRaw;

/// Return the checked byte extent of the UEFI configuration-table array.
pub fn checked_configuration_table_size(
    base: usize,
    count: usize,
) -> Result<usize, proto::EfiStatus> {
    if count > 256 {
        return Err(proto::EfiStatus::INVALID_PARAMETER);
    }
    if count == 0 {
        return Ok(0);
    }
    let stride = core::mem::size_of::<proto::EfiConfigurationTable>();
    if base == 0 || !base.is_multiple_of(core::mem::align_of::<proto::EfiConfigurationTable>()) {
        return Err(proto::EfiStatus::INVALID_PARAMETER);
    }
    let size = count
        .checked_mul(stride)
        .ok_or(proto::EfiStatus::INVALID_PARAMETER)?;
    base.checked_add(size)
        .ok_or(proto::EfiStatus::INVALID_PARAMETER)?;
    Ok(size)
}

/// Select ACPI 2.0's RSDP when advertised; use ACPI 1.0 only if it is absent.
pub fn select_acpi_rsdp(
    entries: &[proto::EfiConfigurationTable],
) -> Result<Option<PhysicalAddress>, proto::EfiStatus> {
    let preferred = entries
        .iter()
        .find(|entry| entry.vendor_guid == proto::EfiGuid::ACPI_20_GUID);
    let selected = preferred.or_else(|| {
        entries
            .iter()
            .find(|entry| entry.vendor_guid == proto::EfiGuid::ACPI_10_GUID)
    });
    match selected {
        None => Ok(None),
        Some(entry) if entry.vendor_table.is_null() => Err(proto::EfiStatus::INVALID_PARAMETER),
        Some(entry) => Ok(Some(PhysicalAddress::new(entry.vendor_table as u64))),
    }
}

/// Validate the memory layout of the actual UEFI-loaded kernel PE, not its raw file offsets.
pub fn decode_kernel_code(
    base: u64,
    image: &[u8],
    info: &mut BootHandoverInfo,
) -> Result<(), proto::EfiStatus> {
    let invalid = proto::EfiStatus::INVALID_PARAMETER;
    let u16_at = |offset: usize| -> Result<u16, proto::EfiStatus> {
        Ok(u16::from_le_bytes(
            image
                .get(offset..offset + 2)
                .ok_or(invalid)?
                .try_into()
                .unwrap(),
        ))
    };
    let u32_at = |offset: usize| -> Result<u32, proto::EfiStatus> {
        Ok(u32::from_le_bytes(
            image
                .get(offset..offset + 4)
                .ok_or(invalid)?
                .try_into()
                .unwrap(),
        ))
    };
    if base & 4095 != 0 || image.len() > 64 * 1024 * 1024 || u16_at(0)? != 0x5a4d {
        return Err(invalid);
    }
    let nt = u32_at(60)? as usize;
    if u32_at(nt)? != 0x4550 || u16_at(nt + 4)? != 0x8664 {
        return Err(invalid);
    }
    let count = u16_at(nt + 6)? as usize;
    let optional = u16_at(nt + 20)? as usize;
    if count == 0 || count > 96 || optional < 112 || u16_at(nt + 24)? != 0x20b {
        return Err(invalid);
    }
    let mut ranges = [(0, 0); 16];
    let mut range_count = 0;
    for index in 0..count {
        let section = nt + 24 + optional + index * 40;
        image.get(section..section + 40).ok_or(invalid)?;
        let flags = u32_at(section + 36)?;
        if flags & 0x20000000 == 0 {
            continue;
        }
        if flags & 0x80000000 != 0 || range_count == ranges.len() {
            return Err(invalid);
        }
        let offset = u32_at(section + 12)? as u64;
        let size = u32_at(section + 8)? as u64;
        if size == 0
            || offset & 4095 != 0
            || offset
                .checked_add(size)
                .is_none_or(|end| end > image.len() as u64)
        {
            return Err(invalid);
        }
        let start = base.checked_add(offset).ok_or(invalid)?;
        let length = size.div_ceil(4096) * 4096;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > image.len() as u64)
        {
            return Err(invalid);
        }
        start.checked_add(length).ok_or(invalid)?;
        // A data section sharing a rounded code page would silently become RX.
        // Reject ambiguous layouts instead of changing writable data permissions.
        for other in 0..count {
            if other == index {
                continue;
            }
            let header = nt + 24 + optional + other * 40;
            image.get(header..header + 40).ok_or(invalid)?;
            let other_offset = u32_at(header + 12)? as u64;
            let other_size = u32_at(header + 8)? as u64;
            let other_end = other_offset.checked_add(other_size).ok_or(invalid)?;
            if other_size != 0 && other_offset < offset + length && other_end > offset {
                return Err(invalid);
            }
        }
        ranges[range_count] = (start, length);
        range_count += 1;
    }
    if range_count == 0 {
        return Err(invalid);
    }
    info.kernel_code = ranges;
    info.kernel_code_len = range_count;
    Ok(())
}

/// Decode firmware descriptors without assuming byte-buffer alignment or truncating the map.
pub fn decode_memory_map(
    bytes: &[u8],
    stride: usize,
    version: u32,
    info: &mut BootHandoverInfo,
) -> Result<(), proto::EfiStatus> {
    if version != 1
        || stride < core::mem::size_of::<EfiMemoryDescriptorRaw>()
        || !stride.is_multiple_of(8)
        || !bytes.len().is_multiple_of(stride)
        || bytes.is_empty()
        || bytes.len() / stride > info.memory_map.len()
    {
        return Err(proto::EfiStatus::INVALID_PARAMETER);
    }
    info.memory_map_len = 0;
    for descriptor in bytes.chunks_exact(stride) {
        let raw = unsafe {
            core::ptr::read_unaligned(descriptor.as_ptr().cast::<EfiMemoryDescriptorRaw>())
        };
        let end = raw
            .number_of_pages
            .checked_mul(4096)
            .and_then(|size| raw.physical_start.checked_add(size))
            .ok_or(proto::EfiStatus::INVALID_PARAMETER)?;
        if raw.physical_start % 4096 != 0 || end > (1u64 << 52) {
            return Err(proto::EfiStatus::INVALID_PARAMETER);
        }
        if !info.push_descriptor(MemoryDescriptor::from(raw)) {
            return Err(proto::EfiStatus::BUFFER_TOO_SMALL);
        }
    }
    Ok(())
}

impl From<EfiMemoryDescriptorRaw> for MemoryDescriptor {
    fn from(raw: EfiMemoryDescriptorRaw) -> Self {
        Self {
            mem_type: UefiMemoryType::from(raw.mem_type),
            phys_start: PhysicalAddress::new(raw.physical_start),
            virt_start: VirtualAddress::new(raw.virtual_start),
            number_of_pages: raw.number_of_pages,
            attribute: raw.attribute,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;

    fn acpi10(address: usize) -> proto::EfiConfigurationTable {
        proto::EfiConfigurationTable {
            vendor_guid: proto::EfiGuid::ACPI_10_GUID,
            vendor_table: address as *const c_void,
        }
    }
    fn acpi20(address: usize) -> proto::EfiConfigurationTable {
        proto::EfiConfigurationTable {
            vendor_guid: proto::EfiGuid::ACPI_20_GUID,
            vendor_table: address as *const c_void,
        }
    }

    #[test]
    fn selects_acpi_rsdp_preference_fallback_and_absence() {
        assert_eq!(checked_configuration_table_size(0, 0).unwrap(), 0);
        assert_eq!(
            select_acpi_rsdp(&[acpi10(0x1000), acpi20(0x2000)]).unwrap(),
            Some(PhysicalAddress::new(0x2000))
        );
        assert_eq!(
            select_acpi_rsdp(&[acpi10(0x1000)]).unwrap(),
            Some(PhysicalAddress::new(0x1000))
        );
        assert_eq!(select_acpi_rsdp(&[]).unwrap(), None);
        assert!(select_acpi_rsdp(&[acpi20(0)]).is_err());
    }

    #[test]
    fn rejects_invalid_configuration_table_extents() {
        assert!(checked_configuration_table_size(0, 1).is_err());
        assert!(checked_configuration_table_size(0x1000, 257).is_err());
        assert!(checked_configuration_table_size(0x1001, 1).is_err());
        assert!(checked_configuration_table_size(
            usize::MAX - (core::mem::size_of::<proto::EfiConfigurationTable>() - 1),
            1
        )
        .is_err());
    }

    fn loaded_pe() -> Vec<u8> {
        let mut image = vec![0; 0x4000];
        image[..2].copy_from_slice(&0x5a4du16.to_le_bytes());
        image[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&112u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        let section = 0x108;
        image[section + 8..section + 12].copy_from_slice(&0x1001u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x60000000u32.to_le_bytes());
        image[section + 48..section + 52].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 52..section + 56].copy_from_slice(&0x3000u32.to_le_bytes());
        image[section + 76..section + 80].copy_from_slice(&0xc0000000u32.to_le_bytes());
        image
    }
    #[test]
    fn loaded_kernel_pe_extracts_rounded_rx_ranges() {
        let mut info = BootHandoverInfo::new();
        decode_kernel_code(0x100000, &loaded_pe(), &mut info).unwrap();
        assert_eq!(info.kernel_code_len, 1);
        assert_eq!(info.kernel_code[0], (0x101000, 0x2000));
    }
    #[test]
    fn loaded_kernel_pe_rejects_truncation_overflow_wx_and_overlap_transactionally() {
        let image = loaded_pe();
        let mut info = BootHandoverInfo::new();
        decode_kernel_code(0x100000, &image, &mut info).unwrap();
        for length in 0..0x158 {
            assert!(decode_kernel_code(0x100000, &image[..length], &mut info).is_err());
        }
        for base in [1, !4095u64] {
            assert!(decode_kernel_code(base, &image, &mut info).is_err());
        }
        for (offset, value) in [
            (0x12c, 0xe0000000u32), // W+X
            (0x114, 0x1001),        // unaligned code RVA
            (0x110, 0),             // empty code
            (0x110, 0x4000),        // beyond loaded image
            (0x13c, 0x2000),        // writable section overlaps rounded code
            (0x12c, 0x40000000),    // no executable sections
        ] {
            let mut bad = image.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(decode_kernel_code(0x100000, &bad, &mut info).is_err());
            assert_eq!(info.kernel_code_len, 1);
            assert_eq!(info.kernel_code[0], (0x101000, 0x2000));
        }
    }
    #[test]
    fn firmware_map_rejects_bad_stride_version_overflow_and_capacity() {
        let mut info = BootHandoverInfo::new();
        for (stride, version, len) in [(0, 1, 40), (8, 1, 40), (40, 2, 40), (40, 1, 41), (40, 1, 0)]
        {
            assert!(decode_memory_map(&vec![0; len], stride, version, &mut info).is_err());
        }
        assert!(
            decode_memory_map(&vec![0; 40 * (info.memory_map.len() + 1)], 40, 1, &mut info)
                .is_err()
        );
        let mut raw = vec![0; 40];
        raw[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_memory_map(&raw, 40, 1, &mut info).is_err());
    }
    #[test]
    fn unaligned_extended_firmware_descriptor_is_decoded_exactly() {
        let mut bytes = [0; 49];
        bytes[1..5].copy_from_slice(&7u32.to_le_bytes());
        bytes[9..17].copy_from_slice(&0x100000u64.to_le_bytes());
        bytes[25..33].copy_from_slice(&5u64.to_le_bytes());
        let mut info = BootHandoverInfo::new();
        decode_memory_map(&bytes[1..], 48, 1, &mut info).unwrap();
        assert_eq!(info.memory_map_len, 1);
        assert_eq!(info.memory_map()[0].number_of_pages, 5);
        assert_eq!(info.memory_map()[0].phys_start.as_u64(), 0x100000);
    }
}
