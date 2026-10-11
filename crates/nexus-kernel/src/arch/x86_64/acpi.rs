#![cfg_attr(
    not(any(target_os = "uefi", target_os = "none", test)),
    allow(dead_code)
)]

#[cfg(test)]
use core::ops::Range;
#[cfg(any(target_os = "uefi", target_os = "none"))]
use nexus_types::{BootHandoverInfo, UefiMemoryType, VirtualAddress};

const MAX_SDT: usize = 1024 * 1024;
const MAX_RSDP: usize = 4096;
const FOUR_GIB: u64 = 1 << 32;
const MAX_PHYSICAL_ADDRESS: u64 = 1 << 52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcpiError {
    PhysicalRange,
    Signature,
    Checksum,
    Length,
    Entry,
    Capacity,
    MissingMadt,
}

pub(crate) trait AcpiPhysicalReader {
    fn read_phys(&self, address: u64, length: usize) -> Result<&[u8], AcpiError>;
}

#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub(crate) struct Processor {
    pub apic_id: u32,
    pub firmware_uid: u32,
    pub enabled: bool,
    pub online_capable: bool,
    pub x2apic: bool,
}
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub(crate) struct IoApic {
    pub id: u8,
    pub address: u64,
    pub gsi_base: u32,
}
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub(crate) struct SourceOverride {
    pub bus: u8,
    pub source_irq: u8,
    pub gsi: u32,
    pub polarity: u8,
    pub trigger: u8,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct AcpiInventory {
    pub revision: u8,
    pub rsdt_address: u64,
    pub xsdt_address: u64,
    pub madt_address: u64,
    pub lapic_address: u64,
    pub processors: [Processor; 256],
    pub processor_count: usize,
    pub io_apics: [IoApic; 16],
    pub io_apic_count: usize,
    pub overrides: [SourceOverride; 256],
    pub override_count: usize,
}

fn u16at(b: &[u8], i: usize) -> Result<u16, AcpiError> {
    Ok(u16::from_le_bytes(
        b.get(i..i.checked_add(2).ok_or(AcpiError::Length)?)
            .ok_or(AcpiError::Length)?
            .try_into()
            .unwrap(),
    ))
}
fn u32at(b: &[u8], i: usize) -> Result<u32, AcpiError> {
    Ok(u32::from_le_bytes(
        b.get(i..i.checked_add(4).ok_or(AcpiError::Length)?)
            .ok_or(AcpiError::Length)?
            .try_into()
            .unwrap(),
    ))
}
fn u64at(b: &[u8], i: usize) -> Result<u64, AcpiError> {
    Ok(u64::from_le_bytes(
        b.get(i..i.checked_add(8).ok_or(AcpiError::Length)?)
            .ok_or(AcpiError::Length)?
            .try_into()
            .unwrap(),
    ))
}
fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}
fn read_sdt<R: AcpiPhysicalReader>(
    r: &R,
    address: u64,
) -> Result<(&'static str, Vec<u8>), AcpiError> {
    let header = r.read_phys(address, 36)?;
    let sig = match header.get(..4) {
        Some(b"RSDT") => "RSDT",
        Some(b"XSDT") => "XSDT",
        Some(b"APIC") => "APIC",
        _ => return Err(AcpiError::Signature),
    };
    let length = u32at(header, 4)? as usize;
    if !(36..=MAX_SDT).contains(&length) || address.checked_add(length as u64).is_none() {
        return Err(AcpiError::Length);
    }
    let bytes = r.read_phys(address, length)?.to_vec();
    if !checksum(&bytes) {
        return Err(AcpiError::Checksum);
    }
    Ok((sig, bytes))
}

pub(crate) fn parse_inventory<R: AcpiPhysicalReader>(
    reader: &R,
    rsdp_address: u64,
) -> Result<AcpiInventory, AcpiError> {
    let prefix = reader.read_phys(rsdp_address, 20)?;
    if prefix.get(..8) != Some(b"RSD PTR ") {
        return Err(AcpiError::Signature);
    }
    if !checksum(prefix) {
        return Err(AcpiError::Checksum);
    }
    let revision = prefix[15];
    let rsdt = u32at(prefix, 16)? as u64;
    let mut xsdt = 0;
    if revision >= 2 {
        let len_bytes = reader.read_phys(rsdp_address, 24)?;
        let length = u32at(len_bytes, 20)? as usize;
        if !(36..=MAX_RSDP).contains(&length) {
            return Err(AcpiError::Length);
        }
        rsdp_address
            .checked_add(length as u64)
            .ok_or(AcpiError::PhysicalRange)?;
        let full = reader.read_phys(rsdp_address, length)?;
        if !checksum(full) {
            return Err(AcpiError::Checksum);
        }
        xsdt = u64at(full, 24)?;
    }
    let (root_address, width, wanted) = if xsdt != 0 {
        (xsdt, 8, "XSDT")
    } else {
        (rsdt, 4, "RSDT")
    };
    if root_address == 0 {
        return Err(AcpiError::MissingMadt);
    }
    let (root_sig, root) = read_sdt(reader, root_address)?;
    if root_sig != wanted {
        return Err(AcpiError::Signature);
    }
    if !(root.len() - 36).is_multiple_of(width) {
        return Err(AcpiError::Entry);
    }
    let mut found: Option<(u64, Vec<u8>)> = None;
    for entry in root[36..].chunks_exact(width) {
        let address = if width == 8 {
            u64::from_le_bytes(entry.try_into().unwrap())
        } else {
            u32::from_le_bytes(entry.try_into().unwrap()) as u64
        };
        if address == 0 {
            return Err(AcpiError::PhysicalRange);
        }
        // Validate every candidate table before probing its signature.
        let candidate_header = reader.read_phys(address, 36)?;
        if candidate_header.get(..4) == Some(b"APIC") {
            if found.is_some() {
                return Err(AcpiError::Entry);
            }
            let (sig, bytes) = read_sdt(reader, address)?;
            if sig == "APIC" {
                found = Some((address, bytes));
            }
        }
    }
    let (madt_address, madt) = found.ok_or(AcpiError::MissingMadt)?;
    if madt.len() < 44 {
        return Err(AcpiError::Length);
    }
    if u32at(&madt, 40)? & !1 != 0 {
        return Err(AcpiError::Entry);
    }
    let mut inventory = AcpiInventory {
        revision,
        rsdt_address: rsdt,
        xsdt_address: xsdt,
        madt_address,
        lapic_address: u32at(&madt, 36)? as u64,
        processors: [Processor::default(); 256],
        processor_count: 0,
        io_apics: [IoApic::default(); 16],
        io_apic_count: 0,
        overrides: [SourceOverride::default(); 256],
        override_count: 0,
    };
    if inventory.lapic_address == 0
        || inventory.lapic_address >= FOUR_GIB
        || inventory.lapic_address & 0xfff != 0
    {
        return Err(AcpiError::Entry);
    }
    let mut cursor = 44usize;
    let mut lapic_override = false;
    while cursor < madt.len() {
        let prefix = madt
            .get(cursor..cursor.checked_add(2).ok_or(AcpiError::Entry)?)
            .ok_or(AcpiError::Entry)?;
        let typ = prefix[0];
        let len = prefix[1] as usize;
        if len < 2 || len > madt.len() - cursor {
            return Err(AcpiError::Entry);
        }
        let e = &madt[cursor..cursor + len];
        let minimum = match typ {
            0 => 8,
            1 => 12,
            2 => 10,
            5 => 12,
            9 => 16,
            _ => 2,
        };
        if len < minimum {
            return Err(AcpiError::Entry);
        }
        match typ {
            0 => {
                let flags = u32at(e, 4)?;
                if flags & !3 != 0 {
                    return Err(AcpiError::Entry);
                }
                let id = e[3] as u32;
                add_processor(
                    &mut inventory,
                    Processor {
                        apic_id: id,
                        firmware_uid: e[2] as u32,
                        enabled: flags & 1 != 0,
                        online_capable: flags & 2 != 0,
                        x2apic: false,
                    },
                )?;
            }
            1 => {
                if e[3] != 0 || inventory.io_apic_count == 16 {
                    return Err(if inventory.io_apic_count == 16 {
                        AcpiError::Capacity
                    } else {
                        AcpiError::Entry
                    });
                }
                let addr = u32at(e, 4)? as u64;
                if addr == 0 || addr >= FOUR_GIB || addr & 0xfff != 0 {
                    return Err(AcpiError::Entry);
                }
                inventory.io_apics[inventory.io_apic_count] = IoApic {
                    id: e[2],
                    address: addr,
                    gsi_base: u32at(e, 8)?,
                };
                inventory.io_apic_count += 1;
            }
            2 => {
                let flags = u16at(e, 8)?;
                let pol = flags & 3;
                let trig = (flags >> 2) & 3;
                if flags & !0xf != 0 || pol == 2 || trig == 2 {
                    return Err(AcpiError::Entry);
                }
                if inventory.overrides[..inventory.override_count]
                    .iter()
                    .any(|o| o.bus == e[2] && o.source_irq == e[3])
                {
                    return Err(AcpiError::Entry);
                }
                if inventory.override_count == 256 {
                    return Err(AcpiError::Capacity);
                }
                inventory.overrides[inventory.override_count] = SourceOverride {
                    bus: e[2],
                    source_irq: e[3],
                    gsi: u32at(e, 4)?,
                    polarity: pol as u8,
                    trigger: trig as u8,
                };
                inventory.override_count += 1;
            }
            5 => {
                if e[2] != 0 || e[3] != 0 || lapic_override {
                    return Err(AcpiError::Entry);
                }
                lapic_override = true;
                let addr = u64at(e, 4)?;
                if addr == 0 || addr >= MAX_PHYSICAL_ADDRESS || addr & 0xfff != 0 {
                    return Err(AcpiError::Entry);
                }
                inventory.lapic_address = addr;
            }
            9 => {
                if u16at(e, 2)? != 0 {
                    return Err(AcpiError::Entry);
                }
                let flags = u32at(e, 8)?;
                if flags & !3 != 0 {
                    return Err(AcpiError::Entry);
                }
                add_processor(
                    &mut inventory,
                    Processor {
                        apic_id: u32at(e, 4)?,
                        firmware_uid: u32at(e, 12)?,
                        enabled: flags & 1 != 0,
                        online_capable: flags & 2 != 0,
                        x2apic: true,
                    },
                )?;
            }
            _ => {}
        }
        cursor = cursor.checked_add(len).ok_or(AcpiError::Entry)?;
    }
    Ok(inventory)
}
fn add_processor(inv: &mut AcpiInventory, p: Processor) -> Result<(), AcpiError> {
    if inv.processors[..inv.processor_count]
        .iter()
        .any(|v| v.apic_id == p.apic_id)
    {
        return Err(AcpiError::Entry);
    }
    if inv.processor_count == 256 {
        return Err(AcpiError::Capacity);
    }
    inv.processors[inv.processor_count] = p;
    inv.processor_count += 1;
    Ok(())
}

fn validate_runtime_range<I, F>(
    address: u64,
    length: usize,
    descriptors: I,
    mut identity_mapped: F,
) -> Result<(), AcpiError>
where
    I: IntoIterator<Item = (u64, u64, bool)>,
    F: FnMut(u64) -> bool,
{
    let length = u64::try_from(length).map_err(|_| AcpiError::PhysicalRange)?;
    let end = address
        .checked_add(length)
        .ok_or(AcpiError::PhysicalRange)?;
    if end > FOUR_GIB {
        return Err(AcpiError::PhysicalRange);
    }
    let covered = descriptors.into_iter().any(|(start, pages, is_acpi)| {
        let size = pages.checked_mul(4096);
        is_acpi
            && size
                .and_then(|size| start.checked_add(size))
                .is_some_and(|limit| address >= start && end <= limit)
    });
    if !covered {
        return Err(AcpiError::PhysicalRange);
    }
    if length != 0 {
        let mut page = address & !4095;
        let last_page = (end - 1) & !4095;
        loop {
            if !identity_mapped(page) {
                return Err(AcpiError::PhysicalRange);
            }
            if page == last_page {
                break;
            }
            page = page.checked_add(4096).ok_or(AcpiError::PhysicalRange)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "uefi", target_os = "none"))]
struct RuntimeReader<'a>(&'a BootHandoverInfo);
#[cfg(any(target_os = "uefi", target_os = "none"))]
impl AcpiPhysicalReader for RuntimeReader<'_> {
    fn read_phys(&self, address: u64, length: usize) -> Result<&[u8], AcpiError> {
        let descriptors = self.0.memory_map().iter().map(|d| {
            (
                d.phys_start.as_u64(),
                d.number_of_pages,
                matches!(
                    d.mem_type,
                    UefiMemoryType::AcpiReclaimMemory | UefiMemoryType::AcpiMemoryNvs
                ),
            )
        });
        let kas = nexus_kernel_map();
        let kas = kas.as_ref().ok_or(AcpiError::PhysicalRange)?;
        let result = validate_runtime_range(address, length, descriptors, |page| {
            kas.translate(VirtualAddress::new(page))
                .is_some_and(|p| p.as_u64() == page)
        });
        if result.is_err()
            && address
                .checked_add(length as u64)
                .is_some_and(|end| end > FOUR_GIB)
        {
            crate::serial_println!(
                "[ACPI] rejected range above 4 GiB: {:#x}..{:#x}",
                address,
                address.saturating_add(length as u64)
            );
        } else if result.is_err() {
            crate::serial_println!(
                "[ACPI] rejected range outside ACPI memory descriptors: {:#x}..{:#x}",
                address,
                address.saturating_add(length as u64)
            );
        }
        result?;
        Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
    }
}
#[cfg(any(target_os = "uefi", target_os = "none"))]
fn nexus_kernel_map() -> spin::MutexGuard<'static, Option<crate::mem::vmm::AddressSpace>> {
    crate::mem::KERNEL_ADDRESS_SPACE.lock()
}

#[cfg(any(target_os = "uefi", target_os = "none"))]
pub(crate) fn discover(info: &BootHandoverInfo) -> Result<Option<AcpiInventory>, AcpiError> {
    let Some(rsdp) = info.rsdp_address else {
        return Ok(None);
    };
    let address = rsdp.as_u64();
    crate::serial_println!("[ACPI] advertised RSDP at {:#x}", address);
    parse_inventory(&RuntimeReader(info), address).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    struct FixtureReader {
        base: u64,
        bytes: &'static [u8],
        denied: Option<Range<u64>>,
    }
    impl AcpiPhysicalReader for FixtureReader {
        fn read_phys(&self, address: u64, length: usize) -> Result<&[u8], AcpiError> {
            let end = address
                .checked_add(length as u64)
                .ok_or(AcpiError::PhysicalRange)?;
            if self
                .denied
                .as_ref()
                .is_some_and(|r| address < r.end && end > r.start)
            {
                return Err(AcpiError::PhysicalRange);
            }
            let start = usize::try_from(
                address
                    .checked_sub(self.base)
                    .ok_or(AcpiError::PhysicalRange)?,
            )
            .map_err(|_| AcpiError::PhysicalRange)?;
            let stop = start.checked_add(length).ok_or(AcpiError::PhysicalRange)?;
            self.bytes.get(start..stop).ok_or(AcpiError::PhysicalRange)
        }
    }
    struct RecordingReader {
        inner: FixtureReader,
        lengths: RefCell<Vec<usize>>,
    }
    impl AcpiPhysicalReader for RecordingReader {
        fn read_phys(&self, address: u64, length: usize) -> Result<&[u8], AcpiError> {
            self.lengths.borrow_mut().push(length);
            self.inner.read_phys(address, length)
        }
    }
    #[test]
    fn valid_xsdt_discovers_firmware_inventory() {
        let r = FixtureReader {
            base: 0x100000,
            bytes: include_bytes!("../../../../../tests/fixtures/acpi/valid_xsdt.bin"),
            denied: None,
        };
        let result = parse_inventory(&r, 0x100000);
        assert!(result.is_ok(), "{result:?}");
        let i = result.unwrap();
        assert_eq!(i.lapic_address, 0xfee01000);
        assert_eq!(i.processors[0].apic_id, 0);
        assert!(i.processors[0].enabled);
        assert_eq!(i.processors[1].apic_id, 2);
        assert_eq!(i.processors[1].firmware_uid, 2);
        assert!(i.processors[1].x2apic);
        assert_eq!(i.io_apics[0].id, 2);
        assert_eq!(i.io_apics[0].address, 0xfec00000);
        assert_eq!(i.io_apics[0].gsi_base, 0);
        assert_eq!(i.overrides[0].gsi, 2);
        assert_eq!(i.overrides[0].bus, 0);
        assert_eq!(i.overrides[0].source_irq, 0);
        assert_eq!(i.overrides[0].polarity, 0);
        assert_eq!(i.overrides[0].trigger, 0);
        assert_eq!(i.revision, 2);
        assert_eq!(i.xsdt_address, 0x101000);
        assert_eq!(i.rsdt_address, 0);
        assert_eq!(i.madt_address, 0x102000);
    }

    #[test]
    fn accepts_uefi_rsdp_at_unaligned_vendor_table_address() {
        let reader = FixtureReader {
            base: 0x100000,
            bytes: include_bytes!("../../../../../tests/fixtures/acpi/valid_unaligned_rsdp.bin"),
            denied: None,
        };
        assert!(parse_inventory(&reader, 0x100014).is_ok());
    }
    #[test]
    fn valid_rsdt_and_negative_fixtures_are_checked() {
        let r = FixtureReader {
            base: 0x100000,
            bytes: include_bytes!("../../../../../tests/fixtures/acpi/valid_rsdt.bin"),
            denied: None,
        };
        assert!(parse_inventory(&r, 0x100000).is_ok());
        let b = FixtureReader {
            base: 0x100000,
            bytes: include_bytes!("../../../../../tests/fixtures/acpi/bad_madt_checksum.bin"),
            denied: None,
        };
        assert_eq!(
            parse_inventory(&b, 0x100000).err(),
            Some(AcpiError::Checksum)
        );
        let denied = FixtureReader {
            base: 0x100000,
            bytes: include_bytes!("../../../../../tests/fixtures/acpi/valid_xsdt.bin"),
            denied: Some(0x102000..0x103000),
        };
        assert!(parse_inventory(&denied, 0x100000).is_err());
        assert_eq!(
            parse_inventory(&r, 0x100001).err(),
            Some(AcpiError::Signature)
        );
    }
    #[test]
    fn malformed_fixture_classes_fail_closed() {
        let fixtures: [(&str, &[u8], AcpiError); 28] = [
            (
                "bad_rsdp_signature",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_rsdp_signature.bin"),
                AcpiError::Signature,
            ),
            (
                "bad_root_signature",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_root_signature.bin"),
                AcpiError::Signature,
            ),
            (
                "bad_madt_signature",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_madt_signature.bin"),
                AcpiError::MissingMadt,
            ),
            (
                "bad_xsdt_address",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_xsdt_address.bin"),
                AcpiError::PhysicalRange,
            ),
            (
                "bad_rsdp_checksum",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_rsdp_checksum.bin"),
                AcpiError::Checksum,
            ),
            (
                "bad_extended_checksum",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_extended_checksum.bin"),
                AcpiError::Checksum,
            ),
            (
                "truncated_extended",
                include_bytes!("../../../../../tests/fixtures/acpi/truncated_extended.bin"),
                AcpiError::PhysicalRange,
            ),
            (
                "bad_root_checksum",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_root_checksum.bin"),
                AcpiError::Checksum,
            ),
            (
                "bad_root_width",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_root_width.bin"),
                AcpiError::Entry,
            ),
            (
                "bad_madt_checksum",
                include_bytes!("../../../../../tests/fixtures/acpi/bad_madt_checksum.bin"),
                AcpiError::Checksum,
            ),
            (
                "madt_zero_length",
                include_bytes!("../../../../../tests/fixtures/acpi/madt_zero_length.bin"),
                AcpiError::Entry,
            ),
            (
                "madt_short_length",
                include_bytes!("../../../../../tests/fixtures/acpi/madt_short_length.bin"),
                AcpiError::Entry,
            ),
            (
                "madt_overrun_length",
                include_bytes!("../../../../../tests/fixtures/acpi/madt_overrun_length.bin"),
                AcpiError::Entry,
            ),
            (
                "short_supported_record",
                include_bytes!("../../../../../tests/fixtures/acpi/short_supported_record.bin"),
                AcpiError::Entry,
            ),
            (
                "reserved_flags",
                include_bytes!("../../../../../tests/fixtures/acpi/reserved_flags.bin"),
                AcpiError::Entry,
            ),
            (
                "reserved_encoding",
                include_bytes!("../../../../../tests/fixtures/acpi/reserved_encoding.bin"),
                AcpiError::Entry,
            ),
            (
                "duplicate_override",
                include_bytes!("../../../../../tests/fixtures/acpi/duplicate_override.bin"),
                AcpiError::Entry,
            ),
            (
                "duplicate_processor",
                include_bytes!("../../../../../tests/fixtures/acpi/duplicate_processor.bin"),
                AcpiError::Entry,
            ),
            (
                "duplicate_madt",
                include_bytes!("../../../../../tests/fixtures/acpi/duplicate_madt.bin"),
                AcpiError::Entry,
            ),
            (
                "processor_overflow",
                include_bytes!("../../../../../tests/fixtures/acpi/processor_overflow.bin"),
                AcpiError::Capacity,
            ),
            (
                "ioapic_overflow",
                include_bytes!("../../../../../tests/fixtures/acpi/ioapic_overflow.bin"),
                AcpiError::Capacity,
            ),
            (
                "override_overflow",
                include_bytes!("../../../../../tests/fixtures/acpi/override_overflow.bin"),
                AcpiError::Capacity,
            ),
            (
                "out_of_range",
                include_bytes!("../../../../../tests/fixtures/acpi/out_of_range.bin"),
                AcpiError::PhysicalRange,
            ),
            (
                "rsdp_length_35",
                include_bytes!("../../../../../tests/fixtures/acpi/rsdp_length_35.bin"),
                AcpiError::Length,
            ),
            (
                "rsdp_length_4097",
                include_bytes!("../../../../../tests/fixtures/acpi/rsdp_length_4097.bin"),
                AcpiError::Length,
            ),
            (
                "sdt_length_35",
                include_bytes!("../../../../../tests/fixtures/acpi/sdt_length_35.bin"),
                AcpiError::Length,
            ),
            (
                "sdt_length_max_plus_one",
                include_bytes!("../../../../../tests/fixtures/acpi/sdt_length_max_plus_one.bin"),
                AcpiError::Length,
            ),
            (
                "madt_length_43",
                include_bytes!("../../../../../tests/fixtures/acpi/madt_length_43.bin"),
                AcpiError::Length,
            ),
        ];
        for (name, bytes, expected) in fixtures {
            let r = FixtureReader {
                base: 0x100000,
                bytes,
                denied: None,
            };
            assert_eq!(
                parse_inventory(&r, 0x100000).err(),
                Some(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn short_supported_record_has_valid_lapic_and_checksum() {
        let fixture =
            include_bytes!("../../../../../tests/fixtures/acpi/short_supported_record.bin");
        let madt = &fixture[0x2000
            ..0x2000 + u32::from_le_bytes(fixture[0x2004..0x2008].try_into().unwrap()) as usize];
        assert_eq!(u32at(madt, 36).unwrap(), 0xfee00000);
        assert_eq!(madt[45], 7);
        assert!(checksum(madt));
        let r = FixtureReader {
            base: 0x100000,
            bytes: fixture,
            denied: None,
        };
        assert_eq!(parse_inventory(&r, 0x100000).err(), Some(AcpiError::Entry));
    }

    #[test]
    fn runtime_pre_dereference_validation_rejects_invalid_ranges_and_mappings() {
        let acpi = [(0x1000, 4, true)];
        let identity = |_: u64| true;
        for (address, length) in [(u64::MAX - 1, 4), (0xffff_f000, 8192)] {
            assert_eq!(
                validate_runtime_range(address, length, acpi.iter().copied(), identity),
                Err(AcpiError::PhysicalRange)
            );
        }
        assert_eq!(
            validate_runtime_range(0x1000, 4096, [(0x1000, 1, false)].into_iter(), identity),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(0x1000, 5 * 4096, acpi.iter().copied(), identity),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(
                0x1000,
                4096,
                [(0x1000, u64::MAX, true)].into_iter(),
                identity
            ),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(
                0x1000,
                8192,
                [(0x1000, u64::MAX / 4096 + 1, true)].into_iter(),
                identity
            ),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(0x1000, 8192, [(0x1000, 2, true)].into_iter(), |page| page
                != 0x2000),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(0x1000, 8192, [(0x1000, 2, true)].into_iter(), |page| page
                != 0x1000),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(0x1000, 12288, [(0x1000, 3, true)].into_iter(), |page| page
                != 0x3000),
            Err(AcpiError::PhysicalRange)
        );
        assert_eq!(
            validate_runtime_range(
                0x1000,
                1,
                [(u64::MAX - 4095, 1, true)].into_iter(),
                identity
            ),
            Err(AcpiError::PhysicalRange)
        );
    }

    #[test]
    fn invalid_runtime_ranges_fail_before_requesting_bytes() {
        let mut translation_calls = 0;
        let result = validate_runtime_range(u64::MAX - 2, 8, core::iter::empty(), |_| {
            translation_calls += 1;
            true
        });
        assert_eq!(result, Err(AcpiError::PhysicalRange));
        assert_eq!(translation_calls, 0);
    }

    #[test]
    fn overflowing_physical_interval_is_rejected_by_reader() {
        let reader = RecordingReader {
            inner: FixtureReader {
                base: u64::MAX - 10,
                bytes: include_bytes!(
                    "../../../../../tests/fixtures/acpi/physical_interval_overflow.bin"
                ),
                denied: None,
            },
            lengths: RefCell::new(Vec::new()),
        };
        assert_eq!(
            parse_inventory(&reader, u64::MAX - 10).err(),
            Some(AcpiError::PhysicalRange)
        );
        assert_eq!(&*reader.lengths.borrow(), &[20]);
    }

    #[test]
    fn rejected_lengths_do_not_request_the_declared_full_table() {
        for (name, bytes, forbidden_length) in [
            (
                "rsdp_length_35",
                include_bytes!("../../../../../tests/fixtures/acpi/rsdp_length_35.bin").as_slice(),
                35,
            ),
            (
                "rsdp_length_4097",
                include_bytes!("../../../../../tests/fixtures/acpi/rsdp_length_4097.bin")
                    .as_slice(),
                4097,
            ),
            (
                "sdt_length_35",
                include_bytes!("../../../../../tests/fixtures/acpi/sdt_length_35.bin").as_slice(),
                35,
            ),
            (
                "sdt_length_max_plus_one",
                include_bytes!("../../../../../tests/fixtures/acpi/sdt_length_max_plus_one.bin")
                    .as_slice(),
                MAX_SDT + 1,
            ),
        ] {
            let reader = RecordingReader {
                inner: FixtureReader {
                    base: 0x100000,
                    bytes,
                    denied: None,
                },
                lengths: RefCell::new(Vec::new()),
            };
            assert_eq!(
                parse_inventory(&reader, 0x100000).err(),
                Some(AcpiError::Length),
                "{name}"
            );
            assert!(
                !reader.lengths.borrow().contains(&forbidden_length),
                "{name}: {:?}",
                reader.lengths.borrow()
            );
        }
    }
}
