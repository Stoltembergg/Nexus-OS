#!/usr/bin/env python3
"""Generate independent, deterministic physical-address ACPI parser fixtures."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'tests' / 'fixtures' / 'acpi'
BASE = 0x100000


def checksum(data):
    return (-sum(data)) & 0xff


def sdt(signature, body):
    data = bytearray(36 + len(body))
    data[:4] = signature
    data[4:8] = len(data).to_bytes(4, 'little')
    data[8] = 1
    data[10:16] = b'NEXUS '
    data[16:24] = b'ACPITEST'
    data[24:28] = (1).to_bytes(4, 'little')
    data[28:32] = b'NXOS'
    data[32:36] = (1).to_bytes(4, 'little')
    data[36:] = body
    data[9] = checksum(data)
    return data


def madt(entries):
    return sdt(b'APIC', (0xfee00000).to_bytes(4, 'little') + bytes(4) + entries)


def make_fixture(xsdt=True, mutation=None, rsdp_offset=0):
    image = bytearray(0x3000)
    # Type 0 LAPIC; type 1 IOAPIC; type 2 override; type 5 LAPIC override; type 9 x2APIC.
    override = bytes([2, 10, 0, 0]) + (2).to_bytes(4, 'little') + (0).to_bytes(2, 'little')
    records = (bytes([0, 8, 0, 0]) + (1).to_bytes(4, 'little') +
               bytes([1, 12, 2, 0]) + (0xfec00000).to_bytes(4, 'little') + (0).to_bytes(4, 'little') +
               override +
               bytes([5, 12, 0, 0]) + (0xfee01000).to_bytes(8, 'little') +
               bytes([9, 16]) + bytes(2) + (2).to_bytes(4, 'little') + (1).to_bytes(4, 'little') + (2).to_bytes(4, 'little'))
    if mutation == 'duplicate_override': records += override
    if mutation == 'duplicate_processor': records += bytes([0, 8, 0, 0]) + (1).to_bytes(4, 'little')
    if mutation == 'processor_overflow':
        records += b''.join(bytes([9, 16]) + bytes(2) + apic.to_bytes(4, 'little') + (1).to_bytes(4, 'little') + apic.to_bytes(4, 'little') for apic in range(3, 258))
    if mutation == 'ioapic_overflow':
        records += b''.join(bytes([1, 12, apic & 0xff, 0]) + (0xfec00000).to_bytes(4, 'little') + (apic * 24).to_bytes(4, 'little') for apic in range(1, 17))
    if mutation == 'override_overflow':
        records += b''.join(bytes([2, 10, irq // 256, irq & 0xff]) + (irq).to_bytes(4, 'little') + bytes(2) for irq in range(1, 257))
    table = madt(records)
    if mutation == 'bad_madt_checksum': table[9] ^= 0xff
    if mutation == 'madt_length_43':
        table = table[:43]
        table[4:8] = (43).to_bytes(4, 'little')
    if mutation in ('sdt_length_35', 'sdt_length_max_plus_one'):
        declared_length = 35 if mutation == 'sdt_length_35' else 1024 * 1024 + 1
        table[4:8] = declared_length.to_bytes(4, 'little')
        if declared_length > len(table):
            table.extend(bytes(declared_length - len(table)))
    if mutation == 'madt_zero_length': table[-len(records)+1] = 0
    if mutation == 'madt_short_length': table[-len(records)+1] = 1
    if mutation == 'madt_overrun_length': table[-len(records)+1] = 0xff
    if mutation == 'short_supported_record': table[45] = 7
    if mutation == 'reserved_flags': table[44+8+12+8] = 0x10
    if mutation == 'reserved_encoding': table[44+8+12+8] = 2
    if mutation == 'bad_madt_signature': table[:4] = b'BAD!'
    if mutation == 'duplicate_madt': pass
    if mutation not in ('bad_madt_checksum',):
        table[9] = 0
        table[9] = checksum(table[:35] if mutation == 'sdt_length_35' else table)
    image[0x2000:0x2000+len(table)] = table
    root_entries = (0x102000).to_bytes(8 if xsdt else 4, 'little')
    if mutation == 'duplicate_madt': root_entries += root_entries
    root = sdt(b'XSDT' if xsdt else b'RSDT', root_entries)
    if mutation == 'bad_root_checksum': root[9] ^= 0xff
    if mutation == 'bad_root_width': root[36:] += b'X'; root[4:8] = len(root).to_bytes(4,'little'); root[9] = 0; root[9] = checksum(root)
    if mutation == 'bad_root_signature': root[:4] = b'BAD!'; root[9] = 0; root[9] = checksum(root)
    if mutation == 'out_of_range': root[36:44 if xsdt else 40] = (0xfffff000).to_bytes(8 if xsdt else 4, 'little'); root[9] = 0; root[9] = checksum(root)
    image[0x1000:0x1000+len(root)] = root
    rsdp = bytearray(36)
    rsdp[:8] = b'RSD PTR '
    rsdp[9:15] = b'NEXUS '
    rsdp[15] = 2 if xsdt else 0
    rsdp[16:20] = (0 if xsdt else 0x101000).to_bytes(4, 'little')
    rsdp[20:24] = (36).to_bytes(4, 'little')
    rsdp[24:32] = (0x101000 if xsdt else 0).to_bytes(8, 'little')
    rsdp[8] = checksum(rsdp[:20])
    rsdp[32] = checksum(rsdp)
    if mutation in ('rsdp_length_35', 'rsdp_length_4097'):
        declared_length = 35 if mutation == 'rsdp_length_35' else 4097
        rsdp[20:24] = declared_length.to_bytes(4, 'little')
        rsdp[32] = 0
        rsdp[32] = checksum(rsdp[:35] if declared_length == 35 else rsdp)
    if mutation == 'bad_rsdp_checksum': rsdp[8] ^= 1
    if mutation == 'bad_rsdp_signature': rsdp[:8] = b'BAD RSDP'; rsdp[8] = 0; rsdp[8] = checksum(rsdp[:20])
    if mutation == 'bad_extended_checksum': rsdp[32] ^= 1
    if mutation == 'bad_xsdt_address':
        rsdp[24:32] = (0xfffff000).to_bytes(8, 'little')
        rsdp[32] = 0
        rsdp[32] = checksum(rsdp)
    image[rsdp_offset:rsdp_offset + len(rsdp)] = rsdp
    if mutation == 'rsdp_length_4097':
        image[rsdp_offset + 32] = 0
        image[rsdp_offset + 32] = checksum(image[rsdp_offset:rsdp_offset + 4097])
    if mutation == 'truncated_extended': return bytes(image[:20])
    return bytes(image)


def datasets():
    result = {'valid_xsdt': (make_fixture(), 'valid'), 'valid_rsdt': (make_fixture(False), 'valid'),
              'valid_unaligned_rsdp': (make_fixture(rsdp_offset=0x14), 'valid')}
    for name, expected in [('bad_rsdp_checksum','Checksum'),('bad_extended_checksum','Checksum'),('bad_root_checksum','Checksum'),('bad_root_width','Entry'),('bad_madt_checksum','Checksum'),('madt_zero_length','Entry'),('madt_short_length','Entry'),('madt_overrun_length','Entry'),('short_supported_record','Entry'),('reserved_flags','Entry'),('duplicate_override','Entry'),('duplicate_madt','Entry'),('out_of_range','PhysicalRange')]:
        result[name] = (make_fixture(mutation=name), expected)
    for name, expected in [('bad_rsdp_signature','Signature'),('bad_root_signature','Signature'),('bad_madt_signature','MissingMadt'),('bad_xsdt_address','PhysicalRange'),('reserved_encoding','Entry'),('duplicate_processor','Entry'),('processor_overflow','Capacity'),('ioapic_overflow','Capacity'),('override_overflow','Capacity')]:
        result[name] = (make_fixture(mutation=name), expected)
    result['truncated_extended'] = (make_fixture(mutation='truncated_extended'), 'PhysicalRange')
    for name in ('rsdp_length_35', 'rsdp_length_4097', 'sdt_length_35', 'sdt_length_max_plus_one'):
        result[name] = (make_fixture(mutation=name), 'Length')
    result['madt_length_43'] = (make_fixture(mutation='madt_length_43'), 'Length')
    result['physical_interval_overflow'] = (make_fixture(), 'PhysicalRange')
    short = result['short_supported_record'][0]
    madt_start = 0x2000
    madt_length = int.from_bytes(short[madt_start + 4:madt_start + 8], 'little')
    madt_bytes = short[madt_start:madt_start + madt_length]
    if int.from_bytes(madt_bytes[36:40], 'little') != 0xfee00000:
        raise ValueError('short_supported_record has invalid LAPIC base')
    if madt_bytes[45] != 7 or sum(madt_bytes) & 0xff:
        raise ValueError('short_supported_record does not isolate a checksummed short record')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = datasets()
    manifest = {'base_address': hex(BASE), 'fixtures': {}}
    for name, (data, expected) in sorted(generated.items()):
        manifest['fixtures'][name + '.bin'] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'expected': expected}
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    if args.check:
        if not OUT.is_dir(): raise SystemExit('ACPI fixture directory missing')
        existing = {p.name for p in OUT.glob('*.bin')}
        if existing != set(manifest['fixtures']): raise SystemExit('ACPI fixture set differs from generator')
        for name, (data, _) in generated.items():
            if (OUT / (name + '.bin')).read_bytes() != data: raise SystemExit(f'ACPI fixture differs: {name}.bin')
        if (OUT / 'manifest.json').read_bytes() != manifest_bytes: raise SystemExit('ACPI manifest differs from generator')
        print(f'ACPI fixtures reproducible: {len(generated)} files')
    else:
        OUT.mkdir(parents=True, exist_ok=True)
        for name, (data, _) in generated.items(): (OUT / (name + '.bin')).write_bytes(data)
        (OUT / 'manifest.json').write_bytes(manifest_bytes)
        print(f'Generated {len(generated)} ACPI fixtures in {OUT}')


if __name__ == '__main__': main()
