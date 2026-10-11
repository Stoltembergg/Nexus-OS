use byteorder::{ByteOrder, LittleEndian as LE};
use nexus_loader::{ElfImage, PeImage};

fn pe_bytes() -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..2].copy_from_slice(b"MZ");
    LE::write_u32(&mut b[60..64], 128);
    b[128..132].copy_from_slice(b"PE\0\0");
    LE::write_u16(&mut b[132..134], 0x8664);
    LE::write_u16(&mut b[134..136], 1);
    LE::write_u16(&mut b[148..150], 240);
    LE::write_u16(&mut b[152..154], 0x20b);
    LE::write_u32(&mut b[168..172], 0x1000);
    LE::write_u64(&mut b[176..184], 0x140000000);
    LE::write_u32(&mut b[184..188], 4096);
    LE::write_u32(&mut b[188..192], 512);
    LE::write_u32(&mut b[208..212], 8192);
    LE::write_u32(&mut b[212..216], 512);
    LE::write_u32(&mut b[260..264], 16);
    b[392..397].copy_from_slice(b".text");
    LE::write_u32(&mut b[400..404], 4096);
    LE::write_u32(&mut b[404..408], 4096);
    LE::write_u32(&mut b[408..412], 512);
    LE::write_u32(&mut b[412..416], 512);
    LE::write_u32(&mut b[428..432], 0x60000020);
    b
}

#[test]
fn malformed_relocation_directory_and_blocks_fail_closed() {
    for (rva, size, block) in [
        (0x9000, 12, 12),
        (0x1080, 4, 4),
        (0x1080, 12, 14),
        (0x1080, 12, 9),
    ] {
        let mut b = pe_bytes();
        LE::write_u32(&mut b[304..308], rva);
        LE::write_u32(&mut b[308..312], size);
        LE::write_u32(&mut b[640..644], 0x1000);
        LE::write_u32(&mut b[644..648], block);
        let image = PeImage::parse(&b).unwrap();
        assert!(
            image.parse_relocations(&b).is_err(),
            "accepted directory {rva:x}/{size}/{block}"
        );
    }
}

#[test]
fn import_descriptors_cannot_escape_directory_or_truncated_input() {
    let mut b = pe_bytes();
    LE::write_u32(&mut b[272..276], 0x1080);
    LE::write_u32(&mut b[276..280], 20);
    LE::write_u32(&mut b[640..644], 0x1100); // no terminating descriptor in directory
    LE::write_u32(&mut b[652..656], 0x1120);
    LE::write_u32(&mut b[656..660], 0x1140);
    let image = PeImage::parse(&b).unwrap();
    assert!(image.parse_imports(&b).is_err());
    assert!(std::panic::catch_unwind(|| image.parse_imports(&b[..650]))
        .unwrap()
        .is_err());
}

#[test]
fn all_truncations_and_deterministic_header_mutations_never_panic() {
    let original = pe_bytes();
    for end in 0..original.len() {
        assert!(std::panic::catch_unwind(|| PeImage::parse(&original[..end])).is_ok());
    }
    let mut seed = 0x23456789u64;
    for _ in 0..2048 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut bytes = original.clone();
        let offset = seed as usize % 432;
        bytes[offset] = (seed >> 32) as u8;
        assert!(std::panic::catch_unwind(|| PeImage::parse(&bytes)).is_ok());
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        assert!(std::panic::catch_unwind(|| ElfImage::parse(&bytes)).is_ok());
    }
}
