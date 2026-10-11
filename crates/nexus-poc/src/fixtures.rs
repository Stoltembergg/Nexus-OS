//! Synthetic valid x86_64 PE32+ and ELF64 binary builders for automated testing.

use byteorder::{ByteOrder, LittleEndian};

/// Constructs a valid, minimal 64-bit Windows PE32+ executable in memory.
pub fn create_minimal_pe64() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];

    // 1. DOS Header
    LittleEndian::write_u16(&mut buf[0..2], 0x5A4D); // 'MZ'
    LittleEndian::write_u32(&mut buf[60..64], 0x80); // e_lfanew -> 0x80

    // 2. PE Signature at offset 0x80
    let pe_offset = 0x80;
    buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

    // 3. COFF File Header (offset 0x84)
    let coff_offset = pe_offset + 4;
    LittleEndian::write_u16(&mut buf[coff_offset..coff_offset + 2], 0x8664); // AMD64
    LittleEndian::write_u16(&mut buf[coff_offset + 2..coff_offset + 4], 2); // 2 sections (.text, .data)
    LittleEndian::write_u32(&mut buf[coff_offset + 4..coff_offset + 8], 0x65000000); // Timestamp
    LittleEndian::write_u16(&mut buf[coff_offset + 16..coff_offset + 18], 240); // SizeOfOptionalHeader
    LittleEndian::write_u16(&mut buf[coff_offset + 18..coff_offset + 20], 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 4. Optional Header (PE32+ 64-bit at offset 0x98)
    let opt_offset = coff_offset + 20;
    LittleEndian::write_u16(&mut buf[opt_offset..opt_offset + 2], 0x020B); // PE32+
    LittleEndian::write_u32(&mut buf[opt_offset + 16..opt_offset + 20], 0x1000); // AddressOfEntryPoint (RVA 0x1000)
    LittleEndian::write_u32(&mut buf[opt_offset + 20..opt_offset + 24], 0x1000); // BaseOfCode
    LittleEndian::write_u64(&mut buf[opt_offset + 24..opt_offset + 32], 0x0000_0001_4000_0000); // ImageBase
    LittleEndian::write_u32(&mut buf[opt_offset + 32..opt_offset + 36], 0x1000); // SectionAlignment
    LittleEndian::write_u32(&mut buf[opt_offset + 36..opt_offset + 40], 0x200); // FileAlignment
    LittleEndian::write_u32(&mut buf[opt_offset + 56..opt_offset + 60], 0x3000); // SizeOfImage
    LittleEndian::write_u32(&mut buf[opt_offset + 60..opt_offset + 64], 0x400); // SizeOfHeaders
    LittleEndian::write_u16(&mut buf[opt_offset + 68..opt_offset + 70], 3); // Subsystem: Windows CUI (Console)

    // 5. Section Table (offset = opt_offset + 240 = 0x98 + 240 = 0x188)
    let sec1_offset = opt_offset + 240;
    // Section 1: .text
    buf[sec1_offset..sec1_offset + 5].copy_from_slice(b".text");
    LittleEndian::write_u32(&mut buf[sec1_offset + 8..sec1_offset + 12], 0x200); // VirtualSize
    LittleEndian::write_u32(&mut buf[sec1_offset + 12..sec1_offset + 16], 0x1000); // VirtualAddress (RVA)
    LittleEndian::write_u32(&mut buf[sec1_offset + 16..sec1_offset + 20], 0x200); // SizeOfRawData
    LittleEndian::write_u32(&mut buf[sec1_offset + 20..sec1_offset + 24], 0x400); // PointerToRawData
    LittleEndian::write_u32(&mut buf[sec1_offset + 36..sec1_offset + 40], 0x6000_0020); // CODE | EXECUTE | READ

    // Section 2: .data
    let sec2_offset = sec1_offset + 40;
    buf[sec2_offset..sec2_offset + 5].copy_from_slice(b".data");
    LittleEndian::write_u32(&mut buf[sec2_offset + 8..sec2_offset + 12], 0x200); // VirtualSize
    LittleEndian::write_u32(&mut buf[sec2_offset + 12..sec2_offset + 16], 0x2000); // VirtualAddress (RVA)
    LittleEndian::write_u32(&mut buf[sec2_offset + 16..sec2_offset + 20], 0x200); // SizeOfRawData
    LittleEndian::write_u32(&mut buf[sec2_offset + 20..sec2_offset + 24], 0x600); // PointerToRawData
    LittleEndian::write_u32(&mut buf[sec2_offset + 36..sec2_offset + 40], 0xC000_0040); // INITIALIZED_DATA | READ | WRITE

    // 6. Section raw payloads:
    // .text payload at raw offset 0x400: x86_64 "mov eax, 42; ret" (B8 2A 00 00 00 C3)
    buf[0x400..0x406].copy_from_slice(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);

    buf
}

/// Constructs a valid, minimal 64-bit Linux ELF executable in memory.
pub fn create_minimal_elf64() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];

    // 1. ELF Header (64 bytes)
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // 64-bit
    buf[5] = 1; // Little-endian
    buf[6] = 1; // Current ELF version
    buf[7] = 0; // System V ABI

    LittleEndian::write_u16(&mut buf[16..18], 2); // ET_EXEC
    LittleEndian::write_u16(&mut buf[18..20], 62); // EM_X86_64
    LittleEndian::write_u32(&mut buf[20..24], 1); // EV_CURRENT
    LittleEndian::write_u64(&mut buf[24..32], 0x0000_0000_0040_1000); // Entry point
    LittleEndian::write_u64(&mut buf[32..40], 64); // Program Header table offset (immediately follows ELF hdr)
    LittleEndian::write_u64(&mut buf[40..48], 0); // Section Header table offset
    LittleEndian::write_u32(&mut buf[48..52], 0); // Flags
    LittleEndian::write_u16(&mut buf[52..54], 64); // Header size
    LittleEndian::write_u16(&mut buf[54..56], 56); // Program Header entry size
    LittleEndian::write_u16(&mut buf[56..58], 1); // Program Header count (1 PT_LOAD segment)
    LittleEndian::write_u16(&mut buf[58..60], 64); // Section Header size
    LittleEndian::write_u16(&mut buf[60..62], 0); // Section Header count
    LittleEndian::write_u16(&mut buf[62..64], 0); // String table index

    // 2. Program Header 1 (PT_LOAD at offset 64, size 56)
    let ph_offset = 64;
    LittleEndian::write_u32(&mut buf[ph_offset..ph_offset + 4], 1); // PT_LOAD
    LittleEndian::write_u32(&mut buf[ph_offset + 4..ph_offset + 8], 0x5); // PF_R | PF_X
    LittleEndian::write_u64(&mut buf[ph_offset + 8..ph_offset + 16], 0x1000); // p_offset
    LittleEndian::write_u64(&mut buf[ph_offset + 16..ph_offset + 24], 0x0040_1000); // p_vaddr
    LittleEndian::write_u64(&mut buf[ph_offset + 24..ph_offset + 32], 0x0040_1000); // p_paddr
    LittleEndian::write_u64(&mut buf[ph_offset + 32..ph_offset + 40], 0x200); // p_filesz
    LittleEndian::write_u64(&mut buf[ph_offset + 40..ph_offset + 48], 0x200); // p_memsz
    LittleEndian::write_u64(&mut buf[ph_offset + 48..ph_offset + 56], 0x1000); // p_align

    // Enlarge buffer to contain payload at 0x1000
    if buf.len() < 0x1200 {
        buf.resize(0x1200, 0);
    }

    // 3. Payload at offset 0x1000: x86_64 "mov rax, 60; mov rdi, 0; syscall" (exit(0))
    // 48 C7 C0 3C 00 00 00 48 31 FF 0F 05
    let payload = [
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax, 60
        0x48, 0x31, 0xFF,                         // xor rdi, rdi
        0x0F, 0x05,                               // syscall
    ];
    buf[0x1000..0x1000 + payload.len()].copy_from_slice(&payload);

    buf
}
