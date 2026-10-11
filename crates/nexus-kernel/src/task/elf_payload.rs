//! Freestanding ELF64 User-Mode Payloads for Nexus OS Process Execution.

use byteorder::{ByteOrder, LittleEndian};

pub const ELF_USER_BASE_VADDR: u64 = 0x0000_0000_4000_0000; // 1 GB user base
pub const ELF_USER_ENTRY_VADDR: u64 = 0x0000_0000_4000_1000;

/// Generates a valid freestanding ELF64 executable in memory that invokes
/// Linux `SYS_WRITE` (1) to print a greeting message, `SYS_SCHED_YIELD` (24) to yield
/// CPU cooperatively to the Windows PE32+ task, and `SYS_EXIT` (60) with code 0 upon resumption.
pub fn generate_ring3_elf_payload(message: &[u8]) -> [u8; 8192] {
    let mut image = [0u8; 8192];

    // ELF Header (64 bytes)
    image[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB (little endian)
    image[6] = 1; // EV_CURRENT
    image[7] = 0; // ELFOSABI_NONE

    LittleEndian::write_u16(&mut image[16..18], 2); // ET_EXEC
    LittleEndian::write_u16(&mut image[18..20], 0x3E); // EM_X86_64
    LittleEndian::write_u32(&mut image[20..24], 1); // EV_CURRENT
    LittleEndian::write_u64(&mut image[24..32], ELF_USER_ENTRY_VADDR); // e_entry
    LittleEndian::write_u64(&mut image[32..40], 64); // e_phoff
    LittleEndian::write_u16(&mut image[52..54], 64); // e_ehsize
    LittleEndian::write_u16(&mut image[54..56], 56); // e_phentsize
    LittleEndian::write_u16(&mut image[56..58], 1); // e_phnum (1 load segment)

    // Program Header (56 bytes at offset 64)
    let ph_off = 64;
    LittleEndian::write_u32(&mut image[ph_off..ph_off + 4], 1); // PT_LOAD
    LittleEndian::write_u32(&mut image[ph_off + 4..ph_off + 8], 5); // PF_R | PF_X
    LittleEndian::write_u64(&mut image[ph_off + 8..ph_off + 16], 0x1000); // p_offset
    LittleEndian::write_u64(&mut image[ph_off + 16..ph_off + 24], ELF_USER_ENTRY_VADDR); // p_vaddr
    LittleEndian::write_u64(&mut image[ph_off + 24..ph_off + 32], ELF_USER_ENTRY_VADDR); // p_paddr
    LittleEndian::write_u64(&mut image[ph_off + 32..ph_off + 40], 4096); // p_filesz
    LittleEndian::write_u64(&mut image[ph_off + 40..ph_off + 48], 4096); // p_memsz
    LittleEndian::write_u64(&mut image[ph_off + 48..ph_off + 56], 0x1000); // p_align

    // Payload Machine Code placed at file offset 0x1000 (virtual address ELF_USER_ENTRY_VADDR)
    let code_offset = 0x1000;
    let msg_vaddr = ELF_USER_ENTRY_VADDR + 0x100;
    let msg_offset = code_offset + 0x100;

    let msg_len = message.len().min(128);
    image[msg_offset..msg_offset + msg_len].copy_from_slice(&message[..msg_len]);

    let mut code: [u8; 64] = [0; 64];
    let mut i = 0;

    // 1. mov rax, 1 (SYS_WRITE)
    code[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]);
    i += 7;

    // 2. mov rdi, 1 (stdout)
    code[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00]);
    i += 7;

    // 3. movabs rsi, msg_vaddr
    code[i..i + 2].copy_from_slice(&[0x48, 0xBE]);
    LittleEndian::write_u64(&mut code[i + 2..i + 10], msg_vaddr);
    i += 10;

    // 4. mov rdx, msg_len
    code[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC2, msg_len as u8, 0x00, 0x00, 0x00]);
    i += 7;

    // 5. syscall (SYS_WRITE)
    code[i..i + 2].copy_from_slice(&[0x0F, 0x05]);
    i += 2;

    // 6. mov rax, 24 (SYS_SCHED_YIELD)
    code[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC0, 0x18, 0x00, 0x00, 0x00]);
    i += 7;

    // 7. syscall (SYS_SCHED_YIELD)
    code[i..i + 2].copy_from_slice(&[0x0F, 0x05]);
    i += 2;

    // 8. mov rax, 60 (SYS_EXIT)
    code[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00]);
    i += 7;

    // 9. mov rdi, 0 (status 0)
    code[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00]);
    i += 7;

    // 10. syscall (SYS_EXIT)
    code[i..i + 2].copy_from_slice(&[0x0F, 0x05]);
    i += 2;

    image[code_offset..code_offset + i].copy_from_slice(&code[..i]);

    image
}

/// Generates a faulting ELF payload that attempts to dereference supervisor kernel memory
/// from Ring 3 (0x0010_0000 - Kernel PML4 page), intentionally triggering a hardware #PF (Vector 14).
pub fn generate_faulting_elf_payload() -> [u8; 8192] {
    let mut image = [0u8; 8192];

    image[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[7] = 0;

    LittleEndian::write_u16(&mut image[16..18], 2);
    LittleEndian::write_u16(&mut image[18..20], 0x3E);
    LittleEndian::write_u32(&mut image[20..24], 1);
    LittleEndian::write_u64(&mut image[24..32], ELF_USER_ENTRY_VADDR);
    LittleEndian::write_u64(&mut image[32..40], 64);
    LittleEndian::write_u16(&mut image[52..54], 64);
    LittleEndian::write_u16(&mut image[54..56], 56);
    LittleEndian::write_u16(&mut image[56..58], 1);

    // Program Header
    let ph_off = 64;
    LittleEndian::write_u32(&mut image[ph_off..ph_off + 4], 1);
    LittleEndian::write_u32(&mut image[ph_off + 4..ph_off + 8], 5);
    LittleEndian::write_u64(&mut image[ph_off + 8..ph_off + 16], 0x1000);
    LittleEndian::write_u64(&mut image[ph_off + 16..ph_off + 24], ELF_USER_ENTRY_VADDR);
    LittleEndian::write_u64(&mut image[ph_off + 24..ph_off + 32], ELF_USER_ENTRY_VADDR);
    LittleEndian::write_u64(&mut image[ph_off + 32..ph_off + 40], 32);
    LittleEndian::write_u64(&mut image[ph_off + 40..ph_off + 48], 32);
    LittleEndian::write_u64(&mut image[ph_off + 48..ph_off + 56], 0x1000);

    // Code: mov rax, 0x00100000; mov rbx, [rax] (causes Ring 3 #PF: Supervisor page access violation)
    let code_offset = 0x1000;
    let fault_code: [u8; 13] = [
        0x48, 0xB8, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, // movabs rax, 0x00100000 (Supervisor-only Kernel PML4 page)
        0x48, 0x8B, 0x18, // mov rbx, [rax]
    ];
    image[code_offset..code_offset + 13].copy_from_slice(&fault_code);

    image
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_loader::ElfImage;

    #[test]
    fn test_ring3_elf_payload_parsing() {
        let msg = b"Hello Ring 3!\n";
        let image = generate_ring3_elf_payload(msg);
        let elf = ElfImage::parse(&image).expect("Valid ELF64 payload");

        assert_eq!(elf.entry_point, ELF_USER_ENTRY_VADDR);
        assert_eq!(elf.program_headers.len(), 1);
        assert_eq!(elf.program_headers[0].p_vaddr, ELF_USER_ENTRY_VADDR);
    }
}
