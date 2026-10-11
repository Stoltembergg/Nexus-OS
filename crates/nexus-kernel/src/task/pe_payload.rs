//! Freestanding Windows PE32+ (x86_64) Binary Generator for Ring 3 Execution.
//!
//! Generates a valid PE32+ binary in memory with:
//! - Valid DOS Header and PE Header
//! - AMD64 Machine and Optional Header 64 with Data Directories
//! - `.text`, `.data`, and `.reloc` sections
//! - Ring 3 machine code utilizing TEB/PEB via GS base and Windows NT syscalls:
//!   - `NtWriteFile` (SSN 0x0008)
//!   - `NtYieldExecution` (SSN 0x0050)
//!   - `NtTerminateProcess` (SSN 0x002C)

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};

pub const PE_IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
pub const PE_ENTRY_RVA: u32 = 0x1000;
pub const PE_DATA_RVA: u32 = 0x2000;
pub const PE_RELOC_RVA: u32 = 0x3000;

pub fn generate_ring3_pe_payload() -> Vec<u8> {
    let mut pe = vec![0u8; 0x4000]; // 16 KB (4 pages: Headers, .text, .data, .reloc)

    // 1. DOS Header
    LittleEndian::write_u16(&mut pe[0..2], 0x5A4D); // "MZ"
    LittleEndian::write_u32(&mut pe[60..64], 128); // e_lfanew = 128 (0x80)

    // 2. PE Signature
    let pe_sig_offset = 128;
    LittleEndian::write_u32(&mut pe[pe_sig_offset..pe_sig_offset + 4], 0x0000_4550); // "PE\0\0"

    // 3. COFF File Header
    let file_header_offset = pe_sig_offset + 4;
    LittleEndian::write_u16(&mut pe[file_header_offset..file_header_offset + 2], 0x8664); // AMD64
    LittleEndian::write_u16(&mut pe[file_header_offset + 2..file_header_offset + 4], 3); // 3 sections
    LittleEndian::write_u16(
        &mut pe[file_header_offset + 16..file_header_offset + 18],
        240,
    ); // SizeOfOptionalHeader = 240
    LittleEndian::write_u16(
        &mut pe[file_header_offset + 18..file_header_offset + 20],
        0x0022,
    ); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 4. Optional Header (PE32+ 64-bit)
    let opt_offset = file_header_offset + 20;
    LittleEndian::write_u16(&mut pe[opt_offset..opt_offset + 2], 0x020B); // PE32+ magic
    pe[opt_offset + 2] = 14; // MajorLinkerVersion
    pe[opt_offset + 3] = 0; // MinorLinkerVersion
    LittleEndian::write_u32(&mut pe[opt_offset + 4..opt_offset + 8], 0x1000); // SizeOfCode
    LittleEndian::write_u32(&mut pe[opt_offset + 8..opt_offset + 12], 0x2000); // SizeOfInitializedData
    LittleEndian::write_u32(&mut pe[opt_offset + 16..opt_offset + 20], PE_ENTRY_RVA); // AddressOfEntryPoint
    LittleEndian::write_u32(&mut pe[opt_offset + 20..opt_offset + 24], 0x1000); // BaseOfCode
    LittleEndian::write_u64(&mut pe[opt_offset + 24..opt_offset + 32], PE_IMAGE_BASE); // ImageBase
    LittleEndian::write_u32(&mut pe[opt_offset + 32..opt_offset + 36], 0x1000); // SectionAlignment
    LittleEndian::write_u32(&mut pe[opt_offset + 36..opt_offset + 40], 0x1000); // FileAlignment
    LittleEndian::write_u16(&mut pe[opt_offset + 40..opt_offset + 42], 10); // MajorOSVersion
    LittleEndian::write_u16(&mut pe[opt_offset + 48..opt_offset + 50], 10); // MajorSubsystemVersion
    LittleEndian::write_u32(&mut pe[opt_offset + 56..opt_offset + 60], 0x4000); // SizeOfImage
    LittleEndian::write_u32(&mut pe[opt_offset + 60..opt_offset + 64], 0x1000); // SizeOfHeaders
    LittleEndian::write_u16(&mut pe[opt_offset + 68..opt_offset + 70], 3); // Subsystem = Windows CUI (Console)
    LittleEndian::write_u16(&mut pe[opt_offset + 70..opt_offset + 72], 0x8160); // DllCharacteristics
    LittleEndian::write_u64(&mut pe[opt_offset + 72..opt_offset + 80], 0x100000); // SizeOfStackReserve
    LittleEndian::write_u64(&mut pe[opt_offset + 80..opt_offset + 88], 0x4000); // SizeOfStackCommit
    LittleEndian::write_u32(&mut pe[opt_offset + 108..opt_offset + 112], 16); // NumberOfRvaAndSizes

    // Data Directory 5 (Base Relocations)
    let reloc_dir_offset = opt_offset + 112 + (5 * 8);
    LittleEndian::write_u32(
        &mut pe[reloc_dir_offset..reloc_dir_offset + 4],
        PE_RELOC_RVA,
    );
    LittleEndian::write_u32(&mut pe[reloc_dir_offset + 4..reloc_dir_offset + 8], 12); // Size = 12 bytes

    // 5. Section Headers (3 sections)
    let sec_table_offset = opt_offset + 240;

    // Section 1: .text
    let sec1_off = sec_table_offset;
    pe[sec1_off..sec1_off + 5].copy_from_slice(b".text");
    LittleEndian::write_u32(&mut pe[sec1_off + 8..sec1_off + 12], 0x1000); // VirtualSize
    LittleEndian::write_u32(&mut pe[sec1_off + 12..sec1_off + 16], 0x1000); // VirtualAddress
    LittleEndian::write_u32(&mut pe[sec1_off + 16..sec1_off + 20], 0x1000); // SizeOfRawData
    LittleEndian::write_u32(&mut pe[sec1_off + 20..sec1_off + 24], 0x1000); // PointerToRawData
    LittleEndian::write_u32(&mut pe[sec1_off + 36..sec1_off + 40], 0x6000_0020); // EXECUTE | READ | CODE

    // Section 2: .data
    let sec2_off = sec_table_offset + 40;
    pe[sec2_off..sec2_off + 5].copy_from_slice(b".data");
    LittleEndian::write_u32(&mut pe[sec2_off + 8..sec2_off + 12], 0x1000); // VirtualSize
    LittleEndian::write_u32(&mut pe[sec2_off + 12..sec2_off + 16], PE_DATA_RVA); // VirtualAddress
    LittleEndian::write_u32(&mut pe[sec2_off + 16..sec2_off + 20], 0x1000); // SizeOfRawData
    LittleEndian::write_u32(&mut pe[sec2_off + 20..sec2_off + 24], 0x2000); // PointerToRawData
    LittleEndian::write_u32(&mut pe[sec2_off + 36..sec2_off + 40], 0xC000_0040); // READ | WRITE | INITIALIZED_DATA

    // Section 3: .reloc
    let sec3_off = sec_table_offset + 80;
    pe[sec3_off..sec3_off + 6].copy_from_slice(b".reloc");
    LittleEndian::write_u32(&mut pe[sec3_off + 8..sec3_off + 12], 0x1000); // VirtualSize
    LittleEndian::write_u32(&mut pe[sec3_off + 12..sec3_off + 16], PE_RELOC_RVA); // VirtualAddress
    LittleEndian::write_u32(&mut pe[sec3_off + 16..sec3_off + 20], 0x1000); // SizeOfRawData
    LittleEndian::write_u32(&mut pe[sec3_off + 20..sec3_off + 24], 0x3000); // PointerToRawData
    LittleEndian::write_u32(&mut pe[sec3_off + 36..sec3_off + 40], 0x4200_0040); // READ | DISCARDABLE | INITIALIZED_DATA

    // 6. Machine Code in .text (Offset 0x1000)
    let msg_va = PE_IMAGE_BASE + PE_DATA_RVA as u64;
    let msg_len: u64 = 46; // "Hello from Nexus OS Ring 3 (Windows PE32+)!\n\0" length

    let mut code: Vec<u8> = Vec::new();

    // 1. Verify TEB and PEB access through GS base MSR:
    // mov rax, qword ptr gs:[0x30] (TEB self pointer)
    code.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00]);
    // mov rbx, qword ptr gs:[0x60] (PEB pointer)
    code.extend_from_slice(&[0x65, 0x48, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00]);

    // 2. NtWriteFile (SSN 0x0008)
    // Setup stack frame (48 bytes shadow + stack args)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x48]); // sub rsp, 0x48

    // mov rdx, msg_va (Buffer pointer in RDX)
    code.extend_from_slice(&[0x48, 0xBA]);
    code.extend_from_slice(&msg_va.to_le_bytes());

    // mov [rsp + 0x30], rdx
    code.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, 0x30]);

    // mov qword ptr [rsp + 0x38], msg_len
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x38]);
    code.extend_from_slice(&(msg_len as u32).to_le_bytes());

    // mov r10, 1 (FileHandle = stdout)
    code.extend_from_slice(&[0x49, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);
    // mov r8, msg_len
    code.extend_from_slice(&[0x49, 0xC7, 0xC0]);
    code.extend_from_slice(&(msg_len as u32).to_le_bytes());
    // mov eax, 0x0008 (NtWriteFile)
    code.extend_from_slice(&[0xB8, 0x08, 0x00, 0x00, 0x00]);
    // syscall
    code.extend_from_slice(&[0x0F, 0x05]);

    // add rsp, 0x48
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x48]);

    // 3. NtYieldExecution (SSN 0x0050)
    // mov eax, 0x0050
    code.extend_from_slice(&[0xB8, 0x50, 0x00, 0x00, 0x00]);
    // syscall
    code.extend_from_slice(&[0x0F, 0x05]);

    // 4. NtTerminateProcess (SSN 0x002C)
    // mov r10, -1 (ProcessHandle: Current Process)
    code.extend_from_slice(&[0x49, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF]);
    // xor edx, edx (ExitStatus: 0)
    code.extend_from_slice(&[0x31, 0xD2]);
    // mov eax, 0x002C (NtTerminateProcess)
    code.extend_from_slice(&[0xB8, 0x2C, 0x00, 0x00, 0x00]);
    // syscall
    code.extend_from_slice(&[0x0F, 0x05]);

    // hlt loop
    code.extend_from_slice(&[0xF4, 0xEB, 0xFD]);

    pe[0x1000..0x1000 + code.len()].copy_from_slice(&code);

    // 7. Data in .data (Offset 0x2000)
    let msg = b"Hello from Nexus OS Ring 3 (Windows PE32+)!\n\0";
    pe[0x2000..0x2000 + msg.len()].copy_from_slice(msg);

    // 8. Relocations in .reloc (Offset 0x3000)
    // Page RVA = 0x1000
    // Offset of msg_va in code:
    // 9 bytes (teb) + 9 bytes (peb) + 4 bytes (sub rsp) + 2 bytes (mov rdx opcode) = 24 (0x18)
    let reloc_offset_in_page = 0x18u16;
    let reloc_entry = (10u16 << 12) | reloc_offset_in_page; // IMAGE_REL_BASED_DIR64

    LittleEndian::write_u32(&mut pe[0x3000..0x3004], 0x1000); // PageRVA
    LittleEndian::write_u32(&mut pe[0x3004..0x3008], 12); // BlockSize = 12
    LittleEndian::write_u16(&mut pe[0x3008..0x300A], reloc_entry);
    LittleEndian::write_u16(&mut pe[0x300A..0x300C], 0); // Padding

    pe
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_loader::pe::PeImage;

    #[test]
    fn test_ring3_pe_payload_parsing_and_relocs() {
        let pe_bytes = generate_ring3_pe_payload();
        let pe = PeImage::parse(&pe_bytes).expect("Valid PE parsing");

        assert_eq!(pe.image_base, PE_IMAGE_BASE);
        assert_eq!(pe.sections.len(), 3);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[1].name, ".data");
        assert_eq!(pe.sections[2].name, ".reloc");

        let relocs = pe.parse_relocations(&pe_bytes).expect("Parse relocations");
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].page_rva, 0x1000);
        assert_eq!(relocs[0].entries.len(), 2);
        assert_eq!(relocs[0].entries[0].rel_type, 10); // DIR64
    }
}
