//! PR-2: o loader de drivers NT falha fechado.
//!
//! Cada teste corrompe um campo específico de um `.sys` real e exige um erro de
//! carga exato. Todos os testes de rejeição têm um controle positivo: a mesma
//! imagem sem a mutação carrega (ver `pristine_images_load`), então uma
//! rejeição só passa se for causada pela mutação.
//!
//! `reloc_driver.sys` (tests/fixtures/nt_driver/reloc) tem uma tabela de ponteiros
//! absolutos (3 entradas DIR64). O `DriverEntry` dele confere, em tempo de
//! execução, cada ponteiro relocado contra o endereço calculado relativo ao RIP.

use byteorder::{ByteOrder, LittleEndian as LE};
use nexus_loader::driver::IMAGE_FILE_RELOCS_STRIPPED;
use nexus_loader::pe::{IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT};
use nexus_loader::{LoaderError, NtDriverError, NtDriverHost, PeImage};
use nexus_types::driver::{UnicodeString, STATUS_SUCCESS};

const RELOC_DRIVER: &[u8] =
    include_bytes!("../../../tests/fixtures/nt_driver/reloc/reloc_driver.sys");
const NEXUS_DRIVER: &[u8] = include_bytes!("../../../tests/fixtures/nt_driver/nexus_driver.sys");
const STANDARD_WDM: &[u8] = include_bytes!("../../../tests/fixtures/nt_driver/standard_wdm.sys");

/// Códigos de erro do `DriverEntry` de reloc_driver.c.
const STATUS_RELOC_DATA_PTR: i32 = 0xC0DE0001u32 as i32;
const PREFERRED_BASE: u64 = 0x1_4000_0000;
/// Uma mutação nomeada aplicada sobre uma cópia da imagem.
type Mutation = (&'static str, Box<dyn Fn(&mut Vec<u8>)>);

const CORRUPTED: NtDriverError = NtDriverError::Loader(LoaderError::CorruptedBinary);

fn opt_off(b: &[u8]) -> usize {
    LE::read_u32(&b[60..64]) as usize + 24
}
fn file_hdr_off(b: &[u8]) -> usize {
    LE::read_u32(&b[60..64]) as usize + 4
}
fn data_dir_off(b: &[u8], index: usize) -> usize {
    opt_off(b) + 112 + index * 8
}
fn section_hdr_off(b: &[u8], name: &str) -> usize {
    let size_of_opt = LE::read_u16(&b[file_hdr_off(b) + 16..file_hdr_off(b) + 18]) as usize;
    let pe = PeImage::parse(b).unwrap();
    let index = pe.sections.iter().position(|s| s.name == name).unwrap();
    opt_off(b) + size_of_opt + index * 40
}
fn data_dir(b: &[u8], index: usize) -> (u32, u32) {
    let o = data_dir_off(b, index);
    (LE::read_u32(&b[o..o + 4]), LE::read_u32(&b[o + 4..o + 8]))
}
fn rva_to_file(b: &[u8], rva: u32) -> usize {
    PeImage::parse(b).unwrap().rva_to_file_offset(rva).unwrap()
}
fn load(b: &[u8]) -> Result<nexus_loader::LoadedDriver, NtDriverError> {
    NtDriverHost::new().load_driver(b, "\\Driver\\FailClosed", "\\Registry\\Test")
}
fn load_err(b: &[u8]) -> NtDriverError {
    match load(b) {
        Ok(_) => panic!("imagem corrompida foi carregada"),
        Err(e) => e,
    }
}

#[test]
fn pristine_images_load() {
    for bytes in [RELOC_DRIVER, NEXUS_DRIVER, STANDARD_WDM] {
        load(bytes).expect("controle positivo: imagem íntegra deve carregar");
    }
}

#[test]
fn reloc_fixture_really_has_dir64_relocations() {
    // Evita repetir o FP10: a fixture precisa ter um diretório .reloc não vazio.
    let pe = PeImage::parse(RELOC_DRIVER).unwrap();
    assert_eq!(pe.image_base, PREFERRED_BASE);
    let blocks = pe.parse_relocations(RELOC_DRIVER).unwrap();
    let dir64 = blocks
        .iter()
        .flat_map(|b| &b.entries)
        .filter(|e| e.rel_type == nexus_loader::pe::IMAGE_REL_BASED_DIR64)
        .count();
    assert_eq!(
        dir64, 3,
        "reloc_driver.c tem exatamente 3 ponteiros absolutos"
    );
}

#[test]
fn relocations_are_applied_and_verified_by_driver_entry() {
    let mut driver = load(RELOC_DRIVER).unwrap();
    assert_ne!(
        driver.image_base, PREFERRED_BASE,
        "o host deve rebasear a imagem"
    );
    assert_eq!(driver.relocations_applied, 3);

    // Verificação independente do código do driver: cada slot DIR64 aponta para
    // image_base + (valor original - ImageBase preferida).
    let pe = PeImage::parse(RELOC_DRIVER).unwrap();
    for block in pe.parse_relocations(RELOC_DRIVER).unwrap() {
        for e in block.entries.iter().filter(|e| e.rel_type == 10) {
            let rva = block.page_rva + e.offset as u32;
            let original = LE::read_u64(&RELOC_DRIVER[rva_to_file(RELOC_DRIVER, rva)..][..8]);
            let mapped = LE::read_u64(&driver.buffer.as_slice()[rva as usize..][..8]);
            assert_eq!(mapped, original - PREFERRED_BASE + driver.image_base);
        }
    }

    // O próprio driver compara os ponteiros relocados com endereços RIP-relativos
    // e chama uma função através de um ponteiro relocado.
    let (reg, _backing) = UnicodeString::from_str_vec("\\Registry\\Test");
    assert_eq!(unsafe { driver.init(&reg) }, STATUS_SUCCESS);
}

#[test]
fn missing_relocations_are_detected_by_the_driver_itself() {
    // Controle negativo do teste acima: sem diretório de relocações (e sem a flag
    // RELOCS_STRIPPED) o loader não tem o que aplicar, e o DriverEntry PRECISA
    // detectar o ponteiro não corrigido. Prova que o teste positivo pode falhar.
    let mut b = RELOC_DRIVER.to_vec();
    let o = data_dir_off(&b, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    b[o..o + 8].fill(0);
    let mut driver = load(&b).unwrap();
    assert_eq!(driver.relocations_applied, 0);
    let (reg, _backing) = UnicodeString::from_str_vec("\\Registry\\Test");
    assert_eq!(unsafe { driver.init(&reg) }, STATUS_RELOC_DATA_PTR);
}

#[test]
fn stripped_relocations_cannot_be_rebased() {
    for bytes in [RELOC_DRIVER, NEXUS_DRIVER] {
        let mut b = bytes.to_vec();
        let o = file_hdr_off(&b) + 18;
        let flags = LE::read_u16(&b[o..o + 2]) | IMAGE_FILE_RELOCS_STRIPPED;
        LE::write_u16(&mut b[o..o + 2], flags);
        assert_eq!(load_err(&b), NtDriverError::RelocationsStripped);
    }
}

#[test]
fn corrupted_import_directory_is_rejected() {
    // E1 da auditoria: antes, parse_imports falhava e load_driver carregava mesmo assim.
    for bytes in [RELOC_DRIVER, NEXUS_DRIVER, STANDARD_WDM] {
        let mut b = bytes.to_vec();
        let o = data_dir_off(&b, IMAGE_DIRECTORY_ENTRY_IMPORT);
        LE::write_u32(&mut b[o..o + 4], 0x7FFF_0000);
        assert_eq!(load_err(&b), CORRUPTED);
    }
}

#[test]
fn import_records_with_bad_pointers_are_rejected() {
    let (imp_rva, _) = data_dir(RELOC_DRIVER, IMAGE_DIRECTORY_ENTRY_IMPORT);
    let desc = rva_to_file(RELOC_DRIVER, imp_rva);

    // Nome da DLL fora da imagem.
    let mut b = RELOC_DRIVER.to_vec();
    LE::write_u32(&mut b[desc + 12..desc + 16], 0x00FF_0000);
    assert_eq!(load_err(&b), CORRUPTED);

    // FirstThunk (IAT) = 0.
    let mut b = RELOC_DRIVER.to_vec();
    LE::write_u32(&mut b[desc + 16..desc + 20], 0);
    assert_eq!(load_err(&b), CORRUPTED);

    // Thunk de nome apontando para fora da imagem (OriginalFirstThunk[0]).
    let mut b = RELOC_DRIVER.to_vec();
    let oft = LE::read_u32(&b[desc..desc + 4]);
    let thunk = rva_to_file(&b, oft);
    LE::write_u64(&mut b[thunk..thunk + 8], 0x00FF_0000);
    assert_eq!(load_err(&b), CORRUPTED);

    // Diretório truncado: sem o descritor nulo terminador.
    let mut b = RELOC_DRIVER.to_vec();
    let o = data_dir_off(&b, IMAGE_DIRECTORY_ENTRY_IMPORT);
    LE::write_u32(&mut b[o + 4..o + 8], 20);
    assert_eq!(load_err(&b), CORRUPTED);
}

#[test]
fn unknown_import_is_rejected_by_name() {
    let mut b = RELOC_DRIVER.to_vec();
    let at = b
        .windows(16)
        .position(|w| w == b"KeGetCurrentIrql")
        .expect("nome do import na fixture");
    b[at..at + 16].copy_from_slice(b"KeGetCurrentIrqX");
    assert_eq!(
        load_err(&b),
        NtDriverError::UnresolvedImport {
            dll: "NTOSKRNL.EXE".into(),
            function: "KeGetCurrentIrqX".into()
        }
    );
}

#[test]
fn corrupted_relocation_directory_is_rejected() {
    // E2 da auditoria: diretório apontando para fora da imagem.
    let mut b = RELOC_DRIVER.to_vec();
    let o = data_dir_off(&b, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    LE::write_u32(&mut b[o..o + 4], 0x7FFF_0000);
    assert_eq!(load_err(&b), CORRUPTED);

    // Também em uma imagem sem .reloc (as fixtures MSVC): RVA inválida não vira "sem relocações".
    let mut b = NEXUS_DRIVER.to_vec();
    let o = data_dir_off(&b, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    LE::write_u32(&mut b[o..o + 4], 0x7FFF_0000);
    LE::write_u32(&mut b[o + 4..o + 8], 12);
    assert_eq!(load_err(&b), CORRUPTED);
}

#[test]
fn corrupted_relocation_blocks_are_rejected() {
    let (reloc_rva, reloc_size) = data_dir(RELOC_DRIVER, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    let blk = rva_to_file(RELOC_DRIVER, reloc_rva);
    let first_entry = blk + 8;

    let cases: [Mutation; 6] = [
        (
            "SizeOfBlock < 8",
            Box::new(move |b| LE::write_u32(&mut b[blk + 4..blk + 8], 4)),
        ),
        (
            "SizeOfBlock ímpar",
            Box::new(move |b| LE::write_u32(&mut b[blk + 4..blk + 8], 13)),
        ),
        (
            "SizeOfBlock além do diretório",
            Box::new(move |b| LE::write_u32(&mut b[blk + 4..blk + 8], reloc_size + 8)),
        ),
        (
            "PageRVA desalinhada",
            Box::new(move |b| {
                let page = LE::read_u32(&b[blk..blk + 4]);
                LE::write_u32(&mut b[blk..blk + 4], page + 8);
            }),
        ),
        (
            "PageRVA fora de qualquer seção",
            Box::new(move |b| LE::write_u32(&mut b[blk..blk + 4], 0x0080_0000)),
        ),
        (
            "tipo HIGHLOW (32 bits) numa imagem PE32+",
            Box::new(move |b| {
                let e = LE::read_u16(&b[first_entry..first_entry + 2]);
                LE::write_u16(
                    &mut b[first_entry..first_entry + 2],
                    (3 << 12) | (e & 0xFFF),
                );
            }),
        ),
    ];
    for (what, mutate) in cases {
        let mut b = RELOC_DRIVER.to_vec();
        mutate(&mut b);
        assert_eq!(load_err(&b), CORRUPTED, "{what}");
    }

    // Entrada DIR64 cujo alvo (8 bytes) ultrapassa o fim da seção.
    let mut b = RELOC_DRIVER.to_vec();
    let e = LE::read_u16(&b[first_entry..first_entry + 2]);
    let sec = section_hdr_off(&b, ".data");
    let vsize = LE::read_u32(&b[sec + 8..sec + 12]).max(LE::read_u32(&b[sec + 16..sec + 20]));
    let off = (vsize - 4) & 0xFFF;
    LE::write_u16(
        &mut b[first_entry..first_entry + 2],
        (e & 0xF000) | off as u16,
    );
    assert_eq!(load_err(&b), CORRUPTED);
}

#[test]
fn writable_and_executable_section_is_rejected_at_load() {
    let mut b = RELOC_DRIVER.to_vec();
    let sec = section_hdr_off(&b, ".data");
    let flags = LE::read_u32(&b[sec + 36..sec + 40]) | 0x2000_0000;
    LE::write_u32(&mut b[sec + 36..sec + 40], flags);
    assert_eq!(load_err(&b), NtDriverError::WritableExecutableSection);
}

#[test]
fn section_layout_violations_are_rejected() {
    // SectionAlignment < 4 KiB permitiria páginas com permissões conflitantes (M7).
    let mut b = RELOC_DRIVER.to_vec();
    let o = opt_off(&b);
    LE::write_u32(&mut b[o + 32..o + 36], 0x200);
    assert_eq!(load_err(&b), CORRUPTED);

    // .rdata invadindo a página de .data (mesma página com RO e RW) -> sobreposição.
    let mut b = RELOC_DRIVER.to_vec();
    let sec = section_hdr_off(&b, ".rdata");
    LE::write_u32(&mut b[sec + 8..sec + 12], 0x1001);
    assert!(matches!(
        load_err(&b),
        NtDriverError::Loader(LoaderError::AddressOverlap(_))
    ));

    // Seção cujos dados brutos passam do fim do arquivo.
    let mut b = RELOC_DRIVER.to_vec();
    let sec = section_hdr_off(&b, ".data");
    let len = b.len() as u32;
    LE::write_u32(&mut b[sec + 20..sec + 24], len - 0x100);
    assert_eq!(load_err(&b), CORRUPTED);

    // Seção além de SizeOfImage.
    let mut b = RELOC_DRIVER.to_vec();
    let sec = section_hdr_off(&b, ".data");
    LE::write_u32(&mut b[sec + 12..sec + 16], 0x0010_0000);
    assert_eq!(load_err(&b), CORRUPTED);

    // Entry point fora de seção executável.
    let mut b = RELOC_DRIVER.to_vec();
    let o = opt_off(&b);
    LE::write_u32(&mut b[o + 16..o + 20], 0x3000);
    assert_eq!(load_err(&b), CORRUPTED);
}

#[test]
fn driver_name_buffer_stays_valid_after_load() {
    // Antes, o buffer UTF-16 de DriverObject.DriverName era liberado ao fim de load_driver.
    let driver = load(RELOC_DRIVER).unwrap();
    let name = &driver.driver_object.driver_name;
    let chars = unsafe { core::slice::from_raw_parts(name.buffer, name.length as usize / 2) };
    assert_eq!(String::from_utf16(chars).unwrap(), "\\Driver\\FailClosed");
}
