//! QEMU-only regression suite. Assertions inspect real mappings, bytes and hardware traps.
use crate::mem::{
    self,
    pmm::PMM,
    vmm::{AddressSpace, PageTable, PageTableFlags as F, VmmError},
};
use crate::task::syscall::{safe_copy_from_user, safe_copy_to_user, validate_user_buffer};
use crate::task::{self, Process, ProcessError, ProcessState, RunOutcome, Scheduler};
use nexus_types::{errno::Errno, ProcessId, VirtualAddress as VA};
const COMMON: u64 = 0x6000000000;
pub(crate) fn assert_kernel_fx() {
    let mut mxcsr = 0u32;
    let mut control = 0u16;
    unsafe {
        core::arch::asm!("stmxcsr [{}]", in(reg) &mut mxcsr, options(nostack));
        core::arch::asm!("fnstcw [{}]", in(reg) &mut control, options(nostack));
        let saved = core::ptr::read(&raw const task::KERNEL_SAVED_CTX);
        let expected_mxcsr = u32::from_le_bytes(saved.fx.0[24..28].try_into().unwrap());
        let expected_control = u16::from_le_bytes(saved.fx.0[..2].try_into().unwrap());
        if mxcsr != expected_mxcsr || control != expected_control {
            serial_println!(
                "[KERNEL_FX_MISMATCH] mxcsr={:#x} expected={:#x} control={:#x} expected={:#x}",
                mxcsr,
                expected_mxcsr,
                control,
                expected_control
            );
        }
        assert_eq!(
            mxcsr,
            u32::from_le_bytes(saved.fx.0[24..28].try_into().unwrap())
        );
        assert_eq!(
            control,
            u16::from_le_bytes(saved.fx.0[..2].try_into().unwrap())
        );
    }
}
const ELF: [&[u8]; 16] = [
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-0.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-1.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-2.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-3.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-4.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-5.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-6.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-7.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-8.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-9.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-10.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-11.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-12.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-13.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-14.elf")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/elf-15.elf")),
];
const PE: [&[u8]; 16] = [
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-0.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-1.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-2.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-3.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-4.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-5.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-6.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-7.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-8.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-9.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-10.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-11.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-12.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-13.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-14.exe")),
    include_bytes!(concat!(env!("NEXUS_FIXTURES_DIR"), "/pe-15.exe")),
];
fn kernel() -> AddressSpace {
    AddressSpace::from_pml4(
        mem::KERNEL_ADDRESS_SPACE
            .lock()
            .as_ref()
            .unwrap()
            .pml4_frame(),
    )
}
fn spawn(nt: bool, mode: usize, id: u64) -> Process {
    let k = kernel();
    let mut pmm = PMM.lock();
    if nt {
        Process::spawn_pe(ProcessId(id), "external.exe", PE[mode], &k, &mut pmm)
    } else {
        Process::spawn_elf(ProcessId(id), "external.elf", ELF[mode], &k, &mut pmm)
    }
    .expect("external compiler fixture must load")
}
fn reap(process: &mut Process) {
    process
        .release(&mut PMM.lock())
        .expect("reap inactive process");
}
fn counts() -> (usize, usize) {
    (PMM.lock().free_frames(), mem::heap::used_bytes())
}
fn check(name: &str) {
    serial_println!("\nNEXUS_CHECK:{}:PASS", name);
}
fn attach(process: &mut Process, nt: bool) {
    let mut initial = [0; 264];
    initial[..8].copy_from_slice(&(if nt { 0x1111u64 } else { 0x2222u64 }).to_le_bytes());
    initial[256..264].copy_from_slice(&0x3333u64.to_le_bytes());
    process
        .map_validation_page(COMMON, &initial, &mut PMM.lock())
        .unwrap();
    if !nt {
        process.threads[0].fs_base = COMMON + 256;
        process.threads[0].registers.fs_base = COMMON + 256;
    }
}
fn value(process: &Process, va: u64) -> u64 {
    let pa = process.address_space.translate(VA::new(va)).unwrap();
    unsafe { core::ptr::read_unaligned(pa.as_u64() as *const u64) }
}
fn msrs() {
    unsafe {
        assert_eq!(
            crate::syscall::rdmsr(crate::syscall::IA32_STAR_MSR),
            0x0013000800000000
        );
        assert_eq!(
            crate::syscall::rdmsr(crate::syscall::IA32_LSTAR_MSR),
            task::syscall::asm_syscall_entry as *const () as u64
        );
        assert_eq!(
            crate::syscall::rdmsr(crate::syscall::IA32_SFMASK_MSR),
            crate::syscall::SFMASK_FLAGS
        );
        assert_eq!(
            crate::syscall::rdmsr(crate::syscall::IA32_EFER_MSR) & 0x801,
            0x801
        );
        let cr0: u64;
        let cr4: u64;
        let flags: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        core::arch::asm!("pushfq; pop {}", out(reg) flags);
        assert_ne!(cr0 & (1 << 16), 0);
        assert_eq!(cr4 & ((1 << 18) | (1 << 16) | (1 << 7)), 0);
        let features = core::arch::x86_64::__cpuid_count(7, 0).ebx;
        if features & (1 << 7) != 0 {
            assert_ne!(cr4 & (1 << 20), 0);
        }
        if features & (1 << 20) != 0 {
            assert_ne!(cr4 & (1 << 21), 0);
        }
        assert_eq!(flags & 0x200, 0);
    }
    check("msrs");
}
fn permissions_and_context() {
    let baseline = counts();
    {
        let mut win = spawn(true, 0, 1);
        let mut lin = spawn(false, 0, 2);
        attach(&mut win, true);
        attach(&mut lin, false);
        let k = kernel();
        let kernel_code = k
            .mapping(VA::new(crate::nexus_kernel_init as *const () as u64))
            .unwrap();
        assert!(!kernel_code
            .flags
            .intersects(F::USER | F::WRITABLE | F::NO_EXECUTE));
        for address in [
            &raw const mem::KERNEL_ADDRESS_SPACE as u64,
            k.pml4_frame().as_u64(),
            &raw const crate::arch::x86_64::KERNEL_STACK as u64,
        ] {
            let data = k.mapping(VA::new(address)).unwrap();
            assert!(data.flags.contains(F::WRITABLE | F::NO_EXECUTE));
            assert!(!data.flags.contains(F::USER));
        }
        assert_ne!(
            win.address_space.pml4_frame(),
            lin.address_space.pml4_frame()
        );
        assert_ne!(
            win.address_space.translate(VA::new(COMMON)),
            lin.address_space.translate(VA::new(COMMON))
        );
        assert!(k.translate(VA::new(COMMON)).is_none());
        for process in [&win, &lin] {
            let code = process.address_space.mapping(process.entry_point).unwrap();
            assert!(code.flags.contains(F::USER));
            assert!(!code.flags.intersects(F::WRITABLE | F::NO_EXECUTE));
            let stack = process
                .address_space
                .mapping(VA::new(task::USER_STACK_TOP - 4096))
                .unwrap();
            assert!(stack.flags.contains(F::USER | F::WRITABLE | F::NO_EXECUTE));
            assert!(process
                .address_space
                .mapping(VA::new(task::USER_STACK_TOP - 20480))
                .is_none());
            assert_eq!(
                validate_user_buffer(0x100000, 8, false, &process.address_space),
                Err(Errno::EFAULT)
            );
            assert_eq!(
                validate_user_buffer(COMMON + 4092, 8, false, &process.address_space),
                Err(Errno::EFAULT)
            );
            assert_eq!(
                safe_copy_to_user(
                    process.entry_point.as_u64(),
                    &[0xcc],
                    &process.address_space
                ),
                Err(Errno::EFAULT)
            );
            let pointer = task::USER_STACK_TOP - 4100;
            let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
            safe_copy_to_user(pointer, &bytes, &process.address_space).unwrap();
            let mut actual = [0; 8];
            assert_eq!(
                safe_copy_from_user(&mut actual, pointer, 8, &process.address_space),
                Ok(8)
            );
            assert_eq!(actual, bytes);
            // A supervisor ancestor must override USER/WRITE on a present user leaf.
            unsafe {
                let root = &mut *(process.address_space.pml4_frame().as_u64() as *mut PageTable);
                let old = root.entries[0];
                root.entries[0].0 &= !F::USER.bits();
                assert_eq!(
                    validate_user_buffer(COMMON, 8, false, &process.address_space),
                    Err(Errno::EFAULT)
                );
                root.entries[0] = old;
                root.entries[0].0 &= !F::WRITABLE.bits();
                assert_eq!(
                    validate_user_buffer(COMMON, 8, true, &process.address_space),
                    Err(Errno::EFAULT)
                );
                root.entries[0] = old;
            }
        }
        assert!(win
            .address_space
            .mapping(VA::new(task::pe_payload::PE_IMAGE_BASE))
            .unwrap()
            .flags
            .contains(F::NO_EXECUTE));
        check("permissions");
        for i in 0..8 {
            for (process, initial) in [(&mut win, 0x1111u64), (&mut lin, 0x2222u64)] {
                assert_eq!(
                    task::run_user_process(process, &k),
                    Ok(task::YIELD_EXIT_CODE)
                );
                assert_eq!(value(process, COMMON), initial + i + 1);
                assert_eq!(process.state, ProcessState::Yielded);
                assert_eq!(process.threads[0].state, ProcessState::Yielded);
                assert_eq!(process.threads[0].registers.rax, 0);
                assert_eq!(
                    process.threads[0].gs_base,
                    if process.personality.is_windows() {
                        task::TEB_USER_VADDR
                    } else {
                        0
                    }
                );
                assert_eq!(
                    process.threads[0].fs_base,
                    if process.personality.is_windows() {
                        0
                    } else {
                        COMMON + 256
                    }
                );
                unsafe {
                    assert_eq!(crate::syscall::rdmsr(0xc0000100), 0);
                    assert_eq!(crate::syscall::rdmsr(0xc0000101), 0);
                }
            }
        }
        for process in [&mut win, &mut lin] {
            assert_eq!(task::run_user_process(process, &k), Ok(0));
            assert_eq!(process.outcome, Some(RunOutcome::Exit(0)));
            reap(process);
        }
        assert_eq!(
            k.mapping(VA::new(0x100000)).unwrap().flags & F::USER,
            F::empty()
        );
    }
    assert_eq!(counts(), baseline);
    check("context");
}
fn fault_cases() {
    let baseline = counts();
    for nt in [true, false] {
        for mode in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15] {
            serial_println!("[CASE] nt={} mode={}", nt, mode);
            {
                let mut victim = spawn(!nt, 10, 10);
                let victim_before = value(&victim, victim.entry_point.as_u64());
                let mut attacker = spawn(nt, mode, 11);
                let k = kernel();
                let vector = match mode {
                    7 => 6,
                    8 | 14 | 15 => 13,
                    9 => 0,
                    _ => 14,
                };
                unsafe {
                    crate::arch::x86_64::idt::LAST_FAULT_INFO = None;
                }
                assert_eq!(
                    task::run_user_process(&mut attacker, &k),
                    Err(ProcessError::Fault(vector))
                );
                let (actual, cr2, error) = unsafe {
                    core::ptr::read(&raw const crate::arch::x86_64::idt::LAST_FAULT_INFO)
                }
                .unwrap();
                assert_eq!(actual, vector);
                if vector == 14 {
                    match mode {
                        1 | 2 => {
                            assert_eq!(cr2, if nt { 0x100001000 } else { 0x140001000 });
                            assert_eq!(error & 7, if mode == 1 { 4 } else { 6 });
                        }
                        3 | 4 => {
                            assert_eq!(cr2, 0x100000);
                            assert_eq!(error & 7, if mode == 3 { 5 } else { 7 });
                        }
                        5 | 13 => assert_eq!(error & 0x15, 0x15),
                        6 => {
                            let code = attacker.address_space.mapping(VA::new(cr2)).unwrap();
                            assert!(code.flags.contains(F::USER));
                            assert!(!code.flags.intersects(F::WRITABLE | F::NO_EXECUTE));
                            assert_eq!(error & 7, 7);
                        }
                        _ => unreachable!(),
                    }
                }
                assert_eq!(value(&victim, victim.entry_point.as_u64()), victim_before);
                reap(&mut attacker);
                assert_eq!(task::run_user_process(&mut victim, &k), Ok(14));
                assert_eq!(victim.outcome, Some(RunOutcome::Exit(14)));
                reap(&mut victim);
            }
            assert_eq!(counts(), baseline);
        }
    }
    check("faults");
    for nt in [false, true] {
        for (mode, code) in [(10, 14), (11, -1), (12, task::YIELD_EXIT_CODE)] {
            let mut process = spawn(nt, mode, 12);
            assert_eq!(task::run_user_process(&mut process, &kernel()), Ok(code));
            assert_eq!(process.outcome, Some(RunOutcome::Exit(code)));
            reap(&mut process);
        }
    }
    // #UD exactly at page boundary: diagnostics must not read into an absent next page.
    {
        use byteorder::{ByteOrder, LittleEndian as LE};
        let mut bytes = task::elf_payload::generate_faulting_elf_payload();
        LE::write_u64(
            &mut bytes[24..32],
            task::elf_payload::ELF_USER_ENTRY_VADDR + 4094,
        );
        LE::write_u64(&mut bytes[96..104], 4096);
        LE::write_u64(&mut bytes[104..112], 4096);
        bytes[4096..8192].fill(0);
        bytes[8190..8192].copy_from_slice(&[0x0f, 0x0b]);
        let mut process = Process::spawn_elf(
            ProcessId(13),
            "ud-boundary",
            &bytes,
            &kernel(),
            &mut PMM.lock(),
        )
        .unwrap();
        assert_eq!(
            task::run_user_process(&mut process, &kernel()),
            Err(ProcessError::Fault(6))
        );
        reap(&mut process);
    }
    assert_eq!(counts(), baseline);
    check("exit-and-boundary");
}
fn rollback_and_oom() {
    let baseline = counts();
    {
        use byteorder::{ByteOrder, LittleEndian as LE};
        let mut collision = task::elf_payload::generate_faulting_elf_payload();
        LE::write_u64(&mut collision[24..32], 0x100000);
        LE::write_u64(&mut collision[80..88], 0x100000);
        assert!(Process::spawn_elf(
            ProcessId(20),
            "collision",
            &collision,
            &kernel(),
            &mut PMM.lock()
        )
        .is_err());
    }
    assert_eq!(counts(), baseline);
    {
        let mut held = Vec::with_capacity(PMM.lock().free_frames());
        let k = kernel();
        let mut pmm = PMM.lock();
        while pmm.free_frames() > 3 {
            held.push(pmm.allocate_frame().unwrap());
        }
        let before = pmm.free_frames();
        assert!(Process::spawn_elf(ProcessId(21), "oom", ELF[0], &k, &mut pmm).is_err());
        assert_eq!(pmm.free_frames(), before);
        for frame in held {
            pmm.free_frame(frame);
        }
    }
    assert_eq!(counts(), baseline);
    {
        let mut held = Vec::with_capacity(PMM.lock().free_frames());
        let mut pmm = PMM.lock();
        let mut space = AddressSpace::new_user(&kernel(), &mut pmm).unwrap();
        let leaf = pmm.allocate_zeroed_frame().unwrap();
        let root_before = unsafe { *(space.pml4_frame().as_u64() as *const PageTable) };
        while pmm.free_frames() > 1 {
            held.push(pmm.allocate_frame().unwrap());
        }
        assert_eq!(
            space.map_page(
                VA::new(0x500000000000),
                leaf,
                F::USER | F::NO_EXECUTE,
                &mut pmm
            ),
            Err(VmmError::FrameAllocationFailed)
        );
        assert_eq!(pmm.free_frames(), 1);
        let root_after = unsafe { &*(space.pml4_frame().as_u64() as *const PageTable) };
        assert_eq!(root_before.entries, root_after.entries);
        for frame in held {
            pmm.free_frame(frame);
        }
        pmm.free_frame(leaf);
        space.destroy(&mut pmm).unwrap();
    }
    assert_eq!(counts(), baseline);
    check("rollback-oom");
}
fn stress() {
    let baseline = counts();
    for cycle in 0..64 {
        {
            let mut scheduler = Scheduler::new();
            let mut win = spawn(true, 0, 100 + cycle * 2);
            let mut lin = spawn(false, 0, 101 + cycle * 2);
            attach(&mut win, true);
            attach(&mut lin, false);
            scheduler.add_process(win);
            scheduler.add_process(lin);
            scheduler.run_all(&kernel()).unwrap();
            assert_eq!(scheduler.current_idx, 18);
            for p in &scheduler.processes {
                assert_eq!(p.outcome, Some(RunOutcome::Exit(0)));
                assert_eq!(p.state, ProcessState::Terminated(0));
                assert!(p.threads.is_empty());
                assert_eq!(p.address_space.pml4_frame().as_u64(), 0);
            }
            // Re-running an empty/terminated queue must not spin.
            scheduler.run_all(&kernel()).unwrap();
        }
        assert_eq!(counts(), baseline, "leak at cycle {cycle}");
    }
    serial_println!(
        "NEXUS_STRESS:cycles=64:processes=128:yields=1024:frames={}:heap={}",
        baseline.0,
        baseline.1
    );
    check("stress");
}

fn loader_bytes() {
    use byteorder::{ByteOrder, LittleEndian as LE};
    let baseline = counts();
    {
        let mut bytes = task::elf_payload::generate_faulting_elf_payload();
        let va = task::elf_payload::ELF_USER_ENTRY_VADDR;
        LE::write_u64(&mut bytes[24..32], va + 3);
        LE::write_u64(&mut bytes[72..80], 4099);
        LE::write_u64(&mut bytes[80..88], va + 3);
        LE::write_u64(&mut bytes[96..104], 5);
        LE::write_u64(&mut bytes[104..112], 4099);
        bytes[4096..].fill(0xee);
        bytes[4099..4104].copy_from_slice(&[1, 2, 3, 4, 5]);
        let mut process = Process::spawn_elf(
            ProcessId(99),
            "unaligned-bss",
            &bytes,
            &kernel(),
            &mut PMM.lock(),
        )
        .unwrap();
        let mut actual = [0; 16];
        safe_copy_from_user(&mut actual, va, 16, &process.address_space).unwrap();
        assert_eq!(actual, [0, 0, 0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut tail = [0xff; 6];
        safe_copy_from_user(&mut tail, va + 4096, 6, &process.address_space).unwrap();
        assert_eq!(tail, [0; 6]);
        let old = process.threads[0].registers;
        let mut invalid = old;
        invalid.rcx = 0x800000000000;
        assert_eq!(
            task::syscall::validate_return_context(&invalid, &process.address_space),
            Err(Errno::EFAULT)
        );
        invalid = old;
        invalid.rsp = 0;
        assert_eq!(
            task::syscall::validate_return_context(&invalid, &process.address_space),
            Err(Errno::EFAULT)
        );
        reap(&mut process);
    }
    assert_eq!(counts(), baseline);
    check("loader-bytes");
}
pub fn run() {
    serial_println!("NEXUS_HARDENING_BEGIN");
    msrs();
    permissions_and_context();
    fault_cases();
    rollback_and_oom();
    loader_bytes();
    stress();
    serial_println!("NEXUS_HARDENING_PASS:checks=8");
}
/// `isa-debug-exit` value written on a kernel panic (QEMU exit status 35).
pub const EXIT_CODE_PANIC: u32 = 0x11;
/// `isa-debug-exit` value written on an unrecoverable Ring 0 trap (QEMU exit status 37).
pub const EXIT_CODE_RING0_TRAP: u32 = 0x12;

/// Terminates QEMU with a failure status so the runner fails immediately instead of
/// waiting for its timeout (audit finding M8). Any value other than 0x10 is a failure.
pub fn exit_failure(code: u32) -> ! {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code, options(nomem, nostack));
        core::arch::asm!("cli; 2: hlt; jmp 2b", options(noreturn));
    }
}

/// Reports any panic on the serial port and exits QEMU with [`EXIT_CODE_PANIC`].
pub fn install_panic_exit_hook() {
    std::panic::set_hook(std::boxed::Box::new(|info| {
        serial_println!("NEXUS_PANIC: {}", info);
        exit_failure(EXIT_CODE_PANIC);
    }));
}

/// Called only after the original Phase 3 flow also verified its real outcomes.
pub fn exit_success() -> ! {
    unsafe {
        core::arch::asm!("out dx, eax",in("dx")0xf4u16,in("eax")0x10u32,options(nomem,nostack));
    }
    loop {
        core::hint::spin_loop();
    }
}
