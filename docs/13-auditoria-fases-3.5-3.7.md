# Relatório de auditoria de encerramento — Fases 3.5 e 3.7 do Nexus OS

- **Repositório:** `Stoltembergg/Nexus-OS`, branch `main`, commit `1d8b134` (2026-10-11 08:40 BRT, "docs: plan Nexus Update OTA and reconcile Nexus OS roadmap").
- **Data da auditoria:** 2026-10-11, entre 08:55 e 09:10 BRT.
- **Ambiente:** computador compartilhado (Linux Debian 13, x86_64). QEMU 10.0.13 (Debian), OVMF `/usr/share/ovmf/OVMF.fd`, clang/lld (Debian), MinGW-w64 (Debian), Rust estável 1.99.0 e toolchains fixas 1.90.0, 1.95.0, 1.96.0, 1.97.0 e 1.98.0.
- **Escopo:** código real, testes e evidências documentadas em `docs/09-phase3.5-kernel-hardening.md`, `docs/11-phase3.6-nt-driver-validation.md` e `docs/12-phase3.7-nt-driver-hardening.md`.
- **Restrições respeitadas:** nenhum push, nenhum PR, nenhuma implementação da Fase 4 e nenhuma mudança de arquitetura. Os arquivos versionados só foram alterados em experimentos descartáveis, todos revertidos (`git status` limpo no fim). Os patches desses experimentos estão em `logs/`.
- **Sobre o tipo de validação:** tudo o que aparece aqui como "QEMU" foi executado em um **guest QEMU/OVMF emulado (TCG)**. **Nada foi validado em hardware físico.** Este relatório não declara compatibilidade com Windows, Linux ou Vanguard.

Os logs citados (`logs/…`) foram produzidos na máquina de auditoria e não estão versionados; os comandos para reproduzi-los estão na seção 7. As correções derivadas deste relatório são entregues em PRs pequenos e sequenciais (PR-1 … PR-6).

---

## 1. Resumo executivo

| Fase | Encerrada? | Justificativa curta |
| :--- | :--- | :--- |
| **3.5 — Kernel hardening** | **NÃO** | Os 11 defeitos listados no doc 09 estão corrigidos no código, e a suíte QEMU passa **localmente**. Porém o `main` **não compila** como está: falta a dependência `libc` no host Linux, e o link UEFI falha com o Rust estável 1.99 (`wcslen`). O **CI nunca passou** (0 de 3 execuções verdes), e o próprio doc 09 continua "em andamento; não concluída", sem os resultados finais. A fase fica perto de poder ser encerrada assim que C1, C2 e C3 forem resolvidos e o CI ficar verde. |
| **3.7 — NT driver runtime hardening** | **NÃO** | O W^X dos drivers funciona de fato: comprovei lendo os PTEs no QEMU com uma sonda descartável. Mas não existe teste no repositório que prove isso. O IRQL via CR8 não tem nenhuma fonte de interrupção: não há LAPIC inicializado, não há vetores de IRQ, e o RFLAGS.IF fica sempre em 0. Os eventos e as esperas são stubs que não bloqueiam. O driver "WDM autêntico" usa structs NT definidas à mão, com offsets **incompatíveis** com o `wdm.h` real. Um driver compilado com cabeçalhos WDM reais **não carrega** (`UnresolvedImport IofCompleteRequest`). Os `.sys` versionados nunca são recompilados no CI. E o doc 12 afirma "Verificado em Hardware Real", o que não tem evidência. |

**Bloqueios críticos:** C1 a C5 (seção 2). Pelo critério de conclusão definido pelo Gabriel, **a Fase 4 não deve começar** antes de resolver C1, C2 e C3 (build e CI) e de uma decisão explícita sobre C4 e C5 (ABI WDM e IRQL com interrupções).

**O que foi comprovado (em QEMU), sem exageros:**
- Isolamento Ring 0/3, permissões efetivas USER/W/NX em todos os níveis, NX ativo (EFER.NXE), SFMASK, salvamento completo de contexto (GPRs, RFLAGS, FXSAVE, FS/GS), traps (#PF, #GP, #UD, #DE), rollback em OOM, e 64 ciclos de estresse sem vazamento de frames e heap. Validado em 3 configurações: 128 MiB/qemu64/debug, 256 MiB/max/debug e 512 MiB/max/release. Usei a toolchain 1.95.0 e repeti 128/qemu64 com a 1.98.0.
- Os dois `.sys` versionados carregam, executam `DriverEntry`, IOCTLs, READ e `DriverUnload` em Ring 0 no guest.
- W^X das seções do driver nos PTEs reais: `.text` RX, `.rdata`/`.pdata`/cabeçalho RO+NX, `.data`/`INIT` RW+NX, nenhuma página W+X e nenhuma página USER. Isso **só** foi comprovado pela sonda da auditoria (seção 6.3).
- CR0.WP: uma escrita em Ring 0 numa página RX do driver gera `#PF error=0x3`. Também foi comprovado pela sonda (seção 6.3).
- O escalonador recusa o despacho quando CR8 ≥ DISPATCH_LEVEL (`Err(UnsupportedExecution)`). Também foi comprovado pela sonda.

---

## 2. Achados, em ordem de gravidade

Escopo da correção sugerida: **P** = pequeno (até cerca de 50 linhas, local), **M** = médio (um módulo, sem mudar a arquitetura).

### Crítico

| ID | Achado | Arquivo:linha | Evidência | Correção sugerida |
| :--- | :--- | :--- | :--- | :--- |
| **C1** | O `main` não compila em host Unix: `nexus-loader` usa `libc::mmap/mprotect/munmap` sem declarar a dependência. `cargo check`, `clippy`, `test`, o `nexus-poc` e o job `ubuntu-latest` do CI falham. | `crates/nexus-loader/Cargo.toml` (sem `libc`); `crates/nexus-loader/src/driver.rs:195-274` | `logs/02-check.log` … `06-poc.log` (13× `E0433 libc`); log do CI, job "Host checks (ubuntu-latest)" | **P:** adicionar `[target.'cfg(unix)'.dependencies] libc = "0.2"` e atualizar o `Cargo.lock`. Validei de forma descartável (`logs/12-throwaway-libc.patch`): check, clippy `-D warnings` e **51 testes** (debug e release) passam, e o `nexus-poc` roda. |
| **C2** | O build UEFI quebra com o Rust estável atual (1.99.0): `rust-lld: undefined symbol: wcslen`. Não existe `rust-toolchain.toml`, então o CI (`dtolnay/rust-toolchain@stable`) pega a 1.99. Causa de fundo: o kernel linka `std` no alvo `x86_64-unknown-uefi` (`#![no_std]` só vale para `target_os = "none"`). | raiz do repo (sem `rust-toolchain.toml`); `.github/workflows/ci.yml:24,52`; `crates/nexus-kernel/src/main.rs:1-2`; `crates/nexus-kernel/src/lib.rs` (sem `no_std`) | `logs/07-uefi-build.log` (1.99 falha). Bissecção: 1.90.0, 1.95.0, 1.96.0, 1.97.0 e 1.98.0 compilam (`logs/07b-*.log`). Primeira versão que falha: **1.99.0**. | **P:** fixar a toolchain com `rust-toolchain.toml` (`channel = "1.98.0"`, `targets = ["x86_64-unknown-uefi"]`, `components = ["clippy","rustfmt"]`). A suíte QEMU passa com 1.98.0 (`logs/18-*.log`). **M (depois):** avaliar `no_std` + `alloc` para o kernel também no alvo UEFI, porque o `std` do UEFI após `ExitBootServices` é frágil. |
| **C3** | **Nenhuma** execução de CI passou: 3 de 3 falharam, incluindo o commit da Fase 3.7 (`3e6cb75`) e o `main` atual. Por isso, nenhuma das evidências QEMU dos docs 11 e 12 foi reproduzida em CI, e os artefatos `result.json` do CI vêm de um build que falhou. | `.github/workflows/ci.yml` | `logs/00-ci-github.txt` (runs 38135301788, 38136367577 e 38136397511, todos `failure`; o Windows foi `cancelled` por fail-fast) | Consequência de C1 e C2. Depois de corrigir os dois, exigir CI verde como critério de encerramento. Considerar `fail-fast: false` também na matriz de host, para que o Windows não seja cancelado. |
| **C4** | **A ABI WDM não é a ABI do Windows.** As structs em `nexus-types` e as definições à mão em `standard_wdm.c`/`nexus_driver.c` concordam entre si, mas divergem do `wdm.h` real nos campos centrais. Um driver compilado com cabeçalhos reais leria e escreveria nos offsets errados. | `crates/nexus-types/src/driver.rs:242-255` (DeviceObject), `290-323` (IoStackLocation), `346-361` (Irp); `tests/fixtures/nt_driver/standard_wdm.c:41-200`; `nexus_driver.c:30-120` | Comparação de offsets (`logs/14-abi-*.log`). Referência: cabeçalhos DDK do MinGW-w64, que **não são o WDK oficial** (ver tabela abaixo). | **M:** corrigir os layouts em `nexus-types` a partir do `wdm.h` oficial (job Windows com WDK, seção 8) e adicionar asserções estáticas de offset. Adicionar ao loader os exports que os cabeçalhos reais geram. Sem mudança de arquitetura. |
| **C5** | **O IRQL não está integrado a APIC, interrupções nem escalonamento.** O kernel executa `cli` no init e nunca habilita interrupções. O RFLAGS de Ring 3 nasce com `r11 = 2` (IF=0), e o retorno de syscall mascara o IF. Não há inicialização do LAPIC (SVR, timer), nem IOAPIC, nem desativação ou remapeamento do PIC, nem vetores ≥ 32 na IDT. O CR8 é escrito e lido de verdade, mas **não existe nenhuma interrupção mascarável que ele possa mascarar**. O "invariante de não-preempção" só se aplica a um escalonador cooperativo. O roadmap exige "real IRQ/APIC IRQL semantics" para a 3.7, e o doc 12 afirma "mascarando interrupções no nível de silício". | `crates/nexus-kernel/src/arch/x86_64/mod.rs:128` (`cli`), `:29-71` (CR8); `arch/x86_64/idt.rs:175-248` (só os vetores 0-31); `task/mod.rs:153` (`r11: 2`); `task/syscall.rs:137-138`; `docs/04-roadmap-and-phases.md:27` | Busca por `apic|lapic|8259|timer|sti` no kernel: nenhum resultado. Sonda QEMU: `AUDIT_RFLAGS_IF=0` (`logs/16-qemu-probe-serial.log`). O hardening exige `flags & 0x200 == 0` (`hardening.rs:154`). | **Decisão do Gabriel:** (a) mover a "semântica real de IRQL com interrupções" para a Fase 4 (APIC/timers) e reescrever o critério da 3.7 como "IRQL = CR8/TPR sem fontes de interrupção"; ou (b) antes de encerrar a 3.7, implementar o mínimo: LAPIC habilitado, PIC mascarado, um vetor de timer e um teste em que a interrupção fica pendente com TPR ≥ classe e é entregue ao baixar o TPR. A opção (b) coincide com o primeiro item da Fase 4. |

Offsets de C4 (x64). Referência: `ntddk.h`/`wdm.h` do MinGW-w64, compilado com `x86_64-w64-mingw32-gcc`. A confirmação definitiva tem que vir do WDK oficial.

| Campo | wdm.h (MinGW DDK) | Nexus (`nexus-types` e fixtures) |
| :--- | :--- | :--- |
| `DRIVER_OBJECT.MajorFunction` / `DriverUnload` | 0x70 / 0x68 | 0x70 / 0x68 ✔ |
| `DEVICE_OBJECT.Flags` | 0x30 | 0x28 ✘ |
| `DEVICE_OBJECT.DeviceExtension` | 0x40 | 0x30 ✘ |
| `DEVICE_OBJECT.DeviceType` | 0x48 | 0x38 ✘ |
| `sizeof(DEVICE_OBJECT)` | 0x148 | 0x48 ✘ |
| `IRP.IoStatus` | 0x30 | 0x20 ✘ |
| `IRP.UserBuffer` | 0x70 | 0x38 ✘ |
| `IRP.Tail.Overlay.CurrentStackLocation` | 0xB8 | 0x40 ✘ |
| `IO_STACK_LOCATION.DeviceIoControl.InputBufferLength` / `IoControlCode` | 0x10 / 0x18 | 0x0C / 0x10 ✘ |
| `IO_STACK_LOCATION.DeviceObject` | 0x28 | 0x20 ✘ |
| `sizeof(KEVENT)` | 0x18 | 0x18 ✔ |

### Alto

| ID | Achado | Arquivo:linha | Evidência | Correção sugerida |
| :--- | :--- | :--- | :--- | :--- |
| **A1** | O loader de drivers **descarta silenciosamente** os erros de parsing de relocações e imports (`unwrap_or_default()`). Um diretório de imports corrompido faz o driver carregar com a IAT sem patch, e o `DriverEntry` acaba saltando para um endereço inválido em Ring 0. Isso anula o "fail-closed" que `adversarial.rs` testa no parser. | `crates/nexus-loader/src/driver.rs:708`, `:729`; também `:680-683` e `:741` (cópias ou escritas fora dos limites ignoradas sem erro) | Experimento E1/E2 (`logs/13-experiments.log`): `parse_imports=Err(CorruptedBinary)` mas `load_driver_ok=true`; o mesmo vale para relocações. | **P:** propagar com `?` (`NtDriverError::Loader`) e transformar os casos fora dos limites em erro. Adicionar testes de host com os bytes do E1 e do E2. |
| **A2** | Eventos e espera são stubs. `KeWaitForSingleObject` nunca bloqueia: com timeout `NULL` (infinito) num evento não sinalizado, devolve `STATUS_TIMEOUT` (0x102) na hora. `SynchronizationEvent` não faz auto-reset. `KeSetEvent` ignora quem espera. Não há verificação de IRQL. | `crates/nexus-loader/src/driver.rs:1138-1188` | E3: `wait(unsignaled, NULL)=0x102`; duas esperas seguidas num evento de sincronização retornam `0x0`/`0x0`. | **P:** implementar o auto-reset e, com uma única thread cooperativa, tratar a espera infinita não satisfazível como erro explícito ou bugcheck (`STATUS_TIMEOUT` não serve). Documentar como "sem threads/waiters" até a Fase 4. |
| **A3** | O caminho de relocações **nunca é exercitado**. Os dois `.sys` não têm `.reloc` (DataDirectory[5] = 0/0), apesar de o doc 11 afirmar que existe uma seção `.reloc`. O loader também não rejeita uma imagem sem relocações carregada fora da `ImageBase` preferida (o delta é sempre ≠ 0). | `driver.rs:702-726`; `docs/11-phase3.6-nt-driver-validation.md:71` | Parsing dos cabeçalhos: `reloc=(0, 0)`, `ImageBase=0x140000000`, carregado em `0x5F59000` (serial do QEMU). | **P:** se `delta != 0` e não houver relocações (ou `IMAGE_FILE_RELOCS_STRIPPED`), recusar o carregamento. Adicionar uma fixture com tabela de ponteiros absolutos para exercitar DIR64. |
| **A4** | Os `.sys` versionados **nunca são recompilados nem validados contra o fonte** no CI. `scripts/build-nt-driver.py` usa um `ntoskrnl.def` feito à mão (biblioteca de import sintética), não o WDK. Um driver compilado com cabeçalhos WDM reais **não carrega**: o x64 importa `IofCompleteRequest` e `KeAcquireSpinLockRaiseToDpc`, e `KeRaiseIrql`/`KeLowerIrql`/`KeGetCurrentIrql`/`KeInitializeSpinLock` são *inline* (escrevem o CR8 diretamente), então nunca passam pelos stubs do Nexus. | `tests/fixtures/nt_driver/*.sys`, `ntoskrnl.def`; `scripts/build-nt-driver.py`; `.github/workflows/ci.yml` (sem passo de build de driver) | E9: `load_driver(audit_wdm.sys)` = `Err(UnresolvedImport { function: "IofCompleteRequest" })`. Imports reais em `logs/15-mingw-wdm-imports.log`; 4 instruções `cr8` inline no binário. Rich header e linker 14.44 confirmam que os `.sys` foram gerados com MSVC. | **M:** job `windows-latest` com WDK (seção 8), sem `.sys` versionado (só o fonte). Adicionar ao `NtoskrnlTable` os exports que os cabeçalhos reais geram. |
| **A5** | Os documentos afirmam mais do que foi provado e se contradizem. O doc 12 diz "Concluído e Verificado em **Hardware Real**", "abandonou-se qualquer modelo baseado em variáveis atômicas" (mas `CURRENT_IRQL` continua sendo escrito), "cabeçalhos WDM padrão" (as structs são definidas à mão), `DbgPrint` como "redirecionamento serial" (é um no-op) e `IoCreateSymbolicLink` como "Validado" (é um no-op). O README e o roadmap dizem que a 3.7 está "planned". O doc 11 conta 47 testes, e hoje são 51. | `docs/12-phase3.7-nt-driver-hardening.md:4,15,17,86-89`; `driver.rs:24,785-787,819,833,924-940`; `README.md:6,8,132`; `docs/04-roadmap-and-phases.md:25-27` | Leitura do código; no serial do QEMU não aparece nenhuma saída de `DbgPrint` dos drivers. | **P:** corrigir o doc 12 e marcar como "PoC em QEMU; não encerrada", alinhando com o README e o roadmap (entregável 9 do Gabriel). |

### Médio

| ID | Achado | Arquivo:linha | Evidência | Correção sugerida |
| :--- | :--- | :--- | :--- | :--- |
| M1 | `IoDeleteDevice` de um device que não é a cabeça da lista libera a memória mas deixa `NextDevice` do anterior apontando para memória liberada (use-after-free latente). | `driver.rs:909-917` | E5: `next_device aponta para device liberado: true` | **P:** remover o nó da lista em qualquer posição. |
| M2 | `IoCreateDevice` ignora `DeviceExtensionSize`: `DeviceExtension` fica nulo. Todo driver real que usa a extensão quebra. | `driver.rs:870-902` | E6: `DeviceExtension nulo com size=64: true` | **P:** alocar a extensão zerada e liberar em `IoDeleteDevice`. |
| M3 | `LoadedDriver::unload()` zera `driver_object.device_object` por conta própria. Isso esconde devices que o driver não removeu e torna as asserções de unload incapazes de falhar. | `driver.rs:616-624` | Leitura do código; ver FP3. | **P:** não zerar; depois do `DriverUnload`, falhar se ainda houver devices ou alocações de pool pertencentes ao driver. |
| M4 | `KeRaiseIrql` aceita um IRQL menor que o atual, e `KeLowerIrql` aceita um maior (o NT faz bugcheck `IRQL_NOT_GREATER_OR_EQUAL`/`IRQL_NOT_LESS_OR_EQUAL`). | `driver.rs:809-834` | E4: `raise(2->0) => 0; lower(0->15) => 15` | **P:** validar a direção e levar ao caminho de bugcheck. |
| M5 | A aplicação do W^X é **pulada em silêncio** se `KERNEL_ADDRESS_SPACE` for `None`. Não existe teste no repo que leia os PTEs, e o runner não verifica a linha de W^X. | `crates/nexus-kernel/src/driver_host.rs:61-81`, `:225-245` | A sonda da auditoria provou que funciona hoje (seção 6.3), mas nada impede uma regressão. | **P:** tornar a aplicação obrigatória (`expect`) e incorporar a sonda de leitura de PTE ao `hardening.rs` como `NEXUS_CHECK:driver-wx`. |
| M6 | Sem contabilidade de pool/heap por driver. Vazamentos depois do `DriverUnload` passam despercebidos, e o ciclo de vida do driver fica fora da verificação `counts()` do hardening. | `driver_host.rs` (todo); `hardening.rs:99-101` | Leitura do código | **P:** comparar `heap::used_bytes()` antes do carregamento e depois do unload e do drop. |
| M7 | O loader não valida `SectionAlignment ≥ 4 KiB`. Se uma página for compartilhada por seções com permissões diferentes, vale a última escrita (código pode virar NX, ou dados podem virar RX). Não há W+X, mas o comportamento fica incorreto. | `driver.rs:510-543` | Leitura do código (as fixtures usam 0x1000) | **P:** rejeitar alinhamento < 4096 ou páginas com permissões conflitantes. |
| M8 | Uma falha em Ring 0 (por exemplo, de um driver) executa `cli; hlt` sem sinalizar falha ao QEMU. O runner fica esperando até o timeout. | `arch/x86_64/idt.rs:167-173` | Sonda do WP: o `#PF` foi registrado e o runner esperou 40 s até o timeout (`logs/17-qemu-wp-probe.log`). | **P:** com `hardening-tests`, escrever um código de falha (≠ 0x10) em `isa-debug-exit`. |
| M9 | O kernel usa `std` no alvo UEFI (causa raiz de C2), e o `panic` no UEFI usa o `panic_abort` do `std`. | `crates/nexus-kernel/src/main.rs:1-15` | `logs/07-uefi-build.log` (o `libstd` aparece na linha do linker) | **M:** migrar para `no_std` + `alloc` em ambos os alvos, com um `panic_handler` próprio que reporte via serial e `isa-debug-exit`. |

### Baixo

| ID | Achado | Arquivo:linha | Correção |
| :--- | :--- | :--- | :--- |
| B1 | A checagem de CR8 ≥ DISPATCH só existe em `Scheduler::run_all`; `run_user_process` entra em Ring 3 sem verificar. | `task/mod.rs:627` vs. `:644` | Mover a checagem para `execute_step`. |
| B2 | Os testes de host compartilham o estático global `CURRENT_IRQL` e rodam em paralelo, o que pode torná-los instáveis. | `driver.rs:1232,1359,1496` | Serializar os testes ou isolar o estado. |
| B3 | `test_pool_tag_verification_and_double_free` não tem nenhuma asserção, e a terceira chamada lê o cabeçalho de memória já liberada (UB). | `driver.rs:1642-1658` | Afirmar resultados observáveis (contador de alocações). |
| B4 | `ExFreePoolWithTag` com tag errada é ignorado em silêncio: vaza memória, sem erro nem bugcheck. | `driver.rs:993-998` | Bugcheck ou contador de violações. |
| B5 | `nexus_driver.c` e `standard_wdm.c` usam `Irp->UserBuffer` para IOCTLs `METHOD_BUFFERED`, mas o padrão WDM é `AssociatedIrp.SystemBuffer`. | fixtures `.c` | Reescrever ao migrar para o WDK. |

---

## 3. Status de cada problema registrado em `docs/09-phase3.5-kernel-hardening.md`

| # | Problema do doc 09 | Status | Evidência (código / teste) |
| :--- | :--- | :--- | :--- |
| 1 | O VMM de host devolve sucesso sem mapear; o init/scheduler de host devolve 0 sem Ring 3 | **Corrigido** | `mem/vmm.rs:131-136,203-207,318-321` devolvem `UnsupportedPlatform`/`None`; teste `host_does_not_invent_mappings_or_success`; `task/mod.rs:543-547` + teste `..._host_execution_is_explicitly_unsupported`. |
| 2 | `validate_user_buffer` ignora USER/WRITABLE | **Corrigido** | `task/syscall.rs:35-59` usa `AddressSpace::mapping`, que calcula as permissões efetivas nos 4 níveis (`vmm.rs:314-350`). QEMU `NEXUS_CHECK:permissions` testa ancestral supervisor e ancestral não gravável. |
| 3 | O ELF copia até o fim do arquivo, ignora o deslocamento na página, aceita entrada inválida | **Corrigido** | `nexus-loader/src/elf.rs:241-275` (filesz ≤ memsz, overflow, sobreposição), `mapper.rs:113-117`; teste `rejects_truncated_segments_filesz_exceeding_memsz_and_bad_entry`; QEMU `loader-bytes` (BSS desalinhado). |
| 4 | PE com optional header truncado; overflow nas tabelas do ELF | **Corrigido no parser**, **contornado no loader de drivers** | `pe.rs` usa `get`/`checked_*`; `tests/adversarial.rs` (truncamentos e 2048 mutações). Mas `driver.rs:708,729` engole os erros: ver **A1**. |
| 5 | NX não aplicado; SFMASK não limpa DF/TF/AC | **Corrigido** | `arch/x86_64/mod.rs:149-153` (exige NX, EFER.NXE); `mem/mod.rs:68-70` (identidade RW+NX); `mem/mod.rs:119-125` (código do kernel RX); `syscall.rs:12` `SFMASK=0x44700` (TF, IF, DF, NT, AC). QEMU `msrs`/`permissions`. |
| 6 | O yield só salva RIP/RSP; FS/GS persistem | **Corrigido** | `SyscallFrame` completo (`task/syscall.rs:9-28`), `fxsave64`/`fxrstor64` (`task/mod.rs:463,498`), FS/GS zerados ao voltar (`task/mod.rs:572-573`). QEMU `context` (8 yields alternados por personalidade). O AVX não é habilitado, então o FXSAVE cobre todo o estado exposto. |
| 7 | Exit e fault compartilham o mesmo inteiro | **Corrigido** | `RunOutcome::{Exit,Fault,Yield}`; `hardening.rs:356-363` (saída 14 ≠ #PF). |
| 8 | O #UD lê 4 bytes em RIP; stubs sem alinhamento | **Corrigido** | `idt.rs:158` (não desreferencia RIP); `idt.rs:425-428` (`and rsp,-16`). QEMU `exit-and-boundary` (#UD na fronteira da página). |
| 9 | Processos e falhas parciais não liberam frames; heap bump | **Corrigido** | `Process::release`; `mem/heap.rs` (linked_list_allocator com recuperação); QEMU `stress`: 64 ciclos, 128 processos, 1024 yields, frames e heap iguais à linha de base. |
| 10 | O PMM libera reservados ou nunca alocados; arredondamento; sobreposição | **Corrigido** | `mem/pmm.rs:85-104,148-160` (bitmap `allocated`, `div_ceil`, a reserva vence); 4 testes unitários específicos. |
| 11 | Boot/CI aceitam marcadores; sucesso da Fase 3 impresso mesmo com fault | **Parcialmente corrigido** | O runner exige `isa-debug-exit=33` + os 8 checks + 130 escritas binárias (`test-hardening.py:18-34,98`); `lib.rs:158-167` entra em pânico em resultado inesperado. **Porém:** os marcadores 3.6/3.7 são impressos incondicionalmente (FP1) e o CI nunca rodou até o fim (C3). |
| — | Doc 09: "Resultados finais… serão preenchidos" | **Pendente** | `docs/09…:3,35`: o próprio documento continua "em andamento; não concluída". |

**Conclusão sobre o doc 09:** 10 de 11 itens estão corrigidos no código, 1 está parcial. A Fase 3.5 só não pode ser encerrada por causa do build e do CI (C1 a C3), do item 11 e do relatório final ainda não escrito.

---

## 4. Validação da Fase 3.7, item a item

| Requisito | Estado real | Evidência |
| :--- | :--- | :--- |
| W^X, sem RWX persistente | **Funciona em QEMU; não há teste no repo** | Sonda `AUDIT_WX`: `rva 0x0` RO+NX, `0x1000` RX, `0x2000` RO+NX, `0x3000` RW+NX, `0x4000` RO+NX, `0x5000` RW+NX, U=0 em todas (`logs/16-qemu-probe-serial.log`). Ver M5 e M7. |
| Permissões RX/RW/NX por seção | Correto para as fixtures (SectionAlignment 0x1000) | `driver.rs:510-543`; `.pdata` e `INIT` corretos. |
| CR0.WP em Ring 0 | **Funciona em QEMU; não há teste no repo** (o doc 12 diz "comprovada de forma inequívoca") | Sonda: `[TRAP] vector=14 … error=0x3 ring=0` ao escrever no `.text` do driver (`logs/17-qemu-wp-probe-serial.log`). |
| CR8 / IRQL | **CR8 real, sem nenhuma interrupção a mascarar (simulado na prática)** | Ver C5. |
| Bloqueio do escalonador em DISPATCH_LEVEL | Funciona em `run_all` (sonda: `Err(UnsupportedExecution)`), mas não em `run_user_process` (B1). Não existe preempção para bloquear. | `task/mod.rs:627` |
| Spinlocks | Funciona em uniprocessador com IF=0: eleva para 2, CAS atômico, restaura. Não há SMP para testar contenção. | `driver.rs:1083-1110`; QEMU `counter = 101`. |
| Eventos / KeWait | **Stub** (A2) | E3 |
| Pools | Funcional; tag errada é ignorada em silêncio (B4) | `driver.rs:958-1013` |
| Descarregamento de drivers | Chama o `DriverUnload` real, mas mascara vazamentos (M3), deixa ponteiro pendente (M1) e não contabiliza pool (M6) | E5, leitura do código |
| Driver WDM "autêntico" com cabeçalhos padrão | **Não atendido** (C4, A4) | Offsets, E9 |
| Relocações e imports | Imports funcionam para a superfície sintética; relocações nunca são testadas (A3); erros engolidos (A1) | E1, E2, cabeçalhos |

---

## 5. Comportamentos simulados ou incompletos (lista explícita)

1. **IRQL sem interrupções:** o CR8/TPR é escrito de verdade, mas IF=0 o tempo todo, não há LAPIC/IOAPIC/timer nem vetores de IRQ. Elevar o IRQL não tem efeito observável sobre nenhuma interrupção (C5).
2. **`CURRENT_IRQL` atômico em software** continua existindo e sendo escrito em todo raise/lower (`driver.rs:24,819,833`). No host é a **única** fonte de IRQL nos testes, porque os hooks de hardware não são instalados.
3. **`KeWaitForSingleObject`** não bloqueia e não tem waiters, e **`KeSetEvent`** não acorda ninguém (A2).
4. **`DbgPrint`** é um no-op (`driver.rs:785-787`); as mensagens dos drivers não aparecem no serial.
5. **`IoCreateSymbolicLink`/`IoDeleteSymbolicLink`** são no-ops sem namespace de objetos (`driver.rs:924-940`).
6. **`IoCompleteRequest`** só zera `pending_returned` (`driver.rs:947-951`): não há rotinas de conclusão nem pilha de I/O.
7. **`IoCreateDevice`** ignora o tamanho da extensão, o nome e o modo exclusivo (M2).
8. **`DriverExtension`** é sempre nulo. Drivers PnP reais (`DriverObject->DriverExtension->AddDevice`) quebrariam.
9. **IRPs** são montados à mão pelo host, sem I/O manager, `IoCallDriver`, `IRP_MJ_CLOSE` nem `SystemBuffer`.
10. **O escalonador é cooperativo**, single-CPU, sem threads de kernel nem preempção. Isso está declarado em `task/mod.rs:1`.
11. **Paged pool** não existe; tudo é non-paged. Isso está declarado no doc 12, §7.3.
12. O próprio código chama a tabela de "Simulated NT Kernel function table" (`driver.rs:334`).

---

## 6. Falsos positivos nos testes

| ID | Teste / verificação | Por que pode passar sem provar o que diz |
| :--- | :--- | :--- |
| FP1 | `NEXUS_PHASE3_6_SUCCESS` / `NEXUS_PHASE3_7_SUCCESS` (`crates/nexus-kernel/src/lib.rs:183-189`), exigidos pelo runner (`test-hardening.py:29-32`) | São impressos incondicionalmente quando `validate_nt_driver_subsystem` retorna. "W^X Verified" não está ligado a nenhuma leitura de PTE nem a nenhum teste de falha. O portão real é o exit code 33 + os `assert!`. |
| FP2 | `test_wx_protection_and_section_isolation` (`driver.rs:1557-1640`) | Só verifica os argumentos do callback (não há página real). No Linux não confere o `mprotect`; só o Windows usa `VirtualQuery`. |
| FP3 | Asserções `device_object.is_null()` depois do unload (`driver.rs:1391,1554`; `driver_host.rs:191-194,382-385`) | Não podem falhar: `unload()` zera o ponteiro por conta própria (`driver.rs:619`). |
| FP4 | "Hardware CR8 TPR verified" (`driver_host.rs:409-416`) | Só testa a ida e volta do registrador; não prova mascaramento (não existem interrupções). |
| FP5 | Teste de evento (`standard_wdm.c`, `IOCTL_WDM_SAMPLE_EVENT_TEST`) | Sinaliza e logo espera, então passa com um stub que nunca bloqueia. |
| FP6 | Testes de IRQL no host (`driver.rs:1359,1496`) | Usam o `CURRENT_IRQL` de software (hooks de hardware nulos). Não testam o CR8. |
| FP7 | `test_pool_tag_verification_and_double_free` | Não tem asserções; tem UB (B3). |
| FP8 | O conjunto inteiro de testes de driver | Fixture e host compartilham a mesma ABI escrita à mão (C4), então passam qualquer que seja a ABI NT real. |
| FP9 | `.sys` versionados | Nunca são recompilados no CI (A4). Mudar o `.c` não altera os testes; não há verificação de hash nem de proveniência. |
| FP10 | "Relocations DIR64" (docs 11/12) | Nenhuma fixture tem relocações (A3). |
| FP11 | `test_user_flag_isolation` (`vmm.rs:480-496`) | Só testa a codificação de bits; não testa isolamento. É baixo risco, mas o nome engana. |

O que **não** é falso positivo: a suíte `hardening.rs` da 3.5 (permissões lidas dos PTEs reais, CR2 e código de erro dos traps, bytes na memória do guest, contagem de frames e heap) e o runner (`test-hardening.py`) com os testes negativos (`test-hardening-runner.py`) são sólidos.

---

## 7. Testes executados (comandos reais e resultados)

Todos foram executados em `/workspace/nexus-os` (commit `1d8b134`), em 2026-10-11 por volta de 08:57 a 09:05 BRT.

| # | Comando | Toolchain | Resultado | Log |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `cargo fmt --all -- --check` | 1.99.0 | ✅ OK | `01-fmt.log` |
| 2 | `cargo check --locked --workspace --all-targets` | 1.99.0 | ❌ 13× `E0433 libc` (C1) | `02-check.log` |
| 3 | `cargo clippy --locked --workspace --all-targets -- -D warnings` | 1.99.0 | ❌ mesmo erro | `03-clippy.log` |
| 4 | `cargo test --locked --workspace` (debug/release) | 1.99.0 | ❌ não compila | `04/05-*.log` |
| 5 | `cargo run --locked -p nexus-poc` | 1.99.0 | ❌ não compila | `06-poc.log` |
| 6 | `cargo build --locked -p nexus-boot --target x86_64-unknown-uefi` | 1.99.0 | ❌ `undefined symbol: wcslen` (C2) | `07-uefi-build.log` |
| 7 | o mesmo, com 1.90.0 / 1.95.0 / 1.96.0 / 1.97.0 / 1.98.0 | fixas | ✅ todas compilam | `07b-*.log` |
| 8 | `python3 scripts/test-hardening-runner.py` | — | ✅ 2 testes OK | `08-runner-negative.log` |
| 9 | `python3 scripts/build-fixtures.py` (clang + lld) | — | ✅ 32 imagens externas | `09-build-fixtures.log` |
| 10 | `cargo clippy --locked -p nexus-boot --target x86_64-unknown-uefi --features hardening-tests -- -D warnings` | 1.95.0 | ✅ OK | `10-clippy-uefi-1.95.log` |
| 11 | `python3 scripts/test-hardening.py --ram 128 --cpu qemu64 --timeout 120` | 1.95.0 | ✅ **QEMU**: exit 33, 8/8 checks, 130 escritas, estresse OK | `11-qemu-128-qemu64.log`, `qemu/hardening-128-qemu64-debug/` |
| 12 | `… --ram 256 --cpu max` | 1.95.0 | ✅ **QEMU** idem | `11-qemu-256-max.log` |
| 13 | `… --ram 512 --cpu max --release` | 1.95.0 | ✅ **QEMU** idem | `11-qemu-512-max-release.log` |
| 14 | `… --ram 128 --cpu qemu64` (árvore limpa) | 1.98.0 | ✅ **QEMU** idem | `18-qemu-128-qemu64-rust1.98.log` |
| 15 | Patch descartável `libc` + `cargo check`/`clippy -D warnings`/`test` (debug e release)/`run -p nexus-poc` | 1.99.0 | ✅ **51 testes** passam (2+4+23+11+3+1+7), clippy limpo, PoC OK; patch revertido | `12-throwaway-libc.patch`, `12a…12e-*.log` |
| 16 | Experimentos adversariais de host E1 a E9 (crate separado `experiments/`) | 1.99.0 + patch libc temporário | ✅ executados; confirmam A1, A2, A4, M1, M2, M4 e B4 | `13-experiments.log` |
| 17 | Offsets de ABI: MinGW DDK `wdm.h` vs. `nexus-types` | gcc mingw / 1.99.0 | divergências listadas em C4 | `14-abi-*.log` |
| 18 | Driver WDM compilado com os cabeçalhos DDK do MinGW-w64 → `load_driver` | — | ❌ `UnresolvedImport IofCompleteRequest` (esperado; achado A4) | `15-*.log`, `13-experiments.log` (E9) |
| 19 | Sonda QEMU descartável: leitura de PTE do driver + escalonador em CR8=2 + RFLAGS.IF | 1.95.0 | ✅ W^X real nos PTEs; `UnsupportedExecution`; `IF=0` | `16-*.log`, `16-throwaway-qemu-probe.patch` |
| 20 | Sonda QEMU descartável: escrita em Ring 0 numa página RX do driver | 1.95.0 | `#PF error=0x3 ring=0` registrado e máquina parada (o timeout de 40 s era o comportamento esperado, ver M8) | `17-*.log`, `17-throwaway-wp-probe.patch` |
| 21 | Consulta ao CI do GitHub (3 execuções) | — | ❌ 0 de 3 verdes | `00-ci-github.txt` |

**O que não foi executado, e por quê:**
- **Compilação com o WDK oficial e MSVC:** exige Windows. Não havia máquina Windows disponível nesta execução. Fica para o job `windows-latest` (seção 8). A comparação com o MinGW DDK é só um indicativo, não substitui o WDK.
- **Host checks no Windows** (`cargo test` com `#[cfg(windows)]`, incluindo `VirtualQuery`): não executados; o job do CI foi cancelado.
- **Testes de concorrência SMP e de interrupções:** não existem no código (`-smp 1`, IF=0). Não há o que executar até haver APIC (C5).
- **Hardware físico:** fora do escopo. Nada aqui vale como validação em hardware.

---

## 8. Bloqueios e próximos passos

### 8.1 Ordem recomendada (PRs pequenos, sem reescrita)

1. **PR-1 (desbloqueia tudo, resolve C1, C2 e C3):** `libc` em `nexus-loader` + `rust-toolchain.toml` fixando a 1.98.0 (com o alvo UEFI, clippy e rustfmt) + `fail-fast: false` na matriz de host. **Aceite:** CI verde nos 5 jobs.
2. **PR-2 (loader fail-closed, resolve A1, A3 e M7):** propagar os erros de relocação e import, recusar imagens sem relocações fora da base, validar SectionAlignment e páginas conflitantes. **Aceite:** testes de host com os bytes do E1 e do E2 falham fechado, e uma fixture com ponteiros absolutos exercita DIR64.
3. **PR-3 (veracidade dos testes, resolve FP1 a FP7, M3, M5, M6, M8 e B2/B3):** portar a sonda de PTE para `hardening.rs` (`NEXUS_CHECK:driver-wx`), tornar o W^X obrigatório, não zerar `device_object` no `unload()`, contabilizar heap e pool no ciclo do driver, sair com código de falha em trap de Ring 0, e corrigir os testes de pool e o IRQL global. **Aceite:** o runner exige `driver-wx`, e uma mutação proposital (por exemplo, `.text` RW) faz o CI falhar.
4. **PR-4 (semântica NT mínima, resolve M1, M2, M4, A2 e B4):** `IoDeleteDevice` em qualquer posição da lista, `DeviceExtensionSize`, validação de direção do IRQL, auto-reset e espera infinita sem waiters como erro explícito. **Aceite:** os testes de host E3, E4 e E5 invertidos passam a exigir o comportamento correto.
5. **PR-5 (WDK real, resolve C4 e A4):** job `windows-latest` (8.2) + correção dos layouts de `nexus-types` + exports `IofCompleteRequest`, `KeAcquireSpinLockRaiseToDpc` etc. + remoção dos `.sys` versionados.
6. **Decisão sobre C5** (pertence ao Gabriel, porque mexe no escopo): ou a 3.7 passa a exigir só "IRQL = CR8/TPR sem fontes de interrupção" e a semântica com interrupções vai para a Fase 4 (APIC/timers), ou se implementa o LAPIC mínimo e o teste de TPR antes de encerrar a 3.7.
7. **Documentação (A5):** doc 09 com os resultados finais, doc 12 sem "Hardware Real" e com as limitações da seção 5, README e roadmap coerentes, e a contagem de testes atualizada.

### 8.2 Plano do job `windows-latest` com o WDK

Objetivo: compilar no CI, a cada push, um driver de teste que **só inclui `<wdm.h>`/`<ntddk.h>` do WDK oficial** e é linkado contra o `ntoskrnl.lib` do WDK. Esse driver alimenta os testes de host e do QEMU, sem `.sys` versionado.

1. **Job `wdk-driver` (`runs-on: windows-latest`):**
   - Detectar o WDK em `C:\Program Files (x86)\Windows Kits\10\Include\*\km`. Se não houver, instalar. Uma opção é o pacote NuGet do WDK (`Microsoft.Windows.WDK.x64`, com o `Microsoft.Windows.SDK.CPP` correspondente), restaurado via `nuget`/`msbuild`. A alternativa é `winget install --id Microsoft.WindowsWDK.<versão>`. A disponibilidade e a versão exata no runner atual **precisam ser verificadas no primeiro run**; não validei isso aqui.
   - `vcvars64.bat` + `cl.exe /kernel /GS- /Zi /W4 /WX /I<WDK>\km /I<WDK>\shared /D_AMD64_ /DNTDDI_VERSION=…` e `link.exe /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB <WDK>\Lib\…\km\x64\ntoskrnl.lib hal.lib`.
   - Fonte novo `tests/fixtures/nt_driver/wdk/sample_wdm.c`: só cabeçalhos oficiais, com `IoGetCurrentIrpStackLocation`, `AssociatedIrp.SystemBuffer`, `KeAcquireSpinLock` (o macro), eventos, pool `NonPagedPoolNx`, `DeviceExtension` via `IoCreateDevice` e uma tabela de ponteiros absolutos (para forçar `.reloc`).
   - Gerar também `abi_offsets.json` com um pequeno `.c` que exporta `offsetof` e `sizeof` dos tipos usados (igual ao `logs/14-abi-mingw-offsets.c`, mas com o WDK oficial).
   - `upload-artifact`: `sample_wdm.sys`, `.pdb`, `abi_offsets.json` e `SHA256SUMS`.
2. **Jobs `check-and-test` e `kernel-hardening`:** `needs: wdk-driver` + `download-artifact`. Passar o caminho por variável de ambiente (como já é feito com `NEXUS_FIXTURES_DIR`) para o `include_bytes!` e para um teste de host que compara `abi_offsets.json` com `core::mem::offset_of!` de `nexus-types`.
3. **Resultado esperado no primeiro run:** **vermelho**, com `UnresolvedImport` e divergência de offsets, o que confirma C4 e A4. O verde só vem depois do PR-5.
4. **Fora do escopo do job:** assinatura e test-signing, carregar o driver no Windows de verdade, e qualquer alegação de compatibilidade além do driver de teste.

### 8.3 Bloqueios para a Fase 4

**Dependências do PR-4 para a Fase 4 (registradas para não se perderem):**
- **Spin lock do registro de pool:** o `PoolTracker` (registro de blocos de pool) é protegido por um spin lock simples (`AtomicBool`) que **não eleva o IRQL nem desabilita interrupções**. Isso só é correto enquanto nenhum ISR ou DPC aloca ou libera pool. Quando a Fase 4 permitir que ISRs/DPCs aloquem, esse lock precisa elevar para `DISPATCH_LEVEL` (para DPCs) ou desabilitar interrupções (para ISRs) durante a seção crítica. Caso contrário, uma interrupção no meio de `ExAllocatePoolWithTag` que tente alocar fica presa no lock para sempre (deadlock).
- **Espera:** `KeWaitForSingleObject` não bloqueia, porque não existem outras threads nem timer. Ver as notas do PR-4 na seção 10. A Fase 4 precisa de scheduler, lista de waiters e timer para implementar a espera real.
- **Conclusão de IRP (depois do PR #8):** `IofCompleteRequest` passou a ser exportado (A4), mas é um stub mínimo: só zera `PendingReturned`. Não há rotinas de conclusão (`IoSetCompletionRoutine`), desempilhamento de `IO_STACK_LOCATION`, `IoCallDriver` nem filter drivers. A semântica real foi transferida para a Fase 4 (`docs/12`, "Itens transferidos").
- **IRQL:** as verificações de direção do PR-4 são de software. Elas **não** tornam o IRQL equivalente ao do Windows. O mascaramento real por APIC/CR8 continua na Fase 4.

A Fase 4 **não deve começar** enquanto o PR-1 não estiver verde e as decisões sobre C4 e C5 não estiverem tomadas e documentadas. Os PRs 2 a 4 são pequenos e podem fechar a 3.5 e boa parte da 3.7 rapidamente. O PR-5 e o C5 definem se a 3.7 é encerrada com escopo reduzido ou só depois do APIC.

---

## 9. Anexo: reprodutibilidade

> **Atenção:** todos os caminhos `logs/...` e `/workspace/nexus-os-audit/...` deste relatório apontam para **evidência local, não versionada**, gerada na máquina da auditoria. Eles **não existem neste repositório** e servem só para rastreabilidade. A evidência versionada e reprodutível é a do CI: os artefatos `hardening-*` (`serial.log`, `qemu.log`, `result.json`) de cada execução do GitHub Actions e os testes do próprio repositório.

- Patches descartáveis (aplicados e revertidos; o repo terminou limpo; locais, não versionados): `logs/12-throwaway-libc.patch`, `logs/16-throwaway-qemu-probe.patch`, `logs/17-throwaway-wp-probe.patch`.
- Experimentos de host (fora do repo; locais, não versionados): `/workspace/nexus-os-audit/experiments/` (`src/lib.rs`, `abi/offsets.c`, `abi/drv.c`, `abi/audit_wdm.sys`). Para rodar, o patch `libc` precisava estar aplicado no clone, por causa de C1 (já corrigido no PR #3). Os experimentos E1 e E2 viraram testes versionados em `crates/nexus-loader/tests/driver_fail_closed.rs` (PR-2).
- Evidência QEMU bruta da auditoria (local, não versionada): `logs/qemu/*/{serial.log,qemu.log,result.json}` (`result.json` traz o hash do EFI, do firmware, das fixtures e do fonte). O equivalente versionado são os artefatos `hardening-*` do CI.

## 10. Acompanhamento das correções

> **Atualização de 2026-10-11 (depois do PR #6):** a tabela da seção 1 registra o estado **no momento da auditoria**. Desde então, a Fase 3.5 foi encerrada pelos critérios de `docs/09-phase3.5-kernel-hardening.md` (C1–C3 e item 11 resolvidos, CI verde). A Fase 3.7 continua aberta: o escopo foi revisado em `docs/12-phase3.7-nt-driver-hardening.md` (decisão sobre C5: IRQL com interrupções vai para a Fase 4), e C4/A4 dependem do PR-5 e do PR-6.

| PR | Achados | Estado |
|---|---|---|
| #3 (PR-1) | C1, C2 (pin temporário; issue #2), C3 | Merged em `main` (`2040ea5`). A mudança no workflow (pin explícito e `fail-fast: false`) ficou pendente porque o token não tinha permissão de workflow. |
| #4 (PR-2) | A1, A3, M7 e o `DriverName` pendurado (ver abaixo) | Merged em `main` (`02a9db8`). |
| #5 (PR-3) | FP1–FP7, M3, M5, M6, M8, B2, B3 (B4 parcial) | Merged em `main` (`7152e44`). |
| #6 (PR-4) | M1, M2, M4, A2, B4, as notas de revisão do PR-3 (limite do registro de pool, contagem exata de páginas W^X) e o `IoDeleteDevice` inválido | Merged em `main` (`a06ea9e`). |
| #7 (PR de documentação) | A5 e o entregável 9 (docs 04, 09, 11, 12 e README alinhados à evidência) | Merged em `main` (`e4d5aa5`). **3.5 encerrada** (critérios em `docs/09`); **3.7 aberta** (escopo revisado em `docs/12`). |
| PR-5 | A4, FP8, FP9 (tabela `sizeof`/`offsetof` com o WDK oficial, rebuild dos drivers, sonda de carga) | #8, 1º commit; merged em `main` (`b0922ae`), sem mudança de workflow. O job `windows-latest` e o pin do CI ficam para um PR só de workflow, quando houver a permissão Workflows. |
| PR-6 | C4, A4 (structs alinhadas ao WDK x64, exports reais `IofCompleteRequest`/`KfRaiseIrql`/`KeAcquireSpinLockRaiseToDpc`, fixtures sobre `<ntddk.h>` sem código estático do `ntoskrnl.lib`, `wdk_min` executado no host e no guest, `--enforce`) | #8, 2º commit; merged em `main` (`b0922ae`). Local: 62/62 entradas, 3/3 drivers linkam, carregam e executam (ver `docs/14`). A 3.7 só fecha com o job WDK verde (PR de workflow). |
| PR de documentação (pós-#8) | Escopo de `IofCompleteRequest` | `IofCompleteRequest` documentado como stub mínimo (`docs/14`); semântica real de conclusão de IRP (`IoSetCompletionRoutine`, desempilhamento, filter drivers) transferida para a Fase 4 (`docs/12`, seção 8.3 deste doc). |

**PR-2 (loader de drivers fail-closed):**
- **A1:** `load_driver` propaga os erros de `parse_relocations`/`parse_imports` com `?`, antes de alocar memória. Cópia de seção, alvo de relocação e slot de IAT fora da imagem viram `ImageOutOfBounds`/`RelocationFailed`, e não são mais ignorados.
- **A3:** nova fixture `tests/fixtures/nt_driver/reloc/reloc_driver.sys` (fonte `reloc_driver.c`, compilada por `scripts/build-reloc-driver.py` com clang + lld-link; `--check` confere byte a byte). Ela tem 3 entradas DIR64, e o `DriverEntry` dela só retorna sucesso se os ponteiros relocados coincidirem com os endereços RIP-relativos. Isso é verificado no host e no Ring 0 do guest QEMU (`NEXUS_DRIVER_RELOC:applied=3:rebased=true:entry_status=0x0`, exigido pelo runner). Uma imagem com `IMAGE_FILE_RELOCS_STRIPPED` que precisaria ser rebaseada é recusada (`RelocationsStripped`). Uma imagem sem diretório `.reloc` e sem a flag continua aceita, como no loader do NT (é o caso das fixtures MSVC, que não têm fixups absolutos). Um teste de controle negativo prova que, sem relocações, o `DriverEntry` detecta o ponteiro errado.
- **M7:** o parser já recusava `SectionAlignment < 4096` e seções que compartilham página. Agora há testes de regressão para isso, e uma seção W+X é recusada na carga (`WritableExecutableSection`), não só no callback de W^X.
- **Novo:** o buffer UTF-16 de `DriverObject.DriverName` era liberado ao fim de `load_driver` (ponteiro pendurado). Agora ele vive em `LoadedDriver`.

**PR-3 (testes que não passam sem prova):**
- **FP1/M5:** o W^X dos drivers deixou de ser opcional. Sem `KERNEL_ADDRESS_SPACE` o kernel entra em pânico; antes ele pulava a etapa em silêncio. Depois de aplicar as permissões, o kernel relê o PTE efetivo de cada página das 3 imagens (cabeçalho e seções) e exige R/NX, R/X ou RW/NX conforme a seção, sem W+X e sem USER. Os marcadores `NEXUS_PHASE3_6/3_7_SUCCESS` só são impressos depois de `NEXUS_CHECK:driver-wx:PASS` e `NEXUS_DRIVER_WX:pages_verified=N` (N=17 hoje), que o runner exige.
- **FP3/M3/M6:** `LoadedDriver::unload()` não zera mais `device_object`. Depois do `DriverUnload`, ele falha com `DevicesLeaked`, `PoolLeaked(n)` ou `PoolViolations(n)`. No guest, o heap do kernel precisa voltar exatamente ao valor anterior em cada um dos 3 ciclos de vida (`NEXUS_CHECK:driver-lifecycle:PASS`, exigido pelo runner). Testes de controle negativo provam que cada vazamento é detectado.
- **FP7/B3 (e B4 parcial):** o pool passou a usar um registro de blocos vivos de capacidade fixa, sem alocação, em vez de um cabeçalho lido antes do ponteiro. Double free, ponteiro desconhecido e tag errada são recusados sem tocar memória liberada e são contados em `pool_violations()`. O teste de pool agora tem asserções. O bugcheck por tag errada (B4) fica para o PR-4.
- **B2:** os testes de host que tocam o estado global do host NT (IRQL de software, hooks de CR8, pool) são serializados por `lock_nt_host_state_for_tests()`, que também zera esse estado. Antes, `counter 100 != 101` aparecia de forma intermitente; depois da correção, 200 execuções seguidas passaram.
- **FP2:** no Linux, o teste de W^X lê as permissões reais em `/proc/self/maps` para cada página de seção. Uma mutação que deixa `.data` como RWX faz o teste falhar.
- **FP4/FP6:** a mensagem do CR8 agora diz o que realmente é provado: a ida e volta do CR8 e o roteamento `KeRaiseIrql`/`KeLowerIrql` → CR8, sem mascaramento de interrupções (que fica para a Fase 4). No guest, o kernel chama os stubs e confere o CR8. No host, um teste com hooks falsos prova que o spin lock do `standard_wdm` passa pelos hooks.
- **FP5:** o teste de evento continua passando com o stub atual porque sinaliza antes de esperar. A mensagem e o comentário agora dizem isso explicitamente. A semântica de espera fica para o PR-4.
- **M8:** com `hardening-tests`, um trap em Ring 0 escreve `0x12` (status 37) e um pânico escreve `0x11` (status 35) no `isa-debug-exit`. O runner nomeia essas falhas, em vez de esperar até o timeout.
- **Mutações verificadas no QEMU** (aplicadas e revertidas): sem W^X no `nexus_driver`, o resultado é `#PF` em Ring 0 e status 37 em cerca de 3 s; com `WRITABLE` forçado nas páginas, pânico de W+X e status 35; com 64 bytes vazados no ciclo do driver, pânico de heap desbalanceado e status 35.

**PR-4 (semântica NT mínima; resolve M1, M2, M4, A2 e B4):**
- **Caminho de bugcheck:** o host NT ganhou `bug_check(code, params)`. No guest, o handler imprime `NEXUS_BUGCHECK: code=… params=…` e, com `hardening-tests`, escreve `0x13` no `isa-debug-exit` (status 39, que o runner nomeia). Sem handler instalado, o bugcheck vira pânico e nunca é ignorado em silêncio. Os códigos `0x09` (`IRQL_NOT_GREATER_OR_EQUAL`), `0x0A` (`IRQL_NOT_LESS_OR_EQUAL`) e `0xC2` (`BAD_POOL_CALLER`) são códigos do Windows. Já os **subcódigos** de `0xC2` (1 = tag errada, 2 = bloco desconhecido ou double free) e o código `0x4E580001` (espera infinita impossível de satisfazer) são **específicos do Nexus**, não códigos do Windows.
- **M1:** `IoDeleteDevice` remove o device da lista em qualquer posição (cabeça, meio ou cauda).
- **Exclusão inválida de device (revisão do PR-4):** antes, `IoDeleteDevice` liberava a memória mesmo quando o device não estava na lista do driver. Assim, um segundo `IoDeleteDevice` no mesmo ponteiro, ou um ponteiro que nunca foi device, lia um cabeçalho já liberado e liberava a memória de novo (double free). Agora o host mantém um registro de devices vivos, de capacidade fixa (256), análogo ao registro de pool. O device só é liberado se estiver vivo **e** for encontrado e removido da lista do driver. Em qualquer outro caso, o host gera o bugcheck `0x4E580002` (`BUGCHECK_NEXUS_INVALID_DEVICE_DELETE`, **código específico do Nexus, não do Windows**), não libera nada e não lê o cabeçalho. O parâmetro 1 é um subcódigo, também específico do Nexus; o parâmetro 2 é o ponteiro recebido:
  - `1` (`DEVICE_DELETE_NOT_LIVE`): o ponteiro não é um device vivo (exclusão dupla ou ponteiro estranho). O ponteiro **nem chega a ser dereferenciado**.
  - `2` (`DEVICE_DELETE_NO_DRIVER`): device vivo com `DriverObject` nulo.
  - `3` (`DEVICE_DELETE_NOT_IN_LIST`): device vivo que não está na lista do seu driver.
  Quando o registro de devices enche, `IoCreateDevice` retorna `STATUS_INSUFFICIENT_RESOURCES`. Testes: `test_invalid_device_delete_bugchecks_without_freeing` (os três subcódigos; nada liberado; a memória estranha fica intacta), `tests/device_delete_heap.rs` (alocador global contador: depois da exclusão dupla e da exclusão de ponteiro estranho, nenhum `dealloc` extra e heap exatamente no valor de antes) e a verificação `device-invalid-delete-bugchecks` do autoteste no guest, com o heap do kernel balanceado. Mutação: com o comportamento antigo restaurado (liberar sem verificar), o binário de testes aborta com `free(): double free detected` e o teste de heap falha.
- **M2:** `IoCreateDevice` aloca `DeviceExtensionSize` bytes zerados e alinhados a 16, no mesmo bloco do `DEVICE_OBJECT`, liberados por `IoDeleteDevice`. Com tamanho 0, a extensão é nula. Acima de 1 MiB, retorna `STATUS_INSUFFICIENT_RESOURCES`.
- **M4:** `KeRaiseIrql` para um IRQL menor ou acima de `HIGH_LEVEL` (15) gera bugcheck `0x09`. `KeLowerIrql` para um IRQL maior gera bugcheck `0x0A`. Nos dois casos o IRQL fica inalterado. `KeAcquireSpinLock` acima de `DISPATCH_LEVEL` também gera bugcheck e não toma o lock. Continua sendo um IRQL de software, roteado para o CR8; não há equivalência com o Windows (ver 8.3).
- **A2:** `SynchronizationEvent` faz auto-reset quando uma espera é satisfeita. `NotificationEvent` continua sinalizado até `KeResetEvent`. `KeSetEvent`/`KeResetEvent` retornam o estado anterior. A espera infinita (`Timeout = NULL`) num evento não sinalizado **nunca** retorna `STATUS_TIMEOUT`: como não há outra thread que possa sinalizá-lo, ela gera bugcheck `0x4E580001` e retorna `STATUS_POSSIBLE_DEADLOCK`. Timeout zero ou finito retorna `STATUS_TIMEOUT` imediatamente: não há timer nem outra thread até a Fase 4, então o resultado é o mesmo de esperar o prazo inteiro, mas sem passagem de tempo real. Esperar em `DISPATCH_LEVEL` com timeout diferente de zero, ou acima de `DISPATCH_LEVEL`, gera bugcheck `0x0A`.
- **B4:** `ExFreePoolWithTag` com tag errada, double free ou ponteiro desconhecido gera bugcheck `0xC2` (o bloco continua vivo e a violação é contada).
- **Nota de revisão (a):** quando o registro de 256 blocos enche, a alocação continua retornando nulo, mas agora incrementa `pool_tracker_exhausted()` e imprime `NEXUS_POOL_TRACKER_EXHAUSTED: capacity=256 refused_total=N` (no serial do guest e por um sink de diagnóstico no host).
- **Nota de revisão (b):** `wx_pages_verified >= 12` virou igualdade exata. O kernel calcula as páginas esperadas a partir da tabela de seções de cada fixture (cabeçalhos até a primeira seção, mais o intervalo de páginas de cada seção), e o runner exige `NEXUS_DRIVER_WX:pages_verified=N:expected=N` com N igual nos dois lados (17 hoje).
- **Prova no guest:** `nt_semantics_self_test()` roda em Ring 0 antes de carregar os drivers e executa 14 verificações, com um handler de bugcheck que só registra. O heap do kernel precisa voltar exatamente ao valor anterior. O runner exige `NEXUS_CHECK:nt-semantics:PASS` e `NEXUS_NT_SEMANTICS:checks=14`. O `NEXUS_POOL_TRACKER_EXHAUSTED` que aparece no serial é o próprio autoteste enchendo o registro de propósito.
- **Testes de host:** são testes novos por comportamento (direção do IRQL, eventos e espera, extensão e remoção de device, esgotamento do registro, bugcheck sem handler, autoteste). Todos seguram `lock_nt_host_state_for_tests()`, que também limpa o handler de bugcheck e o sink de diagnóstico.
- **Mutações verificadas** (aplicadas e revertidas): sem auto-reset, remoção só na cabeça, raise que pode abaixar, lower que pode subir, espera infinita retornando timeout, tag errada aceita, esgotamento sem contador, e extensão sem zerar. Cada uma faz falhar o teste de host específico e o autoteste. No QEMU: um free com tag errada no guest termina com `NEXUS_BUGCHECK: code=0xc2` e status 39; uma contagem esperada de W^X errada em 1 termina em pânico (status 35); sem auto-reset, o autoteste do guest falha com pânico (status 35).
