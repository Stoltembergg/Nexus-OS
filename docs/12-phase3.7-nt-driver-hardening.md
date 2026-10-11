# Nexus OS — Fase 3.7: NT Driver Runtime Hardening

**Documento:** `docs/12-phase3.7-nt-driver-hardening.md`  
**Status:** **Concluída em 2026-10-11, dentro do escopo revisado** (seção 2). Os gates PR-5/PR-6 e os seis jobs do CI passaram no [run 38163656509](https://github.com/Stoltembergg/Nexus-OS/actions/runs/38163656509), no código testado `40f985e` (PR #10).
**Evidência:** guest QEMU/OVMF (TCG), runner Windows hospedado e testes de host no CI. **Nada foi verificado em hardware físico.** Isso não demonstra compatibilidade geral com Windows ou drivers de terceiros.
**Data:** Outubro de 2026

> **Revisão de 2026-10-11.** A versão anterior deste documento dizia "Concluído e Verificado em Hardware Real", "IRQLs de Hardware Reais… mascarando interrupções no nível de silício", "driver WDM autêntico… sem adaptações do Nexus" e "23 rotinas validadas". A auditoria de encerramento (`docs/13-auditoria-fases-3.5-3.7.md`) mostrou que essas afirmações **não tinham evidência**: nunca houve teste em hardware físico; o kernel roda com interrupções desabilitadas e sem APIC, então o CR8 não tem o que mascarar; as structs NT das fixtures são escritas à mão e divergem do `wdm.h` real; e eventos e esperas eram stubs. Este documento foi reescrito para refletir só o que está provado. A versão anterior continua no histórico do Git.

---

## 1. O que está provado hoje (QEMU/OVMF + testes de host, CI verde)

Cada item abaixo é exigido pelo runner `scripts/test-hardening.py` ou por testes de host que falham se a correção for revertida. As mutações que provam isso estão registradas no doc 13, §10.

| Item | Evidência | PR |
| :--- | :--- | :--- |
| **W^X nas imagens de driver.** `.text` RX; cabeçalhos, `.rdata` e `.pdata` RO+NX; `.data`/`INIT` RW+NX; nenhuma página W+X e nenhuma página USER. | O kernel relê o PTE efetivo de **cada** página das 3 fixtures e exige a contagem exata derivada das tabelas de seção: `NEXUS_DRIVER_WX:pages_verified=17:expected=17` (`NEXUS_CHECK:driver-wx`). No host Linux, `/proc/self/maps`. | #5, #6 |
| **Loader fail-closed.** Erros de relocação e de import, seções fora da imagem, seção W+X, `SectionAlignment < 4096` e imagens com `RELOCS_STRIPPED` que precisariam de rebase são recusados. | `crates/nexus-loader/tests/driver_fail_closed.rs`; guest `NEXUS_DRIVER_FAIL_CLOSED:imports=rejected:relocs=rejected`. | #4 |
| **Relocações DIR64.** | Fixture `reloc_driver.sys` (3 entradas DIR64, recompilada e conferida byte a byte por `scripts/build-reloc-driver.py --check`); guest `NEXUS_DRIVER_RELOC:applied=3:rebased=true:entry_status=0x0`. | #4 |
| **Ciclo de vida do driver sem vazamento.** `unload()` falha com `DevicesLeaked`, `PoolLeaked` ou `PoolViolations`; o heap do kernel volta exatamente ao valor anterior em cada um dos 3 ciclos. | `NEXUS_CHECK:driver-lifecycle`; testes de controle negativo no host. | #5 |
| **Semântica NT mínima** (14 verificações em Ring 0): direção do IRQL e limite `HIGH_LEVEL` (bugchecks 0x09/0x0A); `KeAcquireSpinLock` acima de DISPATCH; auto-reset de `SynchronizationEvent`; `NotificationEvent` continua sinalizado; espera infinita não satisfazível gera bugcheck em vez de `STATUS_TIMEOUT`; tag de pool errada e double free (0xC2); extensão de device zerada; remoção de device em qualquer posição; `IoDeleteDevice` inválido (exclusão dupla ou ponteiro estranho) gera bugcheck sem liberar nada; o esgotamento do registro de pool é contado e registrado. | `NEXUS_CHECK:nt-semantics` + `NEXUS_NT_SEMANTICS:checks=14`, com o heap do kernel balanceado; um bugcheck no guest sai com status 39. | #6 |
| **Roteamento IRQL → CR8.** `KeRaiseIrql`/`KeLowerIrql`/spin locks escrevem e leem o CR8 (TPR) de verdade; o escalonador cooperativo recusa o despacho com CR8 ≥ DISPATCH_LEVEL em `Scheduler::run_all`. | Linha do guest: "CR8 (TPR) read/write round-trip and KeRaise/LowerIrql -> CR8 routing verified (no interrupt masking…)"; teste de host com hooks falsos. | #5 |
| **CR0.WP habilitado** no init do kernel. | `arch/x86_64/mod.rs` (bit 16 do CR0). A falta em escrita numa página RX de driver (`#PF error=0x3`) só foi observada pela sonda descartável da auditoria (doc 13, §6.3); **ainda não há teste versionado** disso. | — |
| **ABI oficial WDK e drivers de teste.** 62/62 layouts NT; três drivers WDK compilados/linkados com MSVC, sem imports não resolvidos ou código estático da import lib, e carregados/executados pelo Nexus no host. Fixtures clang-cl conferidas separadamente. | `wdk-abi-evidence` do [run 38163656509](https://github.com/Stoltembergg/Nexus-OS/actions/runs/38163656509): relatórios MSVC/clang-cl, hashes, controles negativos e execução guest. Os drivers MSVC também passaram no guest QEMU: 22/22 páginas W^X, 14 checks NT, ciclo de vida balanceado. | #10 |

## 2. Revisão formal do escopo

O roadmap original exigia, para a 3.7, "real IRQ/APIC IRQL semantics". **Decisão (2026-10-11):** a integração real de IRQL com interrupções foi **transferida para a Fase 4**. Na 3.7, o IRQL é definido como:

> **IRQL na 3.7 = valor de software validado (direção, limites e bugchecks) e roteado para o CR8/TPR, sem nenhuma fonte de interrupção mascarável.** O kernel roda com RFLAGS.IF = 0, sem LAPIC/IOAPIC inicializados, sem PIC remapeado e sem vetores de IRQ ≥ 32. Portanto **não existe mascaramento de interrupções por hardware** e **não existe gerenciamento completo de IRQL**. Isso **não é equivalente ao Windows**.

### Critérios de encerramento da 3.7 (atendidos)

1. **PR-5 — validação com o WDK oficial:** atendido pelo job `wdk-abi` em `windows-latest`; o MSVC compilou e linkou três drivers de teste com WDK/SDK NuGet oficiais e gerou a tabela de `sizeof`/`offsetof` das structs NT principais. Resultado: **62/62 entradas** em concordância com o WDK.
2. **PR-6 — alinhamento das structs:** atendido; `nexus-types` e fixtures têm asserts de layout e concordam com os 62 valores oficiais. Os três drivers foram carregados/executados no host Nexus; os drivers MSVC foram também embutidos na imagem de teste e executados no guest QEMU/OVMF. Fixtures versionadas foram verificadas por rebuild `clang-cl` 19.1.7, sem comparar bytes MSVC a clang-cl.
3. **CI completo:** atendido no run 38163656509 para o SHA `40f985e`: dois jobs host (Ubuntu/Windows), três configurações QEMU/OVMF e o job `wdk-abi` — **seis jobs verdes**. O job passou os controles negativos de layout/import pelo erro esperado e preservou o artefato `wdk-abi-evidence`.

Com esses critérios atendidos, a 3.7 está **encerrada somente dentro do escopo revisado**. O marcador serial `NEXUS_PHASE3_7_SUCCESS` sozinho não fecha a fase; o fechamento decorre dos critérios acima e da evidência CI/QEMU vinculada.

### Itens transferidos explicitamente para a Fase 4

| Item | Por que não cabe na 3.7 |
| :--- | :--- |
| **IRQL real com APIC e mascaramento de interrupções:** LAPIC (SVR, timer), IOAPIC, PIC mascarado ou remapeado, vetores ≥ 32, IF=1, um teste em que uma interrupção fica pendente com TPR ≥ classe e é entregue ao baixar o TPR, e a checagem de CR8 também em `run_user_process` (doc 13, B1). | Exige o subsistema de interrupções e de timers da Fase 4 (doc 13, C5). |
| **Spin lock do `PoolTracker` elevando para `DISPATCH_LEVEL` ou desabilitando interrupções.** Hoje é um `AtomicBool` simples, correto só enquanto nenhum ISR ou DPC aloca pool. | Quando ISRs/DPCs puderem alocar, uma interrupção no meio de `ExAllocatePoolWithTag` causaria deadlock. |
| **Esperas reais com threads e timers:** `KeWaitForSingleObject` bloqueando, lista de waiters, `KeSetEvent` acordando threads e timeouts com passagem de tempo real. | Hoje não há threads de kernel nem timer: espera infinita não satisfazível gera o bugcheck `0x4E580001` e um timeout finito retorna `STATUS_TIMEOUT` imediatamente. |
| **Reuso de endereço de device e contagem de referências.** O registro de devices vivos (PR #6) identifica o device pelo endereço. Se um device é excluído e um novo `IoCreateDevice` reutiliza o mesmo endereço, um ponteiro antigo passa a apontar para o novo device e é aceito (problema ABA). O NT resolve isso com contagem de referências no gerenciador de objetos (`ObReferenceObject`/`ObDereferenceObject`, exclusão adiada até a última referência). | Exige o gerenciador de objetos e handles da Fase 4. |
| **Semântica real de conclusão de IRP:** `IoSetCompletionRoutine` e a chamada das rotinas de conclusão em `IofCompleteRequest` (de baixo para cima, respeitando `SL_INVOKE_ON_SUCCESS/ERROR/CANCEL` e `STATUS_MORE_PROCESSING_REQUIRED`), desempilhamento do `IO_STACK_LOCATION` por device, `IoCallDriver`/`IoSkipCurrentIrpStackLocation`/`IoCopyCurrentIrpStackLocationToNext`, `IoMarkIrpPending`/`STATUS_PENDING` com propagação de `PendingReturned`, `IoAllocateIrp`/`IoFreeIrp`, sinalização de `UserEvent` e cópia para `UserIosb`, e pilhas de devices com filter drivers (`IoAttachDeviceToDeviceStack`). | Hoje `IofCompleteRequest` só zera `PendingReturned` (`docs/14`, PR-6). Exige I/O manager, threads e esperas reais e o gerenciador de objetos (referências de device) da Fase 4. |

## 3. Limitações conhecidas (estado atual)

- **Structs NT alinhadas ao WDK x64 desde o PR #8:** 62/62 entradas verificadas localmente e no job `wdk-abi` com MSVC e clang-cl; asserções `const` de offset em `nexus-types`. As fixtures `nexus_driver.c`, `standard_wdm.c` e `wdk_min.c` usam só `<ntddk.h>`. Isso cobre os campos usados pelos drivers de teste e **não** é uma alegação de compatibilidade com drivers de terceiros.
- Os `.sys` versionados são gerados com `clang-cl`; no run 38163656509 `--check-fixtures` confirmou igualdade byte a byte com rebuild `clang-cl` 19.1.7 e hashes do manifesto. `--check-reproducible` compara builds repetidos do mesmo compilador. Os binários MSVC são verificados e executados separadamente; **não** há igualdade binária exigida entre MSVC e clang-cl.
- `DbgPrint` não imprime; `IoCreateSymbolicLink`/`IoDeleteSymbolicLink` são no-ops; `IofCompleteRequest` (o `IoCompleteRequest` do x64) é um stub mínimo que só zera `PendingReturned`, sem rotinas de conclusão nem desempilhamento da pilha de devices (transferido para a Fase 4); não há I/O manager, `IoCallDriver` nem `DriverExtension` (doc 13, §5).
- Os códigos `0x09`, `0x0A` e `0xC2` são códigos do Windows. Já os subcódigos de `0xC2` e os códigos `0x4E580001` (espera infinita não satisfazível) e `0x4E580002` (`IoDeleteDevice` inválido) são **específicos do Nexus**.
- Todo pool é non-paged. Não há paginação de modo kernel.
- Um único CPU, escalonador cooperativo, sem SMP: nenhum teste de concorrência real.

## 4. Exportações `ntoskrnl` implementadas (superfície de teste, não compatibilidade)

"Testado" significa que existe um teste de host ou de guest que exercita a rotina com as structs do Nexus. **Não** significa compatibilidade com o comportamento do Windows.

| Rotina | Estado |
| :--- | :--- |
| `IoCreateDevice` / `IoDeleteDevice` | Testado: extensão zerada, remoção em qualquer posição, bugcheck em exclusão inválida. Sem nome, sem modo exclusivo, sem contagem de referências. |
| `KeGetCurrentIrql` / `KeRaiseIrql` / `KeLowerIrql` | Testado: direção e limites com bugcheck; roteamento para o CR8. **Sem** mascaramento de interrupções. |
| `KeInitializeSpinLock` / `KeAcquireSpinLock` / `KeReleaseSpinLock` | Testado em um único CPU, com IF=0. |
| `KeInitializeEvent` / `KeSetEvent` / `KeResetEvent` / `KeWaitForSingleObject` | Testado: auto-reset, notification, espera infinita gera bugcheck, timeout finito imediato. **Não bloqueia** (sem threads ou timers). |
| `ExAllocatePoolWithTag` / `ExFreePoolWithTag` / `ExFreePool` | Testado: registro de blocos vivos, bugcheck 0xC2 em tag errada ou double free, esgotamento contado. |
| `IoCompleteRequest`, `RtlInitUnicodeString`, `RtlCopyMemory`, `RtlZeroMemory`, `RtlCompareMemory` | Exercitados pelas fixtures; semântica mínima. |
| `DbgPrint`, `IoCreateSymbolicLink`, `IoDeleteSymbolicLink` | No-ops. |

## 5. Como reproduzir

```bash
cargo test --locked --workspace
python3 scripts/test-hardening-runner.py
cargo build --locked -p nexus-boot --target x86_64-unknown-uefi
python3 scripts/test-hardening.py --ram 256 --cpu max --timeout 120   # exige QEMU + OVMF
```

A evidência versionada são os artefatos `hardening-*` de cada execução do GitHub Actions. O registro das correções e das mutações está em `docs/13-auditoria-fases-3.5-3.7.md`, §10.

## 6. Sem declarações de compatibilidade

Nada aqui declara compatibilidade com Windows, com drivers comerciais, com Linux ou com o Vanguard. Drivers como o `vgk.sys` exigem subsistemas que o Nexus não tem (minifilters, callbacks de objeto, MDLs, `EPROCESS`/`KTHREAD`, atestação TPM), além da aceitação do fornecedor.
