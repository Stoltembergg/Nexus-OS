# Fase 3.5 — Kernel Hardening & Architecture Validation

Estado: **encerrada em 2026-10-11** (`main` em `a06ea9e`), pelos critérios e evidências da seção "Encerramento" no fim deste documento. Escopo: Fases 0–3, sem funcionalidades da Fase 4.

> O encerramento vale **só para a Fase 3.5**. A evidência é de **guest QEMU/OVMF emulado** e de testes de host no CI. **Nada foi validado em hardware físico.** A Fase 3.7 continua aberta (ver `docs/12-phase3.7-nt-driver-hardening.md`). Este documento não declara compatibilidade com Windows, Linux ou Vanguard.

## Plano e critérios de evidência

1. Registrar a linha de base, revisar parsers, ABI, boot, PMM/VMM, traps e scheduler.
2. Reproduzir falhas com regressões antes de corrigi-las. Remover substitutos de sucesso nos testes de host; operações privilegiadas exigem execução real no QEMU.
3. Corrigir validação de imagens/ponteiros/permissões, propriedade de frames, falhas parciais, contexto completo e resultados de traps.
4. Compilar fixtures PE32+/ELF64 externamente em C/assembly, sem headers/bibliotecas Nexus; validar saída, códigos de término, faults e estado da memória no guest.
5. Repetir criação, yield, término e falhas; comparar PMM e heap antes/depois; automatizar QEMU/OVMF com saída controlada pelo guest e validação estrita no host.
6. Atualizar CI, executar checks de host/UEFI/QEMU, revisar diff e só então commitar. Classificar evidências e listar pendências para preempção/SMP/compatibilidade.

## Linha de base (2026-10-11)

- HEAD anterior: `2a5ce36`. Working tree inicialmente limpo.
- `cargo test --workspace`: 24 testes passam, mas o teste de init do kernel simula execução de processos e VMM; não prova isolamento.
- `scripts/test-boot.ps1`: passa no QEMU/OVMF, com dois payloads gerados pelo Nexus e uma leitura supervisor que gera #PF (CR2=0x100000, código=5).
- Auditoria Codex Security Deep Scan não iniciou: `Deep Scan cannot safely start a read-only worker: the parent must provide a managed filesystem permission profile.` Sem resultado independente, sem contagem de tokens disponível. A revisão direta e as regressões abaixo são trabalho local separado.

## Problemas confirmados durante a revisão inicial

- VMM de host retorna sucesso sem mapear e inventa tradução; init/scheduler de host retorna saída 0 sem Ring 3.
- `validate_user_buffer` verifica presença, mas ignora USER/WRITABLE e o argumento de escrita: vazamento de páginas supervisor por syscalls.
- ELF copia até o final do arquivo em vez de `p_filesz`, ignora deslocamento dentro de página e permite entrada/metadados inválidos.
- PE lê optional header truncado sem bounds; ELF permite overflow em tabelas; parsers e mappers carecem de limites/validação.
- NX não aplicado; stack/dados executáveis. SFMASK não limpa DF/TF/AC.
- Yield salva só RIP/RSP; não preserva GPRs, RFLAGS ou estado SIMD. FS/GS podem persistir entre personalidades.
- Exit e fault compartilham o mesmo inteiro; saída normal 14 é interpretada como #PF pelo runner individual.
- #UD lê quatro bytes de RIP sem validar, inclusive na fronteira de página. Stubs não garantem alinhamento da stack de chamada.
- Processos e falhas parciais não liberam frames/tabelas; heap bump nunca recupera objetos.
- PMM libera frames reservados/nunca alocados e arredonda incorretamente reservas não alinhadas; mapas sobrepostos contam frames duplicados.
- Boot/CI aceitam marcadores em logs como prova; sucesso da Fase 3 é impresso mesmo com fault inesperado.

Resultados finais, classificação de componentes e riscos: ver "Encerramento" abaixo.

## Encerramento (2026-10-11)

### Critérios explícitos

A Fase 3.5 é considerada encerrada quando **todos** os critérios abaixo são verdadeiros no `main`:

1. Cada problema listado em "Problemas confirmados durante a revisão inicial" está corrigido no código e tem um teste (de host ou de guest QEMU) capaz de falhar se a correção for revertida.
2. O `main` compila e os testes passam no CI sem passos manuais: `fmt`, `check`, `clippy -D warnings`, testes de host em Linux e Windows, build UEFI e a suíte QEMU/OVMF em 3 configurações.
3. O runner QEMU só aceita sucesso pelo código de saída do guest (`isa-debug-exit` = 33) **e** pelos checks derivados de evidência. Marcadores impressos sem prova não contam, e falhas do guest (pânico, trap em Ring 0, bugcheck NT) terminam a execução com um código de falha nomeado, em vez de esperar o timeout.
4. Os achados da auditoria de encerramento (`docs/13-auditoria-fases-3.5-3.7.md`) que bloqueiam a 3.5 (C1, C2 e C3, mais o item 11 abaixo) estão resolvidos.

### Evidência

| # | Problema (lista acima) | Status | Evidência |
| :--- | :--- | :--- | :--- |
| 1 | VMM/init de host inventando sucesso | Corrigido | `host_does_not_invent_mappings_or_success`; execução de host devolve `UnsupportedPlatform` (doc 13, §3). |
| 2 | `validate_user_buffer` ignorava USER/WRITABLE | Corrigido | Permissões efetivas nos 4 níveis; QEMU `NEXUS_CHECK:permissions`. |
| 3 | ELF copiando além de `p_filesz` / entrada inválida | Corrigido | Teste `rejects_truncated_segments_filesz_exceeding_memsz_and_bad_entry`; QEMU `loader-bytes`. |
| 4 | PE/ELF sem limites | Corrigido | `tests/adversarial.rs` (truncamentos e 2048 mutações). O loader de drivers passou a propagar os erros (PR #4, achado A1). |
| 5 | NX e SFMASK | Corrigido | QEMU `msrs` e `permissions` (EFER.NXE, `SFMASK=0x44700`). |
| 6 | Yield salvando só RIP/RSP; FS/GS | Corrigido | QEMU `context` (GPRs, RFLAGS, FXSAVE, FS/GS). |
| 7 | Exit e fault com o mesmo inteiro | Corrigido | `RunOutcome::{Exit,Fault,Yield}`; QEMU `exit-and-boundary`. |
| 8 | #UD lendo RIP; stack desalinhada | Corrigido | QEMU `exit-and-boundary` (#UD na fronteira de página). |
| 9 | Frames e heap não recuperados | Corrigido | QEMU `stress`: 64 ciclos, frames e heap iguais à linha de base. |
| 10 | PMM liberando reservados / arredondamento | Corrigido | 4 testes unitários do PMM. |
| 11 | Boot/CI aceitando marcadores | Corrigido | PR #5: os marcadores de driver só são impressos depois dos checks `driver-wx`, `driver-lifecycle` (e, a partir do PR #6, `nt-semantics`), que o runner exige. Pânico, trap em Ring 0 e bugcheck NT saem com os status 35, 37 e 39, e o runner tem testes negativos (`scripts/test-hardening-runner.py`). |
| C1–C3 | `main` sem compilar; CI nunca verde | Corrigido | PR #3: dependência `libc` e `rust-toolchain.toml` fixando a 1.98.0. |

**CI verde no `main`, 5 de 5 jobs** (Host checks ubuntu-latest e windows-latest; QEMU/OVMF 128 MiB qemu64 debug, 256 MiB max debug e 512 MiB max release) depois de cada PR:

| PR | Commit em `main` | Execução do CI |
| :--- | :--- | :--- |
| #3 (build e toolchain) | `2040ea5` | https://github.com/Stoltembergg/Nexus-OS/actions/runs/38139029100 |
| #4 (loader fail-closed) | `02a9db8` | https://github.com/Stoltembergg/Nexus-OS/actions/runs/38139872922 |
| #5 (veracidade dos testes) | `7152e44` | https://github.com/Stoltembergg/Nexus-OS/actions/runs/38141055427 |
| #6 (semântica NT mínima) | `a06ea9e` | https://github.com/Stoltembergg/Nexus-OS/actions/runs/38142055810 |

Os artefatos `hardening-*` de cada execução (`serial.log`, `qemu.log`, `result.json`) são a evidência versionada e reproduzível. Os logs locais citados no doc 13 não estão versionados.

### Riscos residuais (não bloqueiam a 3.5, mas continuam abertos)

- **Toolchain fixa em 1.98.0** (issue #2): o kernel ainda linka `std` no alvo UEFI (doc 13, M9). A correção de fundo é migrar para `no_std` + `alloc`. O pin explícito no workflow do CI está pendente, porque o token não tem permissão de workflow.
- **Escalonador cooperativo, um único CPU, interrupções desabilitadas (IF=0).** Preempção, SMP, APIC e timers são escopo da Fase 4. A 3.5 não prova nada sobre concorrência.
- **Somente QEMU/OVMF (TCG).** Nenhum teste em hardware físico.
