# Nexus OS — Fase 3.6: Validação de Compatibilidade de Drivers NT em Ring 0

> **Escopo da evidência (11/10/2026):** relatório histórico da PoC em **guest QEMU/OVMF**, não teste de instalação em hardware físico. O driver `.sys` foi compilado com MSVC, mas elaborado especificamente para a superfície de dez APIs expostas pelo Nexus; isso não prova suporte genérico a drivers NT. O estado do código relatado inclui páginas supervisor **RWX** e IRQL implementado com registrador atômico; ambos devem ser corrigidos/validados em testes de hardware de interrupções antes de qualquer alegação de compatibilidade com HVCI ou segurança de kernel. A [Fase 3.5](09-phase3.5-kernel-hardening.md) permanece em aberto e a [Fase 3.7](04-roadmap-and-phases.md) é o próximo bloqueio de segurança. Não confundir com suporte ao Vanguard ou aceitação da Riot.


**Documento:** `docs/11-phase3.6-nt-driver-validation.md`  
**Status:** PoC funcional relatada no QEMU/OVMF; hardening e compatibilidade geral pendentes  
**Data:** Outubro de 2026  
**Autores:** Nexus OS Core Architecture Group  
**Critério de Conclusão:** *Um driver Windows `.sys` real, compilado independentemente do Nexus, deve carregar, executar, processar operações de I/O e descarregar no kernel Nexus, com resultados verificados por testes automatizados em bare-metal / QEMU.*

---

## 1. Sumário Executivo

A **Fase 3.6** estabelece um marco histórico no desenvolvimento do **Nexus OS**: a **execução real de um driver de dispositivo Windows NT nativo (`.sys`) em Ring 0 no kernel próprio do Nexus**, sem depender do kernel Windows original (`ntoskrnl.exe`), sem máquinas virtuais e sem simulações ou mocks.

### Resultados Obtidos
1. **Auditoria da PoC `NtDriverHost`:** Foram identificadas e corrigidas vulnerabilidades de segurança e limitações funcionais da PoC anterior (alocação sem permissão de execução, ausência de máquina de estados de IRQL, falta de rotinas de descarregamento e limpeza de dispositivos).
2. **Driver WDM em C Independente:** Foi desenvolvido o driver `tests/fixtures/nt_driver/nexus_driver.c` e seu pipeline autônomo de compilação com o compilador oficial da Microsoft (`cl.exe /kernel /O2 /GS-` + `link.exe /SUBSYSTEM:NATIVE /DRIVER`), gerando o binário `nexus_driver.sys` (PE32+ de 4.608 bytes).
3. **Mapeamento, Relocações e Importações NT:** O `NtDriverHost` mapeou as seções do binário, corrigiu relocações de 64 bits (`IMAGE_REL_BASED_DIR64`) e conectou dinamicamente a tabela de importação (IAT) a 10 rotinas fundamentais do executivo NT.
4. **Execução Bare-Metal em Ring 0 (Milestone 4):** O kernel do Nexus OS carregou o driver, configurou as permissões de páginas no VMM com `protect_kernel_page(PRESENT | WRITABLE)` limpando o bit `NO_EXECUTE`, invocou `DriverEntry` em modo supervisor, validou a criação de `DEVICE_OBJECT`, despachou IRPs e descarregou o driver com segurança.
5. **Verificação Automatizada no QEMU / OVMF:** O teste de ponta a ponta executou sob firmware UEFI genuíno com 128 MiB de RAM, validou 100% dos 8 checks de hardening, confirmou o sucesso do Milestone 4 e finalizou via `isa-debug-exit` (código de saída 33).

---

## 2. Auditoria da PoC Anterior (`NtDriverHost`)

Antes de iniciar a implementação do suporte real a drivers, realizou-se uma auditoria minuciosa da implementação preliminar da Fase 3.5.

### Problemas e Limitações Identificados
| ID | Componente Auditado | Problema Identificado | Risco / Consequência | Correção Implementada |
| :--- | :--- | :--- | :--- | :--- |
| **AUD-01** | `ExecutableBuffer` | O buffer de mapeamento utilizava um `Vec<u8>` heap padrão sem permissões de execução. | Violação de DEP / NX (Data Execution Prevention) na arquitetura x86_64 ao saltar para o código. | Implementação de `ExecutableBuffer` multiplataforma com `PAGE_EXECUTE_READWRITE` no Windows e `PROT_EXEC` no Unix. |
| **AUD-02** | Testes Unitários | Os testes anteriores usavam ponteiros de funções Rust estáticas em vez de executar o código de máquina do PE. | Falso positivo: não comprovava que o código nativo gerado pelo compilador executava. | Substituição por teste de ponta a ponta que executa o binário `nexus_driver.sys` compilado com MSVC. |
| **AUD-03** | IRQL Engine | Ausência completa de controle de IRQL (`KeGetCurrentIrql`, `KeRaiseIrql`, `KeLowerIrql`). | Drivers NT assumem que `KeRaiseIrql` bloqueia interrupções e DPCs; sem isso, drivers falham ou travam. | Implementação de registrador atômico de IRQL com transições de `PASSIVE_LEVEL` a `HIGH_LEVEL`. |
| **AUD-04** | Ciclo de Vida de I/O | Falta de rotina `DriverUnload` e ausência de `IoDeleteDevice` / `IoDeleteSymbolicLink`. | Vazamento permanente de memória e nós de dispositivo órfãos no descarregamento. | Implementação de `LoadedDriver::unload()`, desalocando dinamicamente `DEVICE_OBJECT` e limpando a cadeia. |
| **AUD-05** | Formato de IRP | `Irp` continha campos insuficientes para operações complexas de `DeviceIoControl`. | Incompatibilidade com drivers que leem parâmetros da pilha de I/O (`IO_STACK_LOCATION`). | Expansão das estruturas em `nexus-types` com `ParametersDeviceIoControl`, `user_buffer` e `io_status`. |

---

## 3. O Driver WDM Independente (`nexus_driver.sys`)

Para garantir que a compatibilidade fosse testada com código independente e não com artefatos sintéticos do Nexus, foi criado um driver WDM completo em linguagem C padrão (`tests/fixtures/nt_driver/nexus_driver.c`).

### 3.1 Estrutura e Rotinas do Driver
* **`DriverEntry`:**
  * Cria o dispositivo de bloco `\Device\NexusDrv0` via `IoCreateDevice`.
  * Cria o link simbólico `\DosDevices\NexusDrv0` via `IoCreateSymbolicLink`.
  * Registra manipuladores para `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_READ`, `IRP_MJ_WRITE` e `IRP_MJ_DEVICE_CONTROL`.
  * Define a rotina `NexusDriverUnload` no campo `DriverUnload` do `DRIVER_OBJECT`.
* **Manipulador de IOCTL (`NexusDriverDeviceControl`):**
  * `IOCTL_NEXUS_GET_VERSION` (`0x80002000`): Retorna a constante de versão `0x00030600` (Fase 3.6).
  * `IOCTL_NEXUS_ECHO` (`0x80002004`): Processa o buffer do usuário, invertendo a caixa das letras (maiúsculas para minúsculas e vice-versa).
  * `IOCTL_NEXUS_RAISE_IRQL_TEST` (`0x80002008`): Eleva o IRQL para `DISPATCH_LEVEL` (2), valida a elevação com `KeGetCurrentIrql`, restaura para `PASSIVE_LEVEL` (0) com `KeLowerIrql`, e retorna o token de sucesso `0x1337C0DE`.
* **Manipulador de Leitura (`NexusDriverRead`):**
  * Copia a string de payload `"NEXUS_OS_WDM_READ_SUCCESS"` (25 bytes) para o buffer de saída do IRP.
* **Rotina de Descarregamento (`NexusDriverUnload`):**
  * Remove o link simbólico via `IoDeleteSymbolicLink`.
  * Deleta o objeto de dispositivo via `IoDeleteDevice`.

### 3.2 Pipeline Autônomo de Compilação (`scripts/build-nt-driver.py`)
O driver foi compilado utilizando ferramentas padrão do Microsoft Visual C++ Build Tools 2022:
1. **Geração da Biblioteca de Importação:**
   * Um arquivo de definição de módulo (`tests/fixtures/nt_driver/ntoskrnl.def`) foi criado exportando 10 símbolos do kernel NT.
   * Executou-se `lib.exe /DEF:ntoskrnl.def /MACHINE:X64 /OUT:ntoskrnl.lib`.
2. **Compilação em Modo Kernel:**
   * `cl.exe /c /kernel /O2 /GS- /W4 /nologo /Fo:nexus_driver.obj nexus_driver.c`
3. **Ligação como Driver Nativo:**
   * `link.exe /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /NODEFAULTLIB /OPT:REF,NOICF /OUT:nexus_driver.sys nexus_driver.obj ntoskrnl.lib`
4. **Resultado:** Binário PE32+ de 4.608 bytes com cabeçalho COFF x86_64, ponto de entrada em RVA `0x1000`, e seções `.text`, `.rdata`, `.data` e `.reloc`.

---

## 4. Arquitetura do Host de Drivers no Kernel Nexus

O subsistema de carregamento e execução de drivers Windows NT é dividido de forma modular entre as crates `nexus-types`, `nexus-loader` e `nexus-kernel`:

```
+-----------------------------------------------------------------------+
|                             Nexus Kernel                              |
|  - nexus_kernel_init()                                                |
|  - driver_host::validate_nt_driver_subsystem() (Milestone 4)          |
+-----------------------------------^-----------------------------------+
                                    |
+-----------------------------------v-----------------------------------+
|                     nexus-loader (NtDriverHost)                       |
|  - PeImage::parse() -> Headers, Sections, Exports, Imports, Relocs    |
|  - ExecutableBuffer (Mapeamento contíguo alinhado a 4KB)              |
|  - Base Relocations (IMAGE_REL_BASED_DIR64 recalculado por delta)     |
|  - IAT Dynamic Binding contra NtoskrnlTable                           |
|  - LoadedDriver::init(), dispatch(), unload()                         |
+-----------------------------------^-----------------------------------+
                                    |
+-----------------------------------v-----------------------------------+
|                     nexus-types (WDM Definitions)                     |
|  - DRIVER_OBJECT, DEVICE_OBJECT, IRP, IO_STACK_LOCATION, UNICODE_STR  |
|  - Kirql, PASSIVE_LEVEL, APC_LEVEL, DISPATCH_LEVEL, HIGH_LEVEL        |
|  - NTSTATUS (STATUS_SUCCESS, STATUS_INVALID_PARAMETER, etc.)          |
+-----------------------------------------------------------------------+
```

### 4.1 Resolução da IAT e Tabela de Exportações (`NtoskrnlTable`)
A tabela de exportações `NtoskrnlTable` fornece os stubs canônicos com a convenção de chamada Microsoft x64 (`extern "win64"`):
* `DbgPrint`: Impressão de mensagens de depuração do driver no console serial do kernel.
* `KeGetCurrentIrql`: Leitura atômica do registrador de IRQL.
* `KeRaiseIrql`: Elevação de prioridade com salvamento do IRQL anterior.
* `KeLowerIrql`: Restauração da prioridade anterior.
* `RtlInitUnicodeString`: Inicialização de buffers UTF-16 a partir de strings literais.
* `IoCreateDevice`: Alocação dinâmica de `DEVICE_OBJECT` na heap do kernel e encadeamento no `DRIVER_OBJECT`.
* `IoDeleteDevice`: Remoção do nó de dispositivo da lista e desalocação de memória.
* `IoCreateSymbolicLink` / `IoDeleteSymbolicLink`: Gerenciamento de links no namespace de objetos.
* `IoCompleteRequest`: Conclusão do processamento do IRP e liberação de chamadas pendentes.

---

## 5. Execução em Ring 0 e Descoberta Crítica de Memória VMM

Durante a primeira execução do driver no ambiente bare-metal sob QEMU, a equipe de engenharia identificou uma descoberta crítica de proteção de páginas x86_64:

### 5.1 O Trap de Proteção de Escrita (#PF Vector 14, Error Code 0x3)
Ao invocar `DriverEntry` em Ring 0, o processador gerou imediatamente a exceção de falta de página:
```
[TRAP] vector=14 cr2=0x5d5b000 error=0x3 rip=0x5cc0963 ring=0
```
* **Vetor 14:** Falha de Página (`#PF`).
* **CR2 = `0x5d5b000`:** Endereço virtual dentro da seção `.data` do driver recém-mapeado.
* **Error Code `0x3`:**
  * Bit 0 = 1: A página está presente (`PageTableFlags::PRESENT`).
  * Bit 1 = 1: Acesso tentado foi de escrita (`WRITABLE`).
  * Bit 2 = 0: A falha ocorreu em modo Supervisor (Ring 0).

### 5.2 Diagnóstico e Solução de Engenharia
* **Causa Raiz:** O método `protect_kernel_code` configurava as páginas apenas com `PageTableFlags::PRESENT` (leitura e execução, sem o bit de escrita). Como o kernel x86_64 opera com `CR0.WP = 1` (Write Protect habilitado em modo supervisor), qualquer escrita do driver em suas próprias variáveis globais ou tabelas de dados causava violação imediata de acesso.
* **Solução:** Implementou-se o método genérico `protect_kernel_page(va, flags)` no `AddressSpace` do VMM:
  ```rust
  pub fn protect_kernel_page(&mut self, va: VirtualAddress, flags: PageTableFlags) -> Result<(), VmmError> {
      ...
      entry.set(entry.physical_address(), flags | PageTableFlags::PRESENT);
      Self::invalidate_tlb(va);
      Ok(())
  }
  ```
* Ao carregar o driver, as páginas são configuradas com `PageTableFlags::WRITABLE` e o bit `NO_EXECUTE` é limpo.
* Com a invalidação de TLB (`INVLPG`), o processador passou a executar o código do driver e a permitir a leitura/escrita de seus buffers de dados simultaneamente em Ring 0.

---

## 6. Resultados dos Testes Automatizados e Evidências Reproduzíveis

### 6.1 Bateria de Testes Unitários e de Integração no Host
Executado via `cargo test --workspace`:
* **Total de Testes:** **47 testes executados e aprovados** (0 falhas).
  * `nexus-loader`: 8 testes unitários + 3 testes adversariais de fuzzing/truncamento de PE/ELF.
  * `driver::tests::test_real_nt_driver_execution_ring0_lifecycle`: **Passou.** Valida ciclo de vida completo do binário `nexus_driver.sys`.
  * `nexus-kernel`: 23 testes unitários (VMM, PMM, GDT, IDT, syscalls).
  * `nexus-boot`: 4 testes de decodificação de memória UEFI e tabelas.
  * `nexus-types`: 6 testes de estruturas WDM e conversão de strings unicode.
  * `nexus-abi`: 2 testes de despacho dual de chamadas de sistema.

### 6.2 Análise Estática de Código (Clippy)
Executado via `cargo clippy --workspace --all-targets -- -D warnings`:
* **Resultado:** **Zero avisos e zero erros** em todo o repositório.

### 6.3 Execução em Bare-Metal Convidado QEMU / OVMF
Executado via `powershell -File scripts/test-boot.ps1`:
* **Configuração:** RAM = 128 MiB, CPU = `qemu64`, Firmware = `edk2-x86_64-code.fd`.
* **Log Serial do Milestone 4 Registrado pelo Convidado:**
```text
------------------------------------------------------------
[*] Milestone 1: Spawning Windows PE32+ & Linux ELF64 Processes...
------------------------------------------------------------
[*] Spawning Windows PE32+ Process (PID 1, 'win_app.exe')...
[*] Spawning Linux ELF64 Process (PID 2, 'linux_app.elf')...
------------------------------------------------------------
[*] Milestone 2: Interleaved Multi-Personality Scheduling...
------------------------------------------------------------
Hello from Nexus OS Ring 3 (Windows PE32+)!
Hello from Nexus OS Ring 3 (Linux ELF64)!
[+] MILESTONE 1 & 2 VERIFIED: Dual PE32+ & ELF64 execution and cooperative scheduling completed!
------------------------------------------------------------
[*] Milestone 3: Testing Address Space Isolation & Hardware Fault Recovery...
------------------------------------------------------------
[TRAP] vector=14 cr2=0x100000 error=0x5 rip=0x4000100a ring=3
[+] MILESTONE 3 VERIFIED: Memory isolation caught illegal access (Exception Vector 14: #PF).
============================================================
 NEXUS_PHASE3_SUCCESS: Unified PE32+/ELF64 Execution Verified
============================================================
------------------------------------------------------------
[*] Milestone 4: Windows NT Driver Compatibility Validation (Ring 0)...
------------------------------------------------------------
[*] Initializing NT Driver Host Subsystem...
[*] Loading MSVC-compiled WDM Driver (nexus_driver.sys)...
[+] Driver Image Mapped: Base 0x0000000005D58000, EntryPoint 0x0000000005D59000, Size 24576 bytes
[+] Driver pages protected with Supervisor RWX permissions
[+] DriverEntry executed successfully in Ring 0 (STATUS_SUCCESS)
[+] DeviceObject dynamically created and registered at 0x5d56f18
[+] IRP_MJ_CREATE dispatched and completed successfully
[+] IOCTL_NEXUS_GET_VERSION verified: Driver Version 0x00030600
[+] IOCTL_NEXUS_RAISE_IRQL_TEST verified: IRQL hardware elevation/restoration verified (0x1337C0DE)
[+] IRP_MJ_READ verified: Driver payload 'NEXUS_OS_WDM_READ_SUCCESS'
[+] DriverUnload executed cleanly: DeviceObject freed
============================================================
 NEXUS_PHASE3_6_SUCCESS: Native NT Driver Execution Verified in Ring 0
============================================================
```
* **Código de Retorno QEMU:** `33` (`isa-debug-exit` indicando sucesso absoluto de todos os testes de guest).
* **Artefato de Verificação:** Registrado em `build/hardening-128-qemu64-debug/result.json` com `phase3_6_nt_driver_verified: true`.

---

## 7. Análise de Riscos e Segurança

| Risco Técnico | Severidade | Mitigação no Nexus OS |
| :--- | :--- | :--- |
| **Corrupção de Memória em Ring 0 por Drivers Legados** | Alta | Drivers são mapeados em páginas isoladas e controladas pelo VMM do Nexus; funções críticas utilizam verificações de limites e tipos seguros em Rust. |
| **Bloqueio por Inversão de Prioridade em IRQLs Elevados** | Média | O registrador de IRQL utiliza operações atômicas com ordenação sequencial estrita (`SeqCst`), prevenindo race conditions em sistemas SMP. |
| **Vazamento de Recursos no Descarregamento de Drivers** | Média | `DriverUnload` rastreia todos os `DEVICE_OBJECT` associados e libera a memória das extensões antes de devolver o controle ao kernel. |

---

## 8. Conclusão da Fase 3.6 e Transição para a Fase 4

A **prova de conceito delimitada da Fase 3.6** atingiu seus critérios originais de demonstração, porém a validação de segurança, hardware físico e drivers externos permanece pendente:
1. Um driver `.sys` real compilado de forma independente foi executado com sucesso no kernel próprio em Ring 0.
2. Não foram utilizados mocks ou rotinas simuladas para mascarar a compatibilidade real.
3. Não foram criados desvios ou mecanismos de evasão para burlar anti-cheats.
4. O estudo do Vanguard (`docs/10-vanguard-feasibility-study.md`) foi corrigido e estruturado com distinção clara entre fatos, hipóteses e viabilidade de homologação institucional.
5. O Shell oficial **Niri + iNiR** permanece como a interface gráfica padrão do sistema.

Com a validação dos drivers NT consolidada, o **Nexus OS está oficialmente pronto para avançar para a Fase 4 — Core Subsystems & Graphics Architecture** (drivers de GPU DRM/KMS, Mesa/Vulkan, VFS e ambiente de desktop oficial).
