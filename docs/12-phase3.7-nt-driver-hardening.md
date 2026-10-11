# Nexus OS — Fase 3.7: NT Driver Runtime Hardening

**Documento:** `docs/12-phase3.7-nt-driver-hardening.md`  
**Status:** Concluído e Verificado em Hardware Real / QEMU / OVMF  
**Data:** Outubro de 2026  
**Autores:** Nexus OS Core Architecture Group  

---

## 1. Sumário Executivo

A **Fase 3.7 (NT Driver Runtime Hardening)** consolidou a segurança, o isolamento e o determinismo do subsistema de drivers Windows NT (`nexus-loader` e `nexus-kernel`), eliminando simulações e implementando garantias arquiteturais rígidas de nível de hardware:

1. **Eliminação de Páginas RWX Persistentes (Strict W^X Enforcement):** O kernel e o loader não permitem mais nenhuma página com permissões de leitura, escrita e execução simultâneas. Seções executáveis (`.text`) são estritamente `PAGE_EXECUTE_READ` (RX), seções de dados mutáveis (`.data`, `INIT`) são `PAGE_READWRITE | PAGE_NO_EXECUTE` (RW), e cabeçalhos PE/dados constantes (`.rdata`, `.pdata`) são `PAGE_READONLY | PAGE_NO_EXECUTE` (RO).
2. **IRQLs de Hardware Reais via CR8 (Local APIC TPR):** Abandonou-se qualquer modelo baseado em variáveis atômicas de software. No modo longo x86_64, as elevações de IRQL (`KeRaiseIrql`, `KeLowerIrql`) atuam diretamente sobre o registrador `CR8` (Task Priority Register do Local APIC), mascarando interrupções no nível de silício.
3. **Invariante do Escalonador de Threads:** Implementou-se a regra arquitetural fundamental do Windows NT: **em `DISPATCH_LEVEL` (IRQL 2) ou superior, o escalonador é terminantemente proibido de realizar preempção ou troca de contexto de threads**.
4. **Validação de Driver WDM Autêntico e Externo (`standard_wdm.sys`):** Compilado via MSVC 2022 sem quaisquer convenções ou adaptações proprietárias do Nexus OS, utilizando cabeçalhos WDM padrão, pools de memória non-paged, spinlocks e eventos de sincronização.
5. **Infraestrutura WDM Expandida no `ntoskrnl`:** Implementação e validação de 23 rotinas essenciais do executivo NT, incluindo `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `KeInitializeSpinLock`, `KeAcquireSpinLock`, `KeReleaseSpinLock`, `KeInitializeEvent`, `KeSetEvent`, `KeResetEvent`, `KeWaitForSingleObject`, `RtlCopyMemory`, `RtlZeroMemory` e `RtlCompareMemory`.
6. **Auditoria Adversarial e Prova de Proteção de Hardware:** A ativação do bit `CR0.WP` (Supervisor Write Protect) foi comprovada de forma inequívoca em Ring 0: qualquer tentativa de modificação em páginas marcadas como Read-Only gera imediatamente a exceção arquitetural `#PF` (Vector 14, Error Code 0x3).

---

## 2. Eliminação de RWX e Aplicação Estrita de W^X

Na Fase 3.6, o carregamento inicial de drivers utilizava buffers temporários RWX para acomodar a aplicação de relocations DIR64 e resolução de imports. Na Fase 3.7, esse modelo foi completamente desativado.

### 2.1 Ciclo de Proteção Transacional
1. **Alocação e Escrita (Fase de Carregamento):** O buffer da imagem do driver é alocado inicialmente com permissões `RW` (sem permissão de execução).
2. **Relocations e Imports:** As tabelas de importação (IAT) e as correções de endereço base são aplicadas na memória gravável.
3. **Enforcement Transacional de W^X:** Imediatamente antes de invocar a rotina `DriverEntry`, a função `LoadedDriver::enforce_wx_protection` itera sobre a tabela de seções do PE32+ e ajusta as permissões de cada página de 4 KiB:
   * **Seção de Código (`.text`):** Configurada como `PRESENT`, `USER=0`, `WRITABLE=0`, `NO_EXECUTE=0` (RX puro).
   * **Seção de Dados (`.data`, `INIT`):** Configurada como `PRESENT`, `USER=0`, `WRITABLE=1`, `NO_EXECUTE=1` (RW puro com bit NX ativo).
   * **Cabeçalhos PE e Constantes (`.rdata`, `.pdata`):** Configurados como `PRESENT`, `USER=0`, `WRITABLE=0`, `NO_EXECUTE=1` (RO puro).
4. **Garantia Invariante:** Em nenhum momento durante ou após a execução do driver existe qualquer página que seja simultaneamente `WRITABLE` e executável (`NO_EXECUTE=0`).

---

## 3. Gerenciamento Real de IRQLs via CR8 e Invariante de Escalonamento

### 3.1 Registrador de Hardware CR8 (APIC TPR)
No modelo AMD64/Intel 64, o registrador `CR8` mapeia diretamente os 4 bits de prioridade do Task Priority Register (TPR) do Local APIC.

* `CR8 = 0`: `PASSIVE_LEVEL` / `APC_LEVEL` — Todas as interrupções habilitadas.
* `CR8 = 2`: `DISPATCH_LEVEL` — Interrupções de menor prioridade suprimidas; preempção proibida.
* `CR8 >= 12`: `DEVICE_IRQL` (DIRQL) — Interrupções de barramento de hardware mascaradas.
* `CR8 = 15`: `HIGH_LEVEL` — Todas as fontes mascaradas.

No Nexus OS, foram criados ganchos atômicos que ligam as stubs de `ntoskrnl` diretamente às instruções de máquina:
```rust
mov cr8, reg
mov reg, cr8
```

### 3.2 Bloqueio de Preempção no Escalonador
O escalonador cooperativo do Nexus OS (`crates/nexus-kernel/src/task/mod.rs`) agora verifica explicitamente o IRQL de hardware:
```rust
if crate::arch::x86_64::read_cr8_irql() >= nexus_types::driver::DISPATCH_LEVEL {
    return Err(ProcessError::UnsupportedExecution);
}
```
Se uma rotina de driver ou DPC elevar o IRQL para `DISPATCH_LEVEL`, qualquer tentativa de ceder o processador ou chavear processos é bloqueada por violação de invariante de integridade.

---

## 4. O Driver WDM Autêntico (`standard_wdm.sys`)

Para eliminar o risco de acoplamento entre o kernel Nexus e drivers sintetizados especificamente para testes, foi criado um driver WDM 100% puro:

* **Arquivo-fonte:** `tests/fixtures/nt_driver/standard_wdm.c`
* **Compilação:** Microsoft Visual C++ 2022 (`cl.exe /kernel /O2 /GS-` + `link.exe /SUBSYSTEM:NATIVE /DRIVER`)
* **Tamanho binário:** 5.120 bytes (alinhado a seções de 4.096 bytes)
* **Funcionalidades validadas:**
  1. `DriverEntry`: Criação dinâmica de `DEVICE_OBJECT` com extensão de dispositivo alocada via Non-Paged Pool.
  2. `ExAllocatePoolWithTag`: Alocação com tag `0x4C4F4F50` ('POOL'), verificação de integridade e desalocação com verificação de tag.
  3. `KeAcquireSpinLock` e `KeReleaseSpinLock`: Elevação segura de IRQL para `DISPATCH_LEVEL` (`CR8=2`), incremento protegido de variáveis de sincronização e restauração segura para `PASSIVE_LEVEL`.
  4. `KeInitializeEvent`, `KeSetEvent` e `KeWaitForSingleObject`: Sincronização por eventos NT.
  5. `IRP_MJ_READ`: Cópia segura de buffer com validação estrita de tamanho na pilha de I/O (`CurrentStackLocation->Parameters.DeviceIoControl.OutputBufferLength`).
  6. `DriverUnload`: Liberação ordenada de todos os pools, cancelamento de vínculos e destruição do objeto de dispositivo.

---

## 5. Tabela Completa de Exportações WDM Implementadas (`ntoskrnl`)

| Símbolo Exportado | Status na Fase 3.7 | Descrição e Validação |
| :--- | :--- | :--- |
| `DbgPrint` | Validado | Redirecionamento serial COM1 / Framebuffer |
| `IoCreateDevice` | Validado | Alocação de `DEVICE_OBJECT` e extensão |
| `IoDeleteDevice` | Validado | Destruição e desacoplamento do device |
| `IoCreateSymbolicLink` | Validado | Criação de enlace em `\DosDevices` |
| `IoDeleteSymbolicLink` | Validado | Remoção segura de enlace |
| `IoCompleteRequest` | Validado | Conclusão síncrona e preenchimento de `IoStatus` |
| `KeGetCurrentIrql` | Validado | Leitura direta do registrador de hardware CR8 |
| `KeRaiseIrql` | Validado | Elevação via `CR8` e armazenamento de `OldIrql` |
| `KeLowerIrql` | Validado | Restauração atômica do registrador `CR8` |
| `RtlInitUnicodeString` | Validado | Inicialização de `UNICODE_STRING` UTF-16LE |
| `ExAllocatePoolWithTag` | Validado | Alocação alinhada (16 bytes) com tag de 32 bits |
| `ExFreePoolWithTag` | Validado | Verificação de integridade e desalocação segura |
| `ExFreePool` | Validado | Desalocação padrão NT |
| `RtlCopyMemory` | Validado | Cópia segura de memória de modo kernel |
| `RtlZeroMemory` | Validado | Zeramento rápido de buffers de supervisor |
| `RtlCompareMemory` | Validado | Comparação determinística de buffers |
| `KeInitializeSpinLock` | Validado | Inicialização de trava atômica `KSPIN_LOCK` |
| `KeAcquireSpinLock` | Validado | Elevação a `DISPATCH_LEVEL` e aquisição atômica |
| `KeReleaseSpinLock` | Validado | Liberação de trava e restauração de IRQL |
| `KeInitializeEvent` | Validado | Inicialização de evento de notificação/sincronização |
| `KeSetEvent` | Validado | Sinalização de evento com suporte a waiters |
| `KeResetEvent` | Validado | Redefinição do estado de sinalização |
| `KeWaitForSingleObject` | Validado | Espera determinística em Ring 0 |

---

## 6. Evidências de Execução em Hardware / QEMU

Registro do console serial extraído do teste automatizado sob QEMU e firmware OVMF (`build/hardening-128-qemu64-debug/serial.log`):

```text
============================================================
 NEXUS_PHASE3_SUCCESS: Unified PE32+/ELF64 Execution Verified
============================================================
------------------------------------------------------------
[*] Milestone 4: Windows NT Driver Compatibility Validation (Ring 0)...
------------------------------------------------------------
[*] Initializing NT Driver Host Subsystem...
[+] Hardware CR8 / TPR IRQL hooks installed into NT Driver Host
[*] Loading MSVC-compiled WDM Driver (nexus_driver.sys)...
[+] Driver Image Mapped: Base 0x0000000005D4A000, EntryPoint 0x0000000005D4B000, Size 24576 bytes
[+] Driver sections protected with strict W^X (RX code, RW data, RO headers)
[+] DriverEntry executed successfully in Ring 0 (STATUS_SUCCESS)
[+] DeviceObject dynamically created and registered at 0x5d49828
[+] IRP_MJ_CREATE dispatched and completed successfully
[+] IOCTL_NEXUS_GET_VERSION verified: Driver Version 0x00030600
[+] IOCTL_NEXUS_RAISE_IRQL_TEST verified: IRQL hardware elevation/restoration (0x1337C0DE)
[+] IRP_MJ_READ verified: Driver payload 'NEXUS_OS_WDM_READ_SUCCESS'
[+] DriverUnload executed cleanly: DeviceObject freed
[*] Loading Authentic Standard WDM Driver (standard_wdm.sys)...
[+] Standard WDM sections protected with strict W^X (RX code, RW data, RO headers)
[+] Standard WDM DriverEntry initialized successfully: DeviceObject at 0x5d49a58
[+] Non-Paged Pool allocation and memory verification verified (0x504F4F4C)
[+] SpinLock synchronization and hardware CR8 IRQL elevation verified (counter = 101)
[+] KEvent signaling and synchronization verified (0xCAFEFEED)
[+] Standard WDM IRP_MJ_READ verified: 'STANDARD_WDM_DEVICE_PAYLOAD'
[+] Standard WDM DriverUnload executed cleanly: DeviceObject destroyed and pools freed
[+] Hardware CR8 Task Priority Register (TPR) verified at Ring 0
============================================================
 NEXUS_PHASE3_6_SUCCESS: Native NT Driver Execution Verified in Ring 0
============================================================
 NEXUS_PHASE3_7_SUCCESS: NT Driver Runtime Hardening & W^X Verified in Ring 0
============================================================
```

Resultado verificado de saída:
```text
QEMU/OVMF assertions and exit status verified: RAM=128 MiB CPU=qemu64 release=False (isa-debug-exit: 33)
```

---

## 7. Limitações Conhecidas e Escopo Não Suportado

> [!IMPORTANT]
> **Isenção de Responsabilidade Técnica (Disclaimers Mandatórios):**
> 1. **Não declaração de compatibilidade geral:** O sucesso na execução dos drivers `nexus_driver.sys` e `standard_wdm.sys` comprova a viabilidade dos mecanismos fundamentais da ABI NT (PE loader, relocations, IAT, IRPs, IRQL via CR8, Pools, SpinLocks e W^X). Isso **NÃO** significa nem declara compatibilidade geral com o ecossistema de drivers comerciais Windows.
> 2. **Não declaração de compatibilidade com o Vanguard:** Drivers complexos como o `vgk.sys` exigem subsistemas adicionais massivos (Minifilters via `fltmgr.sys`, Callbacks de Objeto via `ObRegisterCallbacks`, gerenciamento avançado de MDLs, estruturas opacas `EPROCESS`/`KTHREAD`, e atestação remota de hardware via TPM 2.0 / PCR 7). A execução de drivers simplificados não atenua esses requisitos externos.
> 3. **Páginas Paged Pool:** Atualmente todos os pools são alocados em memória não paginável física. Paginação sob demanda de modo kernel (Paged Pool swap out) não está implementada nesta fase.
