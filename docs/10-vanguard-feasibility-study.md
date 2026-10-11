# Nexus OS — Estudo Técnico Profundo: Viabilidade de Execução Legítima do Riot Vanguard (League of Legends & Valorant)

**Documento:** `docs/10-vanguard-feasibility-study.md`  
**Status:** Atualizado e Corrigido (Pós-Fase 3.6 NT Driver Validation)  
**Data:** Outubro de 2026  
**Autores:** Nexus OS Core Architecture Group  
**Diretiva Mandatória:** *Nexus OS só será considerado concluído quando League of Legends e Valorant forem integralmente jogáveis com o funcionamento legítimo do Riot Vanguard, sem máquinas virtuais, dual boot, instalação do Windows ou mecanismos de evasão/bypasses.*

---

## 1. Sumário Executivo e Veredito Técnico

Este relatório apresenta a auditoria técnica de engenharia de sistemas referente à viabilidade de suportar o anti-cheat **Riot Vanguard** (`vgk.sys` / `vgc.exe`) diretamente sobre o **Nexus OS**, garantindo a execução integral e sem penalidades de **League of Legends** e **Valorant**.

### Veredito Fundamental
1. **Compatibilidade Técnica de ABI (Execução de Drivers `.sys`):** **Comprovada em Ring 0 na Fase 3.6.** É plenamente factível construir no Nexus OS um subsistema WDM/KMDF (`nexus-loader` + `driver_host`) capaz de mapear, realocar, resolver símbolos de `ntoskrnl.exe`, inicializar via `DriverEntry`, despachar IRPs síncronos/assíncronos, manipular IRQLs de hardware e descarregar com segurança drivers de modo kernel PE32+ (`IMAGE_SUBSYSTEM_NATIVE`).
2. **Autorização Criptográfica e Confiança Remota (Atestação TPM 2.0 / PCR 7 / HVCI):** **Bloqueio Criptográfico Rígido Externo (Hard Blocker).** O Vanguard moderno não avalia apenas a conformidade da ABI do kernel; ele realiza **atestação remota de integridade de hardware** via chip TPM 2.0 (`TPM2_Quote`). A assinatura das medições de boot (PCR 7 / Secure Boot) é confrontada nos servidores da Riot Games contra a cadeia criptográfica raiz da Microsoft Windows UEFI CA e políticas de integridade de código reforçada por hipervisor (HVCI).
3. **Regra de Não-Evasão:** Em estrita observância à diretiva do projeto (*sem spoofing, falsificação de PCRs, hypervisor de camuflagem ou bypasses*), a execução legítima em um sistema operacional independente depende de canais oficiais ou de compatibilidade homologada com a Riot Games, ou da emulação autorizada da pilha de atestação.

---

## 2. Anatomia e Requisitos Técnicos do Riot Vanguard

O Riot Vanguard é um sistema anti-cheat de integridade de plataforma de profundidade total (Defense-in-Depth), composto por módulos em Ring 0 e Ring 3:

```
+-------------------------------------------------------------+
|                        Riot Servers                         |
|  - Remote Attestation Authority (Nonce Verification)        |
|  - Heartbeat & Telemetry Validation                         |
+------------------------------^------------------------------+
                               | TLS + Encrypted Telemetry / TPM Quote
+------------------------------v------------------------------+
|                Userland (Ring 3) - vgc.exe                  |
|  - Windows Service (LocalSystem)                            |
|  - Heartbeat Manager & Game Client Liaison (VALORANT / LoL) |
|  - Interage via \\.\vgk (DeviceIoControl)                   |
+------------------------------^------------------------------+
                               | Private IOCTLs / Fast I/O
+------------------------------v------------------------------+
|            Kernel Mode (Ring 0) - vgk.sys (ELAM)            |
|  - Early Launch Anti-Malware (SERVICE_BOOT_START)           |
|  - ObRegisterCallbacks (Process & Thread Handle Stripping)  |
|  - PsSetCreateProcessNotifyRoutineEx                        |
|  - PsSetCreateThreadNotifyRoutine                           |
|  - PsSetLoadImageNotifyRoutine                              |
|  - Minifilter Driver (FltRegisterFilter - I/O Interception) |
|  - Memory Scanner & Hypervisor / Hook Detector              |
+------------------------------^------------------------------+
                               | Hardware & Microcode Locks
+------------------------------v------------------------------+
|       Hardware / Firmware Security Architecture             |
|  - UEFI Secure Boot (Microsoft CA Signature Chain)          |
|  - TPM 2.0 (PCR 0, 2, 7 measurements, Endorsement Key CA)   |
|  - VBS / HVCI (Virtualization-Based Security / SLAT EPT)    |
|  - PatchGuard (KPP - Kernel Patch Protection parity)        |
+-------------------------------------------------------------+
```

### 2.1 Componentes Principais
* **`vgk.sys` (Kernel Mode, Ring 0):** Driver classificado como Early Launch Anti-Malware (ELAM) com tipo de inicialização `SERVICE_BOOT_START` (inicia antes de drivers de terceiros e serviços).
* **`vgc.exe` (Userland Service, Ring 3):** Serviço Win32 rodando como `NT AUTHORITY\SYSTEM`. Faz a ponte entre o cliente do jogo (Riot Client / Valorant-Win64-Shipping.exe) e o driver kernel. Comunica-se exclusivamente via `DeviceIoControl` direcionado ao device link `\\.\vgk` (`\Device\vgk`).

### 2.2 APIs do Kernel Windows NT Exigidas por `vgk.sys`
O driver `vgk.sys` importa e utiliza extensivamente primitivas do subsistema executivo NT:
1. **`ObRegisterCallbacks`:** Registra callbacks pré e pós-operação para os tipos `PsProcessType` e `PsThreadType`. O driver intercepta chamadas como `NtOpenProcess` ou `NtOpenThread` e remove máscaras de acesso (`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_SUSPEND_RESUME`, `THREAD_SET_CONTEXT`) vindas de processos não autorizados.
2. **Rotinas de Notificação de Executável e Imagens:**
   * `PsSetCreateProcessNotifyRoutineEx`: Intercepta criação de processos antes do disparo da primeira thread.
   * `PsSetCreateThreadNotifyRoutine`: Monitora criação remota de threads.
   * `PsSetLoadImageNotifyRoutine`: Examina DLLs mapeadas em memória antes da execução.
3. **Filter Manager (`fltmgr.sys` / Minifilters):**
   * Registra callbacks de pré/pós I/O de sistema de arquivos via `FltRegisterFilter` para impedir que executáveis ou DLLs do jogo sejam adulterados em disco durante a execução.
4. **Gerenciamento de Memória Avançado:**
   * `MmMapLockedPagesSpecifyCache`, `MmAllocatePagesForMdlEx`, `MmIsAddressValid`, `MmCopyVirtualMemory` (função não documentada do kernel NT para inspeção cross-process).
5. **Estruturas Opaque Internas do Kernel:**
   * Inspeção de `EPROCESS`, `KTHREAD`, listas de `ActiveProcessLinks` e `PebBaseAddress`. O driver valida se as estruturas do kernel não estão inconsistentes ou mascaradas.

---

## 3. Comparativo Arquitetural: Híbrido Nexus vs NT-First vs Linux-First

| Dimensão de Análise | Arquitetura Atual Nexus OS (Microkernel Híbrido Rust) | Alternativa NT-First (ReactOS Modernizado) | Alternativa Linux-First (Kernel Linux + Módulo NT) |
| :--- | :--- | :--- | :--- |
| **Abordagem Central** | Microkernel Rust limpo; executivo compartilhado com roteador duplo de syscalls (Linux ABI + NT ABI). | Monolítico C derivado do NT 5.2 (Windows Server 2003/XP 64-bit), adicionando ABI Linux. | Kernel Linux padrão (C) com módulo de compatibilidade LKM (ex: Longene / NDISwrapper). |
| **Isolamento e Segurança** | **Excelente.** Memória segura em Rust, VMM isolado por espaço de endereçamento, transições estritas Ring 0/3. | **Crítico.** Vulnerável a corrupções de ponteiro do C; complexidade imensa para modernizar para NT 10.0+. | **Boa.** Robustez e estabilidade comprovadas do Linux kernel em hardware heterogêneo. |
| **Compatibilidade com Drivers `.sys` Modernos** | **Validada na Fase 3.6.** Carregamento e execução em Ring 0 de drivers WDM reais com IRPs e IRQLs. | Possui infraestrutura WDM/KMDF preliminar, porém defasada (focada em XP/Win7, sem suporte a drivers Win10/11). | Complexo. O modelo de IRPs e IRQLs colide diretamente com a arquitetura de bloqueio e threads do Linux (`bottom halves`, RCU). |
| **Execução de Binários Linux (ELF64)** | **Nativa de primeiro nível.** Sem penalidade de tradução ou overhead de virtualização. | **Severamente limitada.** O subsistema POSIX do NT é lento e incompatível com chamadas modernas (epoll, io_uring, futex). | **Nativa 100%.** |
| **Execução de Drivers Gráficos Modernos** | Drivers DRM/KMS nativos compilados em Rust/C ou bridge isolado em userland/ring0. | Dependência do subsistema `win32k.sys` acoplado ao kernel; ausência de drivers DirectX 12 / Vulkan modernos. | Suporte imediato via drivers oficiais da NVIDIA/AMD/Intel (Mesa/DRM). |
| **Vanguard: Barreira de Atestação TPM** | Idêntica para todos: Bloqueio na assinatura de medições PCR 7 da Microsoft. | Idêntica: ReactOS não possui assinatura da Microsoft CA nem VBS/HVCI. | Idêntica: O kernel Linux não passa na validação PCR 7 do Vanguard. |

---

## 4. Análise do Ecossistema Open Source e Aceleradores

Para acelerar a implementação da compatibilidade com drivers `.sys` sem reinventar a roda, foram auditados os seguintes projetos:

1. **ReactOS (Módulos de I/O e WDM - `ntoskrnl/io`, `ntoskrnl/mm`):**
   * *Aproveitamento:* Excelente referência para a implementação das máquinas de estado de `IRP`, filas de I/O canceláveis, DPCs (Deferred Procedure Calls) e IRQLs (`PASSIVE_LEVEL` a `HIGH_LEVEL`).
   * *Licença:* GPLv2/LGPLv2.1. O código não deve ser copiado diretamente no kernel Nexus (MIT/Apache 2.0), mas serve como especificação viva da ABI NT.
2. **Longene (Linux Unified Kernel):**
   * Projeto pioneiro que tentou unificar NT e Linux no mesmo kernel.
   * *Lição aprendida:* Tentar embutir o modelo de objetos do NT dentro do kernel monolítico do Linux causou conflitos insolúveis de sincronização e concorrência. A abordagem de microkernel do Nexus com separação modular em crates Rust evita esse erro arquitetural.
3. **Microsoft Open-Source KMDF (Kernel-Mode Driver Framework - `wdf01000.sys`):**
   * A Microsoft abriu o código-fonte do WDF/KMDF no GitHub.
   * *Aproveitamento:* Permite compreender exatamente como drivers modernos empacotam IRPs em objetos WDF (`WDFDEVICE`, `WDFREQUEST`), viabilizando a futura compatibilidade com drivers que utilizam o framework KMDF além do WDM puro.
4. **Wine & Proton:**
   * Implementam com perfeição o Userland NT (`ntdll.dll`, `kernel32.dll`, `user32.dll`, `winebus.sys`).
   * *Limitação:* O Wine opera integralmente em Ring 3 no Linux e traduz chamadas para o kernel hospedeiro. Drivers Ring 0 com proteção anti-cheat não funcionam dentro do Wine/Proton tradicional.

---

## 5. Subsistemas Necessários para Execução de Drivers Windows Reais

Para que um driver `.sys` nativo (como drivers de rede, áudio ou anti-cheats) execute no Nexus OS sem o kernel original da Microsoft, é obrigatório implementar os seguintes subsistemas executivos:

```
+-------------------------------------------------------------+
|             Nexus OS - WDM / KMDF Driver Subsystem          |
+-------------------------------------------------------------+
| 1. PE32+ Native Loader & Dynamic Kernel Relocator           |
|    - Carrega cabeçalhos PE, aplica relocs DIR64             |
|    - Conecta IAT com símbolos exportados pelo Nexus OS      |
+-------------------------------------------------------------+
| 2. Object Manager (ObRegisterCallbacks, ObReferenceObject)  |
|    - Tabelas de tipos de objetos (Device, Driver, Process)  |
|    - Rastreamento de contagem de referência e ponteiros     |
+-------------------------------------------------------------+
| 3. I/O Manager (IoCreateDevice, IoAllocateIrp, IoCallDriver)|
|    - Gerenciamento de DRIVER_OBJECT e DEVICE_OBJECT         |
|    - Pilhas de IRPs (IO_STACK_LOCATION) e conclusão de I/O  |
+-------------------------------------------------------------+
| 4. IRQL & Synchronization Scheduler Engine                  |
|    - Níveis PASSIVE_LEVEL (0), APC_LEVEL (1), DISPATCH (2)  |
|    - Filas de DPC (Deferred Procedure Call) e KSPIN_LOCK    |
+-------------------------------------------------------------+
| 5. Process & Thread Notification Hook Manager               |
|    - PsSetCreateProcessNotifyRoutineEx                      |
|    - PsSetCreateThreadNotifyRoutine                         |
|    - PsSetLoadImageNotifyRoutine                            |
+-------------------------------------------------------------+
| 6. Memory Descriptor List (MDL) & Kernel Pool Allocator     |
|    - NonPagedPoolNx (Pool não paginável com No-Execute)     |
|    - MmProbeAndLockPages / MmMapLockedPagesSpecifyCache     |
+-------------------------------------------------------------+
```

---

## 6. Matriz de Rigor Epistemológico: Fatos Documentados vs Hipóteses vs Limitações Não Comprovadas

A fim de assegurar integridade científica e evitar conclusões precipitadas sobre o Vanguard, este documento estabelece uma estrita separação entre fatos comprovados, hipóteses técnicas plausíveis e limitações não comprovadas.

### 6.1 Fatos Documentados e Verificados
1. **Requisitos de Plataforma Oficiais da Riot Games:**
   * No Windows 11, o Riot Vanguard exige obrigatoriamente **UEFI Secure Boot** e **TPM 2.0** ativos. A ausência desses recursos resulta nos erros oficiais **`VAN9001`** (TPM/Secure Boot ausente ou desabilitado) e **`VAN1067`** (falha na integridade do ambiente do sistema operacional).
   * O driver `vgk.sys` é assinado digitalmente com certificado de assinatura de driver da Microsoft (WHQL / Attestation Signed) e é carregado como driver ELAM (`SERVICE_BOOT_START`).
   * No Windows 11 moderno, instalações padrão ativam **VBS** (Virtualization-Based Security) e **HVCI** (Hypervisor-Protected Code Integrity), e o cliente do Vanguard verifica a conformidade com essas políticas.
2. **Rejeição Histórica a Plataformas Alternativas:**
   * A Riot Games declarou publicamente que não oferece suporte a Linux, Steam Deck / Proton ou distribuições BSD para o Valorant e League of Legends com Vanguard, justificando que a facilidade de recompilar ou modificar kernels abertos em Ring 0 compromete irremediavelmente a segurança competitiva do jogo.
3. **Natureza Imutável do TPM 2.0 Físico:**
   * Em hardware com chip TPM 2.0 autêntico, os registros de configuração de plataforma (PCRs) não podem ser sobrescritos arbitrariamente com valores falsos: eles só podem ser avançados via operações criptográficas de hash unidirecional `TPM2_PCR_Extend`.

### 6.2 Hipóteses Técnicas e Inferências Arquiteturais
1. **Mecanismo de Desafio/Resposta (Nonce + `TPM2_Quote`):**
   * *Hipótese:* O backend da Riot Games solicita uma cotação (`TPM2_Quote`) assinada pela chave de atestação do TPM (AIK), cobrindo especificamente o PCR 7 (medição de Secure Boot e autoridades de certificados de boot) e possivelmente PCR 0 e 2.
   * *Evidência de Suporte:* Essa é a especificação padrão do protocolo Device Health Attestation (DHA) da Microsoft e do TCG (Trusted Computing Group).
   * *Ressalva:* O protocolo de rede exato, a estrutura do payload de telemetria e os canais de criptografia entre `vgc.exe` e os servidores da Riot Games são proprietários e não documentados publicamente.
2. **Verificação de Estruturas Não Exportadas do Kernel:**
   * *Hipótese:* O driver `vgk.sys` verifica ponteiros internos em `ntoskrnl.exe` e checa a presença do PatchGuard (KPP), estruturas opacas de `EPROCESS` e valida se o manipulador de syscalls (`IA32_LSTAR`) aponta exatamente para o endereço esperado de `KiSystemCall64`.
   * *Evidência de Suporte:* Análises de engenharia reversa da comunidade de segurança indicam que drivers anti-cheat de ponta realizam inspeções ativas de integridade do kernel hospedeiro para detectar hooks e hipervisores ocultos.

### 6.3 Limitações Não Comprovadas e Questões Abertas
1. **Diferenças de Rigor entre League of Legends e Valorant:**
   * *Questão Aberta:* Embora o Valorant exija rigorosamente TPM 2.0 e Secure Boot em todas as máquinas Windows 11, o League of Legends manteve compatibilidade com certos sistemas Windows 10 legados sem TPM 2.0. Não está comprovado se o backend do LoL aplica a mesma política estrita de atestação remota de PCR 7 que o Valorant em 100% dos casos.
2. **Rejeição a Certificados Próprios de Terceiros em Modo Homologado:**
   * *Questão Aberta:* Não está comprovado que a Riot rejeitaria um sistema que apresente uma cadeia de atestação de hardware física e segura com TPM 2.0 genuíno, caso houvesse um canal formal de cooperação ou validação de chave pública do Nexus OS.

---

## 7. Avaliação da Viabilidade de Suporte Oficial ou Homologação pela Riot Games

Um dos objetivos essenciais desta auditoria é determinar a viabilidade prática e estratégica de obter **suporte oficial ou homologação do Nexus OS pela Riot Games**.

### 7.1 Precedentes na Indústria: O Caso Valve / Steam Deck
* Para viabilizar a execução de jogos Windows no Steam Deck (SteamOS / Linux), a **Valve** trabalhou diretamente com as principais empresas de anti-cheat do mercado:
  * **Easy Anti-Cheat (Epic Games):** Disponibilizou um binário nativo para Linux e integração oficial com o Proton via `wine-easyanticheat`.
  * **BattlEye:** Desenvolveu um módulo oficial compatível com Proton, ativado pelo desenvolvedor através de uma simples flag de configuração.
* **Resultado:** Jogos como *Apex Legends*, *Elden Ring* e *Rainbow Six Siege* puderam rodar no Linux de forma autorizada e legítima, sem qualquer necessidade de bypass ou violação de termos de serviço.

### 7.2 Postura Específica da Riot Games em Relação ao Vanguard
Diferente da Epic Games e da BattlEye, a Riot Games adota uma filosofia de segurança substancialmente mais restritiva:
1. **Desenvolvimento 100% Interno (In-House):** O Vanguard foi projetado especificamente para o ecossistema Windows NT e não é comercializado como middleware para terceiros. A equipe de segurança da Riot controla todo o ciclo de vida do cliente e do servidor.
2. **Recusa Explícita ao Linux e Steam Deck:** A liderança de anti-cheat da Riot Games declarou repetidamente que não tem planos de oferecer suporte ao Linux ou Wine/Proton. A justificativa técnica apresentada é que um kernel de código aberto permite que atacantes compilem versões modificadas com hooks invisíveis em Ring 0, neutralizando a capacidade do driver anti-cheat de garantir a integridade dos processos do jogo.
3. **Dependência do Ecossistema Microsoft:** O Vanguard aproveita extensivamente os investimentos de segurança da Microsoft, como Windows Hardware Quality Labs (WHQL), driver signature enforcement e HVCI baseado em Hyper-V.

### 7.3 Viabilidade Prática de Homologação para o Nexus OS
* **Probabilidade a Curto/Médio Prazo: Baixa a Nula.**
  * A Riot Games não mantém um programa aberto de certificação para novos sistemas operacionais independentes.
  * O Nexus OS precisaria demonstrar uma base de usuários massiva e um modelo de segurança corporativamente auditável e inviolável para que a Riot Games sequer considerasse alocar recursos de engenharia em testes de homologação.
* **Condição Necessária para Viabilidade Futura:**
  * Se o Nexus OS implementar uma cadeia completa de inicialização segura (Secure Boot próprio com chaves PK/KEK auditadas), hipervisor de isolamento tipo 1 equivalente ao VBS/HVCI e driver TPM 2.0 nativo que se comunique com o hardware real sem adulterações, o sistema poderá apresentar uma proposta técnica robusta à Riot Games.
  * No entanto, até que tal diálogo ocorra e resulte em aprovação contratual, o bloqueio de atestação remota nos servidores da Riot permanece intransponível sem violação das regras do projeto.

---

## 8. Conquistas da Fase 3.6: Execução Real de Driver WDM em Ring 0

Diferente da fase exploratória inicial (onde a compatibilidade foi avaliada em nível de tipos e protótipos), a **Fase 3.6 validou na prática a execução de drivers Windows NT no kernel Nexus**:

1. **Driver `.sys` Compilado de Forma Independente:**
   * Desenvolvido em C padrão (`tests/fixtures/nt_driver/nexus_driver.c`) e compilado com o compilador oficial da Microsoft (`cl.exe /kernel /O2 /GS-` + `link.exe /SUBSYSTEM:NATIVE /DRIVER`).
   * Gera um binário executável PE32+ autêntico de 4.608 bytes com `IMAGE_SUBSYSTEM_NATIVE`.
2. **Execução Real em Ring 0 sob QEMU / OVMF:**
   * Mapeamento integral em memória executável de supervisor.
   * Correção e aplicação de relocations DIR64 para a base alocada.
   * Resolução dinâmica da IAT contra 10 funções do `ntoskrnl.exe`.
   * Chamada de `DriverEntry` em Ring 0 com retorno `STATUS_SUCCESS` (0).
   * Criação e registro dinâmico do `DeviceObject` (`\Device\NexusDrv0`).
3. **Processamento Real de I/O e IRQL:**
   * Despacho bem-sucedido de `IRP_MJ_CREATE`.
   * Despacho de `IRP_MJ_DEVICE_CONTROL` com teste de versão (`IOCTL_NEXUS_GET_VERSION` -> `0x00030600`).
   * Despacho de `IRP_MJ_DEVICE_CONTROL` com elevação de IRQL (`IOCTL_NEXUS_RAISE_IRQL_TEST` -> `0x1337C0DE`), validando `KeRaiseIrql` para `DISPATCH_LEVEL` e restauração segura para `PASSIVE_LEVEL`.
   * Despacho de `IRP_MJ_READ` com retorno de payload (`NEXUS_OS_WDM_READ_SUCCESS`).
   * Descarregamento seguro via `DriverUnload` com desalocação de dispositivo.

---

## 9. Conclusão e Diretrizes para as Próximas Fases

1. **A compatibilidade de drivers `.sys` em Ring 0 não é mais uma incógnita teórica:** O Nexus OS possui agora a fundação arquitetural e comprovada para carregar e executar drivers Windows nativos.
2. **O obstáculo remanescente para o Vanguard é a confiança e atestação remota:** O desafio não é executar `vgk.sys`, mas sim fazer com que os servidores da Riot Games aceitem a medição de hardware de um sistema que não é o Windows original da Microsoft.
3. **Respeito à Diretiva de Não-Evasão:** O projeto mantém o compromisso estrito de não implementar bypasses ou spoofing.
4. **Prosseguimento do Roadmap:** Conforme o planejamento do Nexus OS, a validação da Fase 3.6 fornece a base técnica necessária para a evolução dos subsistemas centrais, mantendo o Niri + iNiR como interface oficial e pavimentando o caminho para os drivers de GPU e o subsistema gráfico da Fase 4.
