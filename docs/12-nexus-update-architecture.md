# Nexus OS — Nexus Update: Arquitetura Técnica de Atualizações OTA

**Estado:** proposta de arquitetura (não implementada)  
**Alvo:** Nexus OS x86_64, firmware UEFI, kernel híbrido próprio em Rust/C  
**Data:** 11 de outubro de 2026  
**Local sugerido no repositório:** `docs/12-nexus-update-architecture.md`

## 1. Decisão e objetivo

**Decisão proposta:** adotar atualizações do sistema por *slots A/B* com imagens de sistema versionadas, verificadas criptograficamente, e um mecanismo de boot independente que somente confirma a versão nova depois de verificações de saúde. Usar **GitHub Releases como distribuição inicial**, não como raiz de confiança. O atualizador será um serviço em modo usuário escrito em Rust, com APIs de escrita em bloco, armazenamento persistente e boot control fornecidas pelo Nexus. O sistema deve oferecer instalação offline por USB antes da primeira instalação permanente em hardware físico.

**Meta do usuário:** instalar o Nexus uma vez e aplicar atualizações sem reinstalação, inclusive atualizações de kernel, drivers e, futuramente, Nexus Shell (Niri + iNiR). A primeira implementação deverá funcionar em uma máquina de testes dedicada antes de ser considerada segura para dados importantes.

**Fora do escopo inicial:** atualizações de firmware da placa-mãe, BIOS/UEFI, firmware interno de SSD/GPU, gerenciamento de pacotes de terceiros, alterações irreversíveis de particionamento por OTA, troca do sistema de arquivos raiz em produção e atualizações diferenciais. O atualizador não torna o Nexus compatível com Vanguard e não representa uma certificação da Riot.

### Invariantes obrigatórias

1. Nunca gravar o slot ativo durante uma atualização de sistema.
2. Nunca confiar em arquivo, versão, URL ou checksum apenas porque veio do GitHub ou do TLS.
3. Sempre manter um sistema anteriormente confirmado e uma via de recuperação independente.
4. Nunca marcar uma nova versão como funcional apenas porque o kernel imprimiu `BOOT_SUCCESS`.
5. Nunca apagar dados do usuário durante atualização/rollback; migrações de dados são tratadas separadamente.
6. Não instalar kernel/driver/pacote cuja assinatura, arquitetura, compatibilidade ou integridade não tenham sido verificadas.
7. Um desligamento durante download ou escrita não pode danificar o slot confirmado; a ativação deve ter um único ponto de confirmação persistente.

## 2. Arquitetura

```text
GitHub Actions (build, testes, evidências)
        |
Signatário independente (chaves offline / aprovação)
        |
GitHub Releases (Nightly / Beta / Stable)
        |  artefatos .nxu + metadados assinados
        v
Nexus Update Agent (Ring 3)
  descoberta -> download -> verificação -> staging -> escrita no slot inativo
        |                               |
        |                         Nexus Block/VFS APIs
        v                               v
Nexus Boot Control <------------ Partições Nexus A/B
        |
UEFI Nexus Boot Manager (imagens verificadas, tentativas, rollback)
        |
Nexus Kernel + drivers + serviços + Nexus Shell
        |
Nexus Boot Health: valida -> marca slot como GOOD; falha -> retorno ao GOOD anterior
```

**Fronteira de privilégios:** rede/TLS e parsers de manifestos no serviço Ring 3; apenas operações de escrita autorizadas pela API privilegiada; boot control e validação de imagens no ambiente de boot. Não construir o downloader dentro do kernel.

## 3. Layout proposto de disco (GPT)

| Partição | Nome / destino lógico | Função | Política |
|---|---|---|---|
| 1 | `NEXUS_ESP` (FAT32) | Boot manager EFI estável, arquivos versionados de boot, recuperação mínima | Gravada raramente; alterações do boot manager exigem procedimento separado |
| 2 | `NEXUS_SYSTEM_A` | Imagem do sistema A | Somente leitura quando ativa |
| 3 | `NEXUS_SYSTEM_B` | Imagem do sistema B | Somente leitura quando ativa |
| 4 | `NEXUS_DATA` | Usuários, configuração, aplicativos persistentes, registros de atualização | Persistente entre atualizações |
| 5 | `NEXUS_RECOVERY` | Ambiente mínimo de recuperação independente dos slots | Imutável/assinada, atualizada apenas por procedimento seguro |

**Observações:** as partições são um *projeto*, não recursos presentes no kernel atual. O sistema de arquivos concreto dos slots depende da futura VFS e dos drivers de armazenamento. Na primeira PoC pode-se usar imagens simples, imutáveis e verificáveis em bloco. Não assumir que o Nexus já tenha ext4, Btrfs, dm-verity, HTTPS ou suporte completo a NVMe. O modo de instalação inicial deve exigir backup e disco de testes dedicado.

**Dimensionamento:** dimensionar cada slot para a imagem completa + crescimento previsto; reservar área suficiente para downloads temporários, logs e arquivos pessoais. Tamanhos fixos em GiB são decisão posterior, fundamentada em imagens reais.

### Atualizações do boot manager

O boot manager deve ser um componente mínimo e estável, atualizado separadamente, com binário anterior preservado e entrada de recuperação. Evitar substituir o único `.efi` funcional. Usar arquivos EFI versionados e uma estratégia de seleção que sobreviva a desligamentos, com assinatura compatível com a política UEFI Secure Boot adotada pelo Nexus. **Assinatura de pacote OTA e assinatura UEFI Secure Boot são mecanismos distintos**. O uso da variável UEFI `BootNext` sozinho não fornece contador persistente de tentativas nem rollback automático.

## 4. Máquina de estados transacional

| Estado | Evento / ação | Estado seguinte |
|---|---|---|
| `IDLE` | Nova versão permitida pelo canal | `AVAILABLE` |
| `AVAILABLE` | Aprovação/política de atualização | `DOWNLOADING` |
| `DOWNLOADING` | Download completo com limites, retomada e hash | `VERIFYING` |
| `VERIFYING` | Metadados e payload válidos; compatibilidade confirmada | `STAGING` |
| `STAGING` | Escrever e reler slot inativo; validar imagem instalada | `READY_TO_BOOT` |
| `READY_TO_BOOT` | Registrar slot candidato + versão anterior confirmada; reiniciar | `BOOT_TRIAL` |
| `BOOT_TRIAL` | Autotestes do sistema + confirmação persistida | `COMMITTED` |
| `BOOT_TRIAL` | Limite de tentativas, falha crítica ou watchdog | `ROLLBACK` |
| `ROLLBACK` | Reiniciar slot anterior confirmado; registrar falha | `RECOVERED` |
| Qualquer fase anterior ao boot | Erro / queda de energia | Slot GOOD continua bootável; retoma ou limpa staging |

**Boot metadata mínima:** `active_slot`, `last_good_slot`, `pending_slot`, `generation`, `attempts_left`, `state`, `image_digest` por slot, `min_allowed_version`/política, integridade da estrutura (checksum para corrupção acidental + autenticação quando aplicável). Manter duas cópias ou journal com números de geração, gravação consistente e flush. O boot manager deve validar a integridade e a autenticidade das imagens, independentemente do agente Ring 3.

**Tentativas:** valor inicial de **3 tentativas** como política configurável, não garantia universal. O contador precisa ser reduzido **antes** da entrega ao kernel, armazenado de forma durável e recuperável após queda de energia. Na expiração, selecionar o último slot GOOD. Watchdog físico ajuda em travamentos permanentes quando o hardware permitir; sem watchdog, pode ser necessário reinicializar manualmente.

**Confirmação de saúde:** versão assinalada e verificada, serviços essenciais iniciados, VFS/data montados corretamente, ausência de pânico, teste de I/O persistente e capacidade de ativar o supervisor de processos. Quando o Nexus Shell existir, é possível acrescentar teste de sessão gráfica, mas não bloquear a recuperação do sistema por um bug visual não crítico sem política explícita. Prazo e critérios devem ser configuráveis por perfil de hardware.

**Limites do rollback:** um A/B não restaura automaticamente dados alterados por migrações. Persistir snapshots/backup de configurações antes de uma migração, usar migrações reversíveis ou compatíveis com ambas as versões, e bloquear mudanças destrutivas sem plano de recuperação. Rollback pode falhar se firmware, ESP, SSD ou ambos os slots estiverem danificados; manter imagem USB de recuperação.

## 5. Segurança da cadeia de atualização

**Padrão-alvo:** TUF (*The Update Framework*), usando uma implementação/biblioteca auditada quando compatível com o Nexus. Evitar inventar protocolo criptográfico próprio. TUF define papéis `root`, `targets`, `snapshot` e `timestamp`, verificações de assinatura, versões monotônicas e validade temporal.

- **Root of trust:** chaves públicas confiáveis incorporadas ao instalador e ao Nexus Update; root privada mantida offline. Para distribuição pública, avaliar limiar 2-de-3 para rotação de raízes, sem fazer o CI controlar todas as chaves.
- **Targets:** SHA-256, tamanho exato, canal, modelo/arquitetura, versão do Nexus, compatibilidade de ABI/boot manager e identificação da imagem; conferir o payload baixado e a imagem gravada.
- **Snapshot / Timestamp:** amarrar versões de metadados e evitar ataques de replay/congelamento; sincronização temporal confiável e política explícita para máquinas sem relógio válido.
- **Assinatura de artefatos:** Ed25519 é uma opção possível se adotada pela implementação TUF selecionada; não assinar JSON bruto de forma ambígua. Usar serialização e validação previstas na biblioteca.
- **Comprometimento:** exigir revogação/rotação de chaves e procedimento de publicação emergencial; chaves privadas jamais embutidas no repositório ou imagem do OS.
- **Downgrade:** impedir *downgrades* arbitrários acionados por um atacante, mas permitir rollback A/B **estritamente para a última imagem GOOD previamente verificada**. A política anti-rollback deve distinguir recuperação de atualização ofertada pela rede. Se houver requisito de versão mínima de segurança, a liberação de exceção precisa ser explícita e assinada.
- **Boot trust:** verificar imagem carregada na pré-inicialização e planejar Secure Boot/medição TPM futuros. O hash de download não protege um sistema cujo bootloader aceite código adulterado.
- **Supply chain:** GitHub Actions pode gerar atestados de proveniência (Sigstore) e SBOM; são complementares, não substituem a assinatura de atualização verificada de modo independente do GitHub.

**MVP de laboratório:** para começar, é aceitável uma única chave offline Ed25519 e um manifesto de versão assinada, desde que a implementação seja isolada atrás de uma interface para migração a TUF completo **antes da distribuição pública**. Não confundir isso com segurança TUF integral.

## 6. Contrato de release e compatibilidade

Cada release deve ter um pacote A/B completo e metadados. Convenção sugerida:

```text
release tag: nexus-v0.4.0-beta.1  (ilustrativo)
assets:
  nexusos-x86_64-uefi-v0.4.0-beta.1.nxu
  nexusos-x86_64-uefi-v0.4.0-beta.1.nxu.sha256   # informativo; TUF é autoridade
  nexus-update-metadata.tar                      # root/targets/snapshot/timestamp pertinentes
  nexus-release-notes.md
  nexus-sbom.spdx.json
  nexus-build-attestation.json
```

**Estrutura lógica de `.nxu`:** pacote com cabeçalho formatado e versionado, índice de arquivos com limites, imagem integral do sistema (kernel, serviços, drivers, componentes gráficos quando disponíveis) e metadados de compatibilidade. Seu hash/tamanho deve ser assinado via targets TUF. Empacotamento precisa admitir streaming e rejeitar caminhos relativos maliciosos, links e entradas excessivamente grandes.

**Exemplo ilustrativo de campos do manifesto de *aplicação* (não substitui a especificação TUF):**

```json
{
  "schema": 1,
  "product": "nexus-os",
  "version": "0.4.0-beta.1",
  "channel": "beta",
  "architecture": "x86_64",
  "platform": "uefi",
  "minimum_updater": "0.2.0",
  "minimum_boot_manager": "0.2.0",
  "kernel_abi": 4,
  "system_format": 1,
  "image": {
    "name": "system.img",
    "size_bytes": 123456789,
    "sha256": "<sha256-hex-da-imagem-real>"
  },
  "requires_reboot": true
}
```

Nunca usar valores demonstrativos para assinar uma release real. Definir regras de compatibilidade anteriores ao uso do manifesto, validação de tamanho máximo, monotonicidade de versões e esquemas rejeitados por padrão.

### Política de canais

| Canal | Frequência | Quem recebe | Política |
|---|---|---|---|
| `nightly` | A cada build aprovado definido pelo CI | Laboratório e desenvolvedores | Falhas esperadas; recovery obrigatório |
| `beta` | Releases candidatas | Testadores com hardware suportado | Aprovação de testes e assinaturas |
| `stable` | Após qualificação | Usuários finais futuros | Rollout gradual; regressão zero em critérios críticos |

As releases precisam de tags imutáveis por convenção operacional; **o cliente não pode presumir que tags ou assets são imutáveis**. O canal é uma decisão assinada nos metadados. Não permitir que Nightly seja instalada automaticamente em Stable sem troca explícita de canal/autorização.

## 7. Integração com GitHub Releases

GitHub Releases atua como CDN de arquivos e ponto inicial de descoberta. O agente pode consultar a **API REST de releases públicas**, localizar a release do canal desejado e baixar metadados e artefatos por HTTPS, usando `ETag`/requisições condicionais e backoff. Não depender exclusivamente do endpoint `latest`, que não é seletor universal para Nightly/Beta. Os detalhes de seleção devem ser baseados em tags, pre-release e metadados assinados do canal.

**Limitação operacional:** a API pública sem autenticação possui limites de taxa; adicionar cache local, espaçamento das verificações e jitter. Não exigir token pessoal de GitHub no Nexus, nem colocá-lo na imagem pública. Se necessário, migrar a descoberta de canais para metadados estáticos assinados em GitHub Pages ou infraestrutura própria, mantendo Releases para os payloads.

**Fluxo de publicação:** PR -> testes unitários/integração QEMU -> build reproduzível quando possível -> validação de imagem/compatibilidade -> geração de SBOM e proveniência -> aprovação de release -> assinatura com chaves separadas do CI -> publicação -> verificação de download independente -> liberação do canal. `nightly` pode ter aprovação menos rígida, mas nunca dispensar integridade/assinatura em máquinas de teste.

**TLS e confiança:** planejar validação de certificados, limites de redirecionamento, tamanho e tempo, DNS seguro dentro das capacidades disponíveis e tolerância a rede intermitente. TLS é importante para transporte, mas **assinatura autenticada é a fonte de confiança final**.

## 8. Componentes de software

```text
crates/
  nexus-update-core/        # Versionamento, políticas, estados, erros
  nexus-update-metadata/    # Validação TUF / assinaturas, digests
  nexus-update-agent/       # Serviço Ring 3: download, staging, UI API
  nexus-update-storage/     # Escrita segura de imagens, flush, leitura de volta
  nexus-boot-control/       # Contrato boot manager <-> kernel, slots, tentativas
  nexus-health/             # Confirmação de boot e diagnóstico
  nexus-recovery/           # Recuperação local/offline

tools/
  nexus-release/            # Build, pacote .nxu, SBOM e publicação

docs/
  12-nexus-update-architecture.md
  13-nexus-update-threat-model.md
  14-nexus-update-test-matrix.md
```

Separar APIs/traits puras e verificáveis das implementações dependentes de rede/VFS/UEFI. Toda interação com partições deve ocorrer por interface de bloco com identidade de dispositivo e partição, validação dos limites de gravação, `flush` e readback. Manter uma API de atualização de boot metadata com geração e recuperação após interrupção.

**API futura entre UI/CLI e serviço:** `check(channel)`, `download(release)`, `verify()`, `stage(slot)`, `reboot_into_candidate()`, `status()`, `cancel()` (permitido apenas antes da ativação), `get_history()`, `request_rollback()` (exige autorização). A UI não recebe permissões diretas de escrita em disco.

**CLI inicial sugerida:** `nexus-update status`, `check`, `install /media/usb/release.nxu`, `stage`, `history`, `rollback --to-last-good`. A CLI pode começar por mídia local, antes de existir rede.

## 9. Dependências mínimas do próprio Nexus OS

O kernel hoje apresentado tem boot UEFI e execução experimental de processos, mas **ainda não demonstrou VFS persistente, armazenamento NVMe/AHCI, rede/TLS, serviços duráveis nem integridade de boot**. Portanto não é viável construir OTA completo de imediato.

| Dependência | Necessária para |
|---|---|
| Driver de bloco confiável + descoberta GPT | Persistir imagens A/B |
| Sistema de arquivos mínimo + VFS | Ler pacotes, escrever logs e manter Data |
| Transações/flush e integridade de armazenamento | Recuperar de power loss |
| Boot manager Nexus com seleção persistente | Escolher A/B e fallback independente |
| Loader capaz de validar imagens versionadas | Não inicializar código adulterado |
| Processos/serviços Ring 3 estáveis + IPC | Agente, UI e saúde do boot |
| Pilha de rede + DNS + TLS + relógio verificável | OTA via GitHub |
| Dispositivo de entrada/console para recovery | Recuperação manual |

**Recomendação de sequência:** não adiar o planejamento, mas executar as primeiras implementações **assim que storage + boot control existirem**. A primeira instalação no SSD deve nascer preparada para A/B, mesmo que o único método de atualização ainda seja USB.

## 10. Roadmap de execução

| Etapa | Objetivo | Gate de aceite |
|---|---|---|
| **U0 — Especificação** | ADR, ameaça, esquema de partições, compatibilidade, formatos e interfaces | Revisão técnica documentada sem alterações destrutivas no kernel |
| **U1 — Boot A/B em QEMU** | Seleção/contador persistente, fallback, slots com imagens de demonstração | Três boots com falha levam ao último slot GOOD; power-cut em cada transição |
| **U2 — Storage + instalador experimental** | GPT, slots, Data, Recovery, VFS/bloco/flush | Instalar em disco virtual; reiniciar; preservar dados e layout |
| **U3 — Atualização offline assinada** | CLI + pacote `.nxu` + verificação + escrita/compare | v0.1 -> v0.2 e rollback sem reinstalação, sem rede |
| **U4 — Transporte GitHub** | Rede/TLS, seleção de canais, cache, download resumível | Download íntegro com falhas de rede, autenticação e retomada |
| **U5 — Nexus Shell** | Tela no iNiR para status, notas, progresso, reinício | Atualização pelo desktop sem acesso de escrita à UI |
| **U6 — Hardening público** | TUF completo, chaves offline/rotação, Secure Boot, recovery, rollout | Auditoria independente e matriz adversarial aprovada |
| **U7 — Otimização** | Delta, downloads P2P opcionais, espelhos e updates de componentes | Economia medida sem comprometer integridade/rollback |

**Gates de dependência:** U1 pode começar emulado e como módulos separáveis antes de driver físico. U2/U3 devem existir **antes** de disponibilizar a primeira instalação física de uso contínuo. U4 depende de rede real; U5 depende de compositor/shell. Não tratar essas fases como datas ou durações garantidas.

## 11. Matriz mínima de testes

- **Integridade:** arquivo alterado (um bit), hash inválido, assinatura inválida, chave revogada, metadados expirados, canal inadequado, arquitetura errada, versão proibida.
- **Resiliência:** desligar durante download, metadata, início/meio/fim da escrita, readback, ativação, primeiro boot e confirmação de saúde.
- **Rollback:** kernel que não inicializa, boot loop, driver essencial com falha, health agent ausente, um slot corrompido, ambas as cópias de metadata discordantes.
- **Armazenamento:** disco cheio, bad blocks simulados, escrita parcial, flush falho, ESP inacessível, desligamento abrupto, troca de ordem de discos.
- **Rede:** sem DNS, sem TLS confiável, erro 429, timeout, redirecionamento inválido, payload incompleto, desconexão e retomada por ranges verificados.
- **Compatibilidade:** kernel ABI insuficiente, versão antiga do updater, schema migration, mudança de driver gráfico, mudanças do Nexus Shell e dados de usuário preservados.
- **Matriz QEMU:** RAM pequena/grande, CPU single/multi, diferentes dispositivos virtuais, UEFI variada, Secure Boot quando disponível, snapshots independentes para cada falha.
- **Hardware real:** SSD dedicado, backup externo, recovery USB, várias inicializações, discos com particionamento GPT, falha controlada e logs serial/persistentes.

**Critério mínimo antes de instalar Nexus para testes contínuos:** em um mesmo disco QEMU, instalar v0.1, atualizar para v0.2, verificar hashes, preservar `NEXUS_DATA`, reiniciar em v0.2, provocar falha antes de mark-good e recuperar v0.1 automaticamente; repetir todos os cenários de power loss relevantes; depois reproduzir em SSD de testes dedicado.

## 12. Operação, telemetria e privacidade

Guardar histórico local de versões, slots, tentativas, duração dos passos, erros e hashes, sem coleta remota obrigatória. Se for necessário relatório remoto no futuro, exigir consentimento e anonimização. Separar logs de boot do slot de sistema para sobreviver ao rollback. Adotar limites de consumo de banda, pausa/resume, política de bateria/energia e horários de reinicialização definidos pelo usuário.

## 13. Riscos prioritários e decisões em aberto

1. **Sem VFS/bloco confiável:** começar pelas interfaces e QEMU, não por HTTP.
2. **Boot manager atualizado incorretamente:** manter recuperação e bootloader anterior assinados.
3. **W^X e driver NT Ring 0:** impor integridade de imagens, limitar drivers aceitos e não permitir que download ou UI façam patch arbitrário no kernel.
4. **Perda de chaves:** documentar revogação, rotação, recuperação e resposta a comprometimento.
5. **Dados migrados:** exigir esquemas reversíveis ou snapshots antes de confirmação.
6. **Firmware heterogêneo:** testar o estado persistente A/B sem presumir que `BootNext` implementa fallback.
7. **Assinatura não equivale a homologação Riot:** separação explícita entre confiança do Nexus Update, UEFI Secure Boot e critérios de aceitação do Vanguard.
8. **Portabilidade de RAUC:** usar seus conceitos como referência; RAUC é Linux-centric e não será assumido como aplicativo executável diretamente no Nexus.

## 14. Primeiras tarefas a abrir no backlog

- `UPD-001` ADR de layout GPT, slots, política de boot e recovery.
- `UPD-002` Contrato Rust `BootSlotState` versionado e persistência crash-safe.
- `UPD-003` Testes de boot manager A/B em QEMU e simulações de power cut.
- `UPD-004` Especificação `.nxu`, manifestos, ABI, compatibilidade e limites.
- `UPD-005` Threat model: supply chain, disco, chaves, replay, rollback e recovery.
- `UPD-006` Prova offline de assinatura/verificação sem chaves no CI.
- `UPD-007` CLI experimental com disco virtual, sem acesso ao disco real da máquina hospedeira.
- `UPD-008` Workflow de build e publicação com gates, SBOM e atestados.
- `UPD-009` Contrato IPC Nexus Shell ↔ Update Agent.
- `UPD-010` Plano de validação física e procedimento de recuperação USB.

## 15. Referências oficiais

- GitHub Releases REST API: https://docs.github.com/en/rest/releases/releases
- GitHub API rate limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- GitHub artifact attestations: https://docs.github.com/en/actions/concepts/security/artifact-attestations
- TUF specification: https://theupdateframework.github.io/specification/
- TUF metadata roles: https://theupdateframework.io/docs/metadata/
- RAUC mark good / boot slot state: https://rauc.readthedocs.io/en/latest/using.html
- RAUC EFI/BootNext notes: https://rauc.readthedocs.io/en/latest/reference.html
- UEFI 2.11 Boot Manager / BootNext: https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html

---

**Decisão final sugerida:** planejar agora e implementar primeiro *boot control A/B + recovery + atualização offline assinada*. Adicionar GitHub OTA depois de VFS, armazenamento persistente, rede e TLS; incorporar Nexus Shell como interface, nunca como autoridade de instalação.