# Fase 3.5 — Kernel Hardening & Architecture Validation

Estado: **em andamento; não concluída**. Escopo: Fases 0–3, sem funcionalidades da Fase 4.

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

Resultados finais, classificação de componentes e riscos serão preenchidos após as validações.
