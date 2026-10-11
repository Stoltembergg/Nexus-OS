/*
 * Nexus OS — fixture de relocações (PR-2).
 *
 * Driver NT mínimo cujo único propósito é ter uma tabela de ponteiros
 * ABSOLUTOS em .data, o que obriga o linker a emitir entradas
 * IMAGE_REL_BASED_DIR64 em .reloc. O loader do Nexus carrega a imagem
 * fora da ImageBase preferida (0x140000000), então o DriverEntry só
 * retorna STATUS_SUCCESS se cada ponteiro absoluto tiver sido corrigido
 * pelo delta e coincidir com o endereço calculado de forma relativa ao RIP.
 *
 * Não usa cabeçalhos WDM nem structs NT: só valida relocação e import.
 * Compilado por scripts/build-reloc-driver.py (clang + lld-link).
 */
typedef long NTSTATUS;
typedef unsigned char KIRQL;

__declspec(dllimport) KIRQL KeGetCurrentIrql(void);

#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#define STATUS_RELOC_DATA_PTR     ((NTSTATUS)0xC0DE0001L)
#define STATUS_RELOC_DATA_VALUE   ((NTSTATUS)0xC0DE0002L)
#define STATUS_RELOC_FUNC_PTR     ((NTSTATUS)0xC0DE0003L)
#define STATUS_RELOC_FUNC_CALL    ((NTSTATUS)0xC0DE0004L)
#define STATUS_RELOC_SELF_PTR     ((NTSTATUS)0xC0DE0005L)
#define STATUS_IMPORT_IRQL        ((NTSTATUS)0xC0DE0006L)

static volatile int g_marker = 0x4E455855; /* "NEXU" */

static __declspec(noinline) int reloc_probe(int x) { return x ^ 0x5A5A; }

typedef int (*probe_fn)(int);

/* Tabela de ponteiros absolutos: cada inicializador gera um DIR64. */
static void *volatile g_abs_table[3] = {
    (void *)&g_marker,
    (void *)&reloc_probe,
    (void *)&g_abs_table,
};

NTSTATUS DriverEntry(void *driver_object, void *registry_path)
{
    (void)driver_object;
    (void)registry_path;

    if (g_abs_table[0] != (void *)&g_marker)
        return STATUS_RELOC_DATA_PTR;
    if (*(volatile int *)g_abs_table[0] != 0x4E455855)
        return STATUS_RELOC_DATA_VALUE;
    if (g_abs_table[1] != (void *)&reloc_probe)
        return STATUS_RELOC_FUNC_PTR;
    if (((probe_fn)g_abs_table[1])(0x1234) != (0x1234 ^ 0x5A5A))
        return STATUS_RELOC_FUNC_CALL;
    if (g_abs_table[2] != (void *)&g_abs_table)
        return STATUS_RELOC_SELF_PTR;
    if (KeGetCurrentIrql() != 0)
        return STATUS_IMPORT_IRQL;
    return STATUS_SUCCESS;
}
