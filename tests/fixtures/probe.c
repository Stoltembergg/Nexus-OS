/* Freestanding C, no Nexus headers/runtime. Linux syscall ABI / fixed NT test SSDT. */
typedef unsigned long long u64;
typedef long long i64;
static volatile unsigned char bss[8192];
static volatile u64 data = 0x123456789abcdef0ULL;
static const unsigned char output[] = {0xff, 0x00, 0x7f};
static volatile unsigned char nx_data[16] = {0xc3};
extern int context_probe(void);
#ifdef NT
extern u64 nt_write(u64, u64, u64, u64, u64 *, const void *, u64, u64, u64);
static u64 iosb[2];
static i64 write_test(u64 fd, const void *p, u64 n) {
    return (i64)nt_write(fd, 0, 0, 0, iosb, p, n, 0, 0);
}
static const u64 initial = 0x1111;
#define FOREIGN 0x100001000ULL
#define BAD_POINTER 0xc0000005LL
#define BAD_FD 0xc0000008LL
#else
static i64 write_test(u64 fd, const void *p, u64 n) {
    u64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(1), "D"(fd), "S"(p), "d"(n) : "rcx", "r11", "memory");
    return (i64)r;
}
static const u64 initial = 0x2222;
#define FOREIGN 0x140001000ULL
#define BAD_POINTER (-14LL)
#define BAD_FD (-9LL)
#endif
#ifndef MODE
#define MODE 0
#endif
int probe(void) {
    if (MODE != 0) {
        const unsigned int mxcsr = 0x2000;
        const unsigned short control = 0x077f;
        __asm__ volatile("ldmxcsr %0; fldcw %1" :: "m"(mxcsr), "m"(control));
    }
    if (MODE == 1) return *(volatile u64 *)FOREIGN;
    if (MODE == 2) { *(volatile u64 *)FOREIGN = 0xdeadbeef; return 99; }
    if (MODE == 3) return *(volatile u64 *)0x100000;
    if (MODE == 4) { *(volatile u64 *)0x100000 = 0; return 99; }
    if (MODE == 5) { ((void (*)(void))nx_data)(); return 99; }
    if (MODE == 6) { *(volatile unsigned char *)(u64)probe = 0xc3; return 99; }
    if (MODE == 7) { __asm__ volatile("ud2"); return 99; }
    if (MODE == 8) { __asm__ volatile("cli"); return 99; }
    if (MODE == 9) { __asm__ volatile("xor %%edx,%%edx; xor %%ecx,%%ecx; mov $1,%%eax; div %%ecx" ::: "rax", "rcx", "rdx"); return 99; }
    if (MODE == 10) return 14;
    if (MODE == 11) return -1;
    if (MODE == 12) return 0x7fff0001;
    if (MODE == 13) { volatile unsigned char code[8] = {0xc3}; ((void (*)(void))code)(); return 99; }
    if (MODE == 14) { __asm__ volatile("out %%eax,%%dx" :: "a"(16), "d"((unsigned short)0xf4)); return 99; }
    if (MODE == 15) { __asm__ volatile("wrmsr" :: "c"(0xc0000101U), "a"(0), "d"(0)); return 99; }
    for (u64 i = 0; i < sizeof bss; ++i) if (bss[i] != 0) return 101;
#ifdef NT
    u64 self, peb;
    __asm__ volatile("movq %%gs:0x30,%0; movq %%gs:0x60,%1" : "=r"(self), "=r"(peb));
    if (!self || *(u64 *)(self+0x30) != self || !peb
        || *(unsigned short *)(*(u64 *)(peb+0x10)) != 0x5a4d) return 113;
#else
    u64 fs_value;
    __asm__ volatile("movq %%fs:0,%0" : "=r"(fs_value));
    if (fs_value != 0x3333) return 113;
#endif
    if (data != 0x123456789abcdef0ULL) return 102;
    if (write_test(1, (void *)0x100000, 8) != BAD_POINTER) return 103;
    if (write_test(1, (void *)FOREIGN, 8) != BAD_POINTER) return 104;
    if (write_test(1, (void *)0x700000000000ULL, 8) != BAD_POINTER) return 105;
    if (write_test(1, (void *)0, 8) != BAD_POINTER) return 106;
    if (write_test(1, (void *)0x7ffffffffffcULL, 8) != BAD_POINTER) return 107;
    if (write_test(7, output, 3) != BAD_FD) return 108;
    i64 written = write_test(1, output, 3);
#ifdef NT
    if (written != 0 || iosb[0] != 0 || iosb[1] != 3) return 109;
#else
    if (written != 3) return 109;
#endif
    volatile u64 *shared_va = (volatile u64 *)0x6000000000ULL;
    for (u64 i = 0; i < 8; ++i) {
        if (*shared_va != initial + i) return 110;
        *shared_va = initial + i + 1;
        data = 0x123456789abcdef0ULL + i;
        bss[sizeof bss - 1] = (unsigned char)i;
        int result = context_probe();
        if (result) return result;
#ifdef NT
        u64 current;
        __asm__ volatile("movq %%gs:0x30,%0" : "=r"(current));
        if (current != self) return 114;
#else
        __asm__ volatile("movq %%fs:0,%0" : "=r"(fs_value));
        if (fs_value != 0x3333) return 114;
#endif
        if (data != 0x123456789abcdef0ULL + i || bss[sizeof bss - 1] != i) return 111;
    }
    return 0;
}
