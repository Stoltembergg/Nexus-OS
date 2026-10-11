ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }
SECTIONS {
  . = 0x100001000;
  .text : { *(.text*) *(.ltext*) } :text
  . = ALIGN(4096);
  .rodata : { *(.rodata*) *(.lrodata*) } :ro
  . = ALIGN(4096);
  .data : { *(.data*) *(.ldata*) *(.got*) } :data
  .bss : { *(.bss*) *(.lbss*) *(COMMON) } :data
  /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) }
}
