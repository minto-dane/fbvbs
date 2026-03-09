ENTRY(_start)

SECTIONS
{
  . = 0x00100000;

  .text : ALIGN(4096)
  {
    *(.text .text.*)
    *(.rodata .rodata.*)
  }

  .data : ALIGN(4096)
  {
    *(.data .data.*)
  }

  .bss : ALIGN(4096)
  {
    *(COMMON)
    *(.bss .bss.*)
  }

  /DISCARD/ :
  {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
  }
}
