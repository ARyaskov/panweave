/* QEMU mps2-an505 (Cortex-M33), secure aliases: code in ZBT SSRAM1 at
 * 0x10000000, data in SSRAM2/3 at 0x38000000. The sensor gets exactly
 * the EFR32MG22's 32 KiB as RAM; the full coordinator it commissions
 * with, its emulated flash and the measurement buffers live in BIGRAM,
 * which the 32 KiB figure does not count. */
MEMORY
{
  FLASH  : ORIGIN = 0x10000000, LENGTH = 2M
  RAM    : ORIGIN = 0x38000000, LENGTH = 32K
  BIGRAM : ORIGIN = 0x38100000, LENGTH = 2M
}

SECTIONS
{
  .bigram (NOLOAD) : ALIGN(8)
  {
    *(.bigram .bigram.*);
  } > BIGRAM
} INSERT AFTER .uninit;

/* The stack lives at the top of BIGRAM: the coordinator is built on it.
 * The sensor's stack use is measured below each call into it
 * (src/stack_meter.rs), not from here. */
_stack_start = ORIGIN(BIGRAM) + LENGTH(BIGRAM);

_lite_stack_reserve = 8K;
ASSERT(ORIGIN(RAM) + LENGTH(RAM) - __sheap >= _lite_stack_reserve,
       "Panweave Lite: static RAM leaves less than the stack reserve in 32 KiB");
