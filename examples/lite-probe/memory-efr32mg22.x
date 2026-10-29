/* EFR32MG22C224F512IM40 (EFR32MG22 Datasheet, ordering information):
 * 512 KiB of flash at 0x00000000, 32 KiB of RAM at 0x20000000.
 * Other MG22 parts (C224F352, …) differ in flash, not RAM: check the
 * part. The last 16 KiB of flash are left to the persistent store
 * (two 8 KiB pages); the bootloader region is not modelled. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 512K - 16K
  RAM   : ORIGIN = 0x20000000, LENGTH = 32K
}

/* The main stack grows down from the top of RAM into what .data and
 * .bss leave. Reserve at least the measured worst case (docs/lite.md):
 * the link fails when the static RAM leaves less. */
_lite_stack_reserve = 8K;
ASSERT(ORIGIN(RAM) + LENGTH(RAM) - __sheap >= _lite_stack_reserve,
       "Panweave Lite: static RAM leaves less than the stack reserve in 32 KiB");
