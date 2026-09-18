/* A generic Cortex-M4F part: 1 MiB flash, 256 KiB RAM (nRF52840-like). */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
