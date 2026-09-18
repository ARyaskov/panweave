#!/usr/bin/env python3
"""Prints the ROM / RAM footprint of a 32-bit ELF the way `size` does.

Usage: elf_size.py <elf> [--sections] [--components]

ROM is every allocated, non-writable section plus the load image of
`.data` (its initial values live in flash); RAM is every allocated
writable section (`.data`, `.bss`, stacks). `--components` reads the
`PANWEAVE_SIZES` table the size probe (`examples/size-probe`) exports
and prints the size of each stack component on the target. Pure
Python: no binutils required.
"""

import struct
import sys

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHT_SYMTAB = 2
SHT_NOBITS = 8

# The order of `PANWEAVE_SIZES` in examples/size-probe/src/main.rs.
COMPONENTS = [
    "Node (facade)",
    "Stack (runtime)",
    "  MacService",
    "  Nwk (StackNwk)",
    "  Aps (StackAps)",
    "  Zdo (StackZdo)",
    "  Zcl (StackZcl)",
    "    EndpointInstance",
    "      ClusterInstance",
    "        ClusterState",
    "        Attribute",
    "  MemoryStorage<32, 128>",
    "  event queue",
    "Bdb",
]


class Elf:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 1:
            raise SystemExit("not a 32-bit ELF")
        self.e = "<" if d[5] == 1 else ">"
        (shoff,) = struct.unpack_from(self.e + "I", d, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(self.e + "HHH", d, 0x2E)
        self.headers = []
        for i in range(shnum):
            off = shoff + i * shentsize
            # name, type, flags, addr, offset, size, link
            self.headers.append(struct.unpack_from(self.e + "IIIIIII", d, off))
        self.shstr = self.headers[shstrndx][4]

    def string(self, table_off, idx):
        end = self.data.index(b"\0", table_off + idx)
        return self.data[table_off + idx : end].decode()

    def sections(self):
        return [
            (self.string(self.shstr, h[0]), h[1], h[2], h[3], h[5]) for h in self.headers
        ]

    def symbol(self, name):
        """(address, size) of a symbol, or None."""
        for h in self.headers:
            if h[1] != SHT_SYMTAB:
                continue
            _, _, _, _, off, size, link = h
            strtab = self.headers[link][4]
            for i in range(size // 16):
                st_name, st_value, st_size = struct.unpack_from(
                    self.e + "III", self.data, off + i * 16
                )
                if self.string(strtab, st_name) == name:
                    return st_value, st_size
        return None

    def read(self, addr, size):
        """Bytes at a load address, from the section that holds it."""
        for h in self.headers:
            _, ty, flags, sh_addr, sh_off, sh_size, _ = h
            if flags & SHF_ALLOC and ty != SHT_NOBITS and sh_addr <= addr < sh_addr + sh_size:
                start = sh_off + (addr - sh_addr)
                return self.data[start : start + size]
        raise SystemExit(f"address {addr:#x} is not in a loaded section")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    elf = Elf(sys.argv[1])
    rom = ram = 0
    rows = []
    for name, sh_type, flags, addr, size in elf.sections():
        if not flags & SHF_ALLOC or size == 0:
            continue
        writable = bool(flags & SHF_WRITE)
        nobits = sh_type == SHT_NOBITS
        if writable:
            ram += size
            if not nobits:
                rom += size
        else:
            rom += size
        rows.append((name, size, addr, "RAM" if writable else "ROM", nobits))
    if "--sections" in sys.argv:
        for name, size, addr, kind, nobits in rows:
            print(f"{name:20} {size:8}  {kind}{' (nobits)' if nobits else ''}  @0x{addr:08x}")
    print(f"ROM {rom} bytes ({rom / 1024:.1f} KiB)")
    print(f"RAM {ram} bytes ({ram / 1024:.1f} KiB)")
    if "--components" in sys.argv:
        sym = elf.symbol("PANWEAVE_SIZES")
        if sym is None:
            raise SystemExit("no PANWEAVE_SIZES symbol: not the size probe?")
        addr, size = sym
        values = struct.unpack_from(elf.e + f"{size // 4}I", elf.read(addr, size))
        for label, value in zip(COMPONENTS, values):
            print(f"{label:28} {value:8}  ({value / 1024:.1f} KiB)")


if __name__ == "__main__":
    main()
