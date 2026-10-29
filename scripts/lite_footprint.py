#!/usr/bin/env python3
"""Panweave Lite footprint report from the lite-probe builds.

Usage:
  lite_footprint.py <efr32 elf> [--qemu <qemu log>] [--ram 32768]
                    [--check <baseline.json>] [--json <out.json>]

Reads the link build's sections and the `LITE_SIZES` table, the QEMU
run's measured stack peaks (its semihosting output), and the main stack
frame of the link build's `main` / firmware loop (from the Thumb
prologue), and prints the report of docs/lite.md. With --check, fails
(exit 1) when RAM or flash grew beyond the baseline's limits.

Pure Python, no binutils.
"""

import json
import re
import struct
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
from elf_size import Elf, SHF_ALLOC, SHF_WRITE, SHT_NOBITS  # noqa: E402

# The order of LITE_SIZES in examples/lite-probe/src/main.rs.
COMPONENTS = [
    ("LiteDevice (whole sensor)", 0),
    ("LiteStack", 1),
    ("MAC", 2),
    ("NWK", 2),
    ("APS", 2),
    ("ZDO", 2),
    ("ZCL", 2),
    ("ZCL cluster instance", 3),
    ("ZCL attribute entry", 4),
    ("Storage (NOR flash store)", 2),
    ("Block cipher state (one key)", 3),
    ("StackEvent", 3),
    ("BDB", 1),
    ("ZoneReporter", 1),
    ("Full Stack (default profile, for comparison)", 0),
]


def sections(elf):
    out = {}
    for name, sh_type, flags, addr, size in elf.sections():
        if flags & SHF_ALLOC and size:
            out[name] = (size, bool(flags & SHF_WRITE), sh_type == SHT_NOBITS)
    return out


def table(elf, name):
    sym = elf.symbol(name)
    if sym is None:
        raise SystemExit(f"no {name} symbol")
    addr, size = sym
    return struct.unpack_from(elf.e + f"{size // 4}I", elf.read(addr, size))


def thumb_frame(elf, sym):
    """Stack frame of a Thumb-2 function from its prologue (the first 24
    instructions): push / push.w / vpush, sub sp, #imm (16- and 32-bit),
    and movw/movt rN + sub sp, sp, rN. A static estimate of the frame;
    dynamic alloca is not used by Rust."""
    s = elf.symbol(sym)
    if s is None:
        return None
    addr, size = s
    return frame_at(elf, addr & ~1, size)


def frame_at(elf, addr, size):
    code = elf.read(addr, min(size, 96))
    frame, i, regs, n = 0, 0, {}, 0
    while i + 2 <= len(code) and n < 24:
        n += 1
        hw = struct.unpack_from("<H", code, i)[0]
        wide = hw >> 11 in (0b11101, 0b11110, 0b11111)
        if not wide:
            if hw & 0xFE00 == 0xB400:  # push {..., lr}
                frame += 4 * (bin(hw & 0xFF).count("1") + ((hw >> 8) & 1))
            elif hw & 0xFF80 == 0xB080:  # sub sp, #imm7*4
                frame += (hw & 0x7F) * 4
            i += 2
            continue
        if i + 4 > len(code):
            break
        hw2 = struct.unpack_from("<H", code, i + 2)[0]
        if hw == 0xE92D:  # push.w {reglist}
            frame += 4 * bin(hw2 & 0x5FFF).count("1")
        elif hw & 0xFBEF == 0xF1AD and hw2 & 0x8F00 == 0x0D00:  # sub.w sp, sp, #imm
            imm = ((hw & 0x0400) << 1) | ((hw2 & 0x7000) >> 4) | (hw2 & 0xFF)
            frame += thumb_expand(imm)
        elif hw & 0xFBFF == 0xF2AD and hw2 & 0x8F00 == 0x0D00:  # subw sp, sp, #imm12
            frame += ((hw & 0x0400) << 1) | ((hw2 & 0x7000) >> 4) | (hw2 & 0xFF)
        elif hw & 0xFBF0 == 0xF240:  # movw rd, #imm16
            rd = (hw2 >> 8) & 0xF
            regs[rd] = ((hw & 0xF) << 12) | ((hw & 0x0400) << 1) | ((hw2 & 0x7000) >> 4) | (hw2 & 0xFF)
        elif hw & 0xFBF0 == 0xF2C0:  # movt rd, #imm16
            rd = (hw2 >> 8) & 0xF
            hi = ((hw & 0xF) << 12) | ((hw & 0x0400) << 1) | ((hw2 & 0x7000) >> 4) | (hw2 & 0xFF)
            regs[rd] = (regs.get(rd, 0) & 0xFFFF) | (hi << 16)
        elif hw == 0xEBAD and hw2 & 0xFF00 == 0x0D00:  # sub.w sp, sp, rm
            frame += regs.get(hw2 & 0xF, 0)
        elif hw & 0xFFBF == 0xED2D:  # vpush
            frame += (hw2 & 0xFF) * 4
        i += 4
    return frame


def thumb_expand(imm12):
    if imm12 >> 10 == 0:
        return imm12 & 0xFF
    rot = imm12 >> 7
    v = 0x80 | (imm12 & 0x7F)
    return ((v >> rot) | (v << (32 - rot))) & 0xFFFFFFFF


def qemu(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    if "PANWEAVE-LITE-QEMU" not in text:
        raise SystemExit(f"{path}: no probe output")
    phases = {m.group(2): int(m.group(1)) for m in re.finditer(r"^phase (\d+) (.+)$", text, re.M)}
    entries = {m.group(2): int(m.group(1)) for m in re.finditer(r"^entry (\d+) (.+)$", text, re.M)}
    result = re.search(r"^result (.+)$", text, re.M).group(1)
    dropped = re.search(r"^dropped (.+)$", text, re.M).group(1)
    dlk = re.search(r"^dlk (\w+)$", text, re.M).group(1)
    return {"phases": phases, "entries": entries, "result": result, "dropped": dropped, "dlk": dlk}


def main():
    args = sys.argv[1:]
    if not args:
        raise SystemExit(__doc__)
    elf_path = args[0]
    opt = lambda k, d=None: args[args.index(k) + 1] if k in args else d
    ram_cap = int(opt("--ram", "32768"))
    elf = Elf(elf_path)
    secs = sections(elf)
    data = secs.get(".data", (0, True, False))[0]
    bss = secs.get(".bss", (0, True, True))[0] + secs.get(".uninit", (0, True, True))[0]
    flash = sum(s for n, (s, w, nb) in secs.items() if not w) + data
    sizes = table(elf, "LITE_SIZES")
    # The firmware loop's frame stays on the stack for good: `main`, the
    # cortex-m-rt trampoline and the probe's `firmware` (mangled names).
    names = [n for n in elf.function_names() if n in ("main", "__cortex_m_rt_main")
             or "__cortex_m_rt_main" in n or "8firmware17h" in n]
    main_frame = sum(v for v in (thumb_frame(elf, n) for n in names) if v)
    q = qemu(opt("--qemu")) if opt("--qemu") else None

    print("Panweave Lite — EFR32MG22 (Cortex-M33)")
    print()
    print(f"Build profile:        SleepySensor, IAS Zone water leak sensor{', DLK' if q and q['dlk'] == 'true' else ''}")
    print("Device role:          Sleepy End Device")
    print("Target:               thumbv8m.main-none-eabihf (opt-level z, fat LTO)")
    print(f"RAM capacity:         {ram_cap} bytes")
    print()
    print("STATIC MEMORY (size_of on the target; indented parts are inside the line above)")
    for (label, depth), v in zip(COMPONENTS, sizes):
        print(f"  {'  ' * depth}{label:<{44 - 2 * depth}} {v:>8} bytes")
    print()
    print(f"  Total .data         {data:>8} bytes")
    print(f"  Total .bss          {bss:>8} bytes")
    print()
    print("DYNAMIC EXECUTION")
    print(f"  main frame (static, link build prologue)   {main_frame:>6} bytes")
    peak = None
    if q:
        worst = max(q["phases"].values())
        peak = main_frame + worst
        for name, v in q["phases"].items():
            print(f"  QEMU-measured, {name:<28} {v:>6} bytes")
        print(f"  Peak application stack (main + deepest)    {peak:>6} bytes")
        print("  Peak interrupt stack                      NOT MEASURED (no radio ISR without RAIL)")
        print(f"  QEMU scenario: {q['result']}")
        print(f"  Dropped queue entries: {q['dropped']}")
    else:
        print("  Stack                                     NOT MEASURED (no QEMU log given)")
    print()
    print("COMPLETE FIRMWARE")
    static_ram = data + bss
    if peak is not None:
        total = static_ram + peak
        print(f"  Static RAM + peak stack                   {total:>6} bytes")
        print(f"  Available RAM                             {ram_cap:>6} bytes")
        print(f"  Remaining headroom                        {ram_cap - total:>6} bytes")
    print("  Radio driver (RAIL) and its RAM          NOT INCLUDED")
    print()
    print("FLASH")
    print(f"  .text + .rodata + vectors + .data init    {flash:>6} bytes")
    print()
    print("VERIFICATION")
    print(f"  Core type-size checks       {'PASS' if sizes[0] < ram_cap else 'FAIL'}")
    print("  Linker memory check         PASS (the link asserts the stack reserve)")
    print(f"  Stack measurement           {'PASS (QEMU, emulated)' if q else 'NOT MEASURED'}")
    print("  Hardware radio validation   NOT TESTED")
    print("  Zigbee conformance          NOT CERTIFIED")

    report = {"data": data, "bss": bss, "flash": flash, "sizes": list(sizes), "main_frame": main_frame,
              "peak_stack": peak, "qemu": q}
    if opt("--json"):
        json.dump(report, open(opt("--json"), "w"), indent=2)
    if opt("--check"):
        base = json.load(open(opt("--check")))
        bad = []
        if static_ram > base["max_static_ram"]:
            bad.append(f"static RAM {static_ram} > {base['max_static_ram']}")
        if flash > base["max_flash"]:
            bad.append(f"flash {flash} > {base['max_flash']}")
        if peak is not None and "max_ram_with_stack" in base and static_ram + peak > base["max_ram_with_stack"]:
            bad.append(f"RAM with stack {static_ram + peak} > {base['max_ram_with_stack']}")
        if bad:
            print("REGRESSION: " + "; ".join(bad))
            sys.exit(1)
        print("Within the footprint baseline.")


if __name__ == "__main__":
    main()
