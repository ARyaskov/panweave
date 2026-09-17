#!/usr/bin/env python3
"""Update entries in the conformance inventories.

Usage:
    python scripts/conformance.py set <ID> [status=...] [module=...]
        [section=...] [tests=a,b,c] [notes=...] [summary=...]
    python scripts/conformance.py show <ID>

Entries are matched by id across all conformance/*.toml files. Existing
`tests` are replaced (use `tests+=a,b` to append).
"""

import glob
import re
import sys


def load():
    out = {}
    for path in sorted(glob.glob("conformance/*.toml")):
        out[path] = open(path, encoding="utf-8").read()
    return out


def find_block(text, id_):
    pat = re.compile(r"\[\[requirement\]\]\nid = \"%s\"\n(?:(?!\[\[requirement\]\]).)*" % re.escape(id_), re.S)
    m = pat.search(text)
    return m


def set_field(block, key, value):
    quoted = '"%s"' % value.replace('"', '\\"') if key != "tests" else value
    line = "%s = %s\n" % (key, quoted)
    pat = re.compile(r"^%s = .*\n" % re.escape(key), re.M)
    if pat.search(block):
        return pat.sub(lambda _: line, block, count=1)
    # Insert before notes if present, else append.
    block = block.rstrip("\n") + "\n"
    return block + line


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, id_ = argv[1], argv[2]
    files = load()
    for path, text in files.items():
        m = find_block(text, id_)
        if not m:
            continue
        block = m.group(0)
        if cmd == "show":
            print(block)
            return 0
        if cmd != "set":
            print(__doc__)
            return 2
        new = block
        for kv in argv[3:]:
            if "+=" in kv:
                k, v = kv.split("+=", 1)
                cur = re.search(r"^tests = \[(.*)\]", new, re.M)
                existing = [t.strip().strip('"') for t in cur.group(1).split(",") if t.strip()] if cur else []
                merged = existing + [t for t in v.split(",") if t and t not in existing]
                new = set_field(new, "tests", "[" + ", ".join('"%s"' % t for t in merged) + "]")
                continue
            k, v = kv.split("=", 1)
            if k == "tests":
                items = [t for t in v.split(",") if t]
                v = "[" + ", ".join('"%s"' % t for t in items) + "]"
            new = set_field(new, k, v)
        if not new.endswith("\n\n") and not new.endswith("\n"):
            new += "\n"
        text = text[: m.start()] + new + text[m.end():]
        open(path, "w", encoding="utf-8", newline="\n").write(text)
        print("updated", id_, "in", path)
        return 0
    print("id not found:", id_)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
