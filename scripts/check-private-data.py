#!/usr/bin/env python3
"""Refuse device identifiers and personal data in what is about to be committed.

Real hardware leaks into this repository easily: capture logs, CLI output
pasted into docs, an address copied into a test. This scanner looks at the
lines a commit adds and reports values that identify a real device, network
or person:

* IEEE (EUI-64) and EUI-48 / Wi-Fi BSSID addresses, written with separators,
  as 0x literals, as byte arrays or bare hex next to an address keyword;
* Zigbee keys and install codes, extended PAN IDs;
* Telegram bot tokens and chat IDs, Wi-Fi SSIDs and passwords;
* e-mail addresses and private IPv4 addresses.

Synthetic values are allowed: locally administered addresses (second hex
digit 2, 6, A or E), addresses whose device part is mostly zeros or a
repeated / sequential pattern, documentation e-mail domains and well-known
public keys. A line containing `privacy:allow` is skipped, and
`.privacy-allowlist` (one value per line, separators optional, `#` comments)
lists further exceptions.

Usage:
    python scripts/check-private-data.py            # staged changes
    python scripts/check-private-data.py --all      # staged + unstaged tracked changes
    python scripts/check-private-data.py FILE...    # whole files
    python scripts/check-private-data.py --hook     # Claude Code PreToolUse hook (stdin JSON)

Exit status: 0 clean, 1 findings (2 in --hook mode, which blocks the commit).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_FILE = ROOT / ".privacy-allowlist"
ALLOW_MARKER = "privacy:allow"

# Paths that are not ours to anonymize or cannot hold such data.
SKIP_PATH = re.compile(
    r"(^|/)(vendor|target)/|Cargo\.lock$|\.(der|bin|elf|png|jpg|pcapng?|a|o|rlib)$"
)

HEX = "[0-9A-Fa-f]"
SEP_ADDR = re.compile(
    rf"(?<![0-9A-Fa-f:\-]){HEX}{{2}}(?P<s>[:\-])(?:{HEX}{{2}}(?P=s)){{4}}"
    rf"(?:{HEX}{{2}}(?P=s){HEX}{{2}}(?P=s))?{HEX}{{2}}(?![0-9A-Fa-f:\-])"
)
HEX64_LITERAL = re.compile(rf"\b0[xX](?:{HEX}_?){{15}}{HEX}\b")
ADDR_KEYWORD = re.compile(
    r"(?i)ieee|eui|extended|ext_?addr|ext_?pan|\bmac\b|bssid|\baddr|address|pan_?id"
)
BARE_HEX = re.compile(rf"(?<![0-9A-Za-z_]){HEX}{{16}}(?![0-9A-Za-z_])|(?<![0-9A-Za-z_]){HEX}{{12}}(?![0-9A-Za-z_])")
BYTE_ARRAY = re.compile(
    rf"\[\s*(?:0[xX]{HEX}{{2}}\s*,\s*){{5}}(?:(?:0[xX]{HEX}{{2}}\s*,\s*){{2}})?0[xX]{HEX}{{2}}\s*,?\s*\]"
)
KEY_KEYWORD = re.compile(r"(?i)network_?key|link_?key|install_?code|tclk|nwk_?key|\bkey\s*[=:]")
HEX128 = re.compile(rf"(?<![0-9A-Za-z_])(?:{HEX}{{2}}[:\- ]?){{15}}{HEX}{{2}}(?:{HEX}{{4}})?(?![0-9A-Za-z_])")
TG_TOKEN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")
TG_CHAT = re.compile(r"(?<![\d\-])-100\d{10}\b|(?i:chat_?id)\W{1,4}(-?\d{6,})")
WIFI_KV = re.compile(
    r"""(?ix)(?:ssid|password|passphrase|psk|wifi[_\-]?pass\w*)\s*[:=]\s*["']([^"'<>{}$\\]{3,})["']"""
)
WIFI_CLI = re.compile(r"""(?i)--wifi-(?:ssid|password)[ =]+["']?([^\s"'<>$]+)""")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Not preceded or followed by another ".N": "3.10.2.3.5" is a spec section.
PRIVATE_IP = re.compile(
    r"(?<![\d.§])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d]|\.\d)"
)

PLACEHOLDER_WORDS = re.compile(
    r"(?i)example|your|changeme|placeholder|secret|password|my[_\- ]?(?:wifi|network|ssid)|"
    r"home[_\- ]?network|test|dummy|sample|xxx|\*\*\*|ssid|^\.\.\.$"
)
SAFE_EMAIL_DOMAINS = re.compile(
    r"(?i)@(?:[\w.\-]*\.)?(?:example\.(?:com|org|net)|users\.noreply\.github\.com|localhost)$|noreply@"
)
PUBLIC_KEYS = {
    "5a6967426565416c6c69616e63653039",  # ZigBeeAlliance09
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",  # ZLL / Touchlink certification key
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",  # BDB test vectors
}


@dataclass
class Finding:
    path: str
    line: int
    kind: str
    value: str
    suggestion: str


def load_allowlist() -> set[str]:
    allowed: set[str] = set()
    if ALLOWLIST_FILE.exists():
        for raw in ALLOWLIST_FILE.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if entry:
                allowed.add(normalize(entry))
    return allowed


def normalize(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return re.sub(r"[^0-9a-z@.\-]", "", value.replace(":", "").replace("-", "").replace("_", ""))


def to_bytes(value: str) -> list[int] | None:
    if value.lstrip().startswith("["):
        return [int(h, 16) for h in re.findall(r"0[xX]([0-9A-Fa-f]{2})", value)]
    digits = re.sub(r"[^0-9A-Fa-f]", "", value[2:] if value.lower().startswith("0x") else value)
    if len(digits) % 2:
        return None
    return [int(digits[i : i + 2], 16) for i in range(0, len(digits), 2)]


def trivial(part: list[int]) -> bool:
    """A device part that no real manufacturer assigns: mostly zero, a repeated
    or sequential pattern, or bytes like aa, bb, 11."""
    meaningful = [b for b in part if b not in (0x00, 0xFF)]
    if len(set(meaningful)) <= 2:
        return True
    if sum((b >> 4) != (b & 0x0F) for b in part) <= 2:
        return True
    rest = part[next((i for i, b in enumerate(part) if b), len(part)) :]
    diffs = {(rest[i + 1] - rest[i]) & 0xFF for i in range(len(rest) - 1)}
    return len(diffs) <= 1


def synthetic_address(octets: list[int], array: bool = False) -> bool:
    # Few distinct bytes (A0:A0:0A:0A:...), bytes like aa, bb, 11 (allowing one
    # odd byte), or printable ASCII ("TESTSECA") are test values.
    if len(set(octets)) <= len(octets) // 2:
        return True
    if sum((b >> 4) != (b & 0x0F) for b in octets) <= 1:
        return True
    if all(0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A for b in octets):
        return True
    diffs = {(octets[i + 1] - octets[i]) & 0xFF for i in range(len(octets) - 1)}
    if len(diffs) == 1:
        return True

    def canonical(o: list[int]) -> bool:
        return bool(o[0] & 0x02) or trivial(o[3:])

    # Text is written MSB first (OUI leading). A byte array may be either
    # order, so it is synthetic only if it reads as synthetic both ways.
    if array:
        return canonical(octets) and canonical(octets[::-1])
    return canonical(octets)


def synthetic_key(octets: list[int]) -> bool:
    if len(set(octets)) <= 4:
        return True
    diffs = {(octets[i + 1] - octets[i]) & 0xFF for i in range(len(octets) - 1)}
    return len(diffs) == 1


class Anonymizer:
    """Stable replacements, so one real value maps to one placeholder."""

    def __init__(self) -> None:
        self.seen: dict[tuple[str, str], str] = {}

    def suggest(self, kind: str, value: str) -> str:
        key = (kind, normalize(value))
        if key in self.seen:
            return self.seen[key]
        n = sum(1 for k in self.seen if k[0] == kind) + 1
        if kind in ("ieee", "eui48"):
            octets = to_bytes(value) or []
            fake = [0x02] + [0x00] * (len(octets) - 2) + [n & 0xFF]
            if len(octets) == 8 and value.strip().startswith("["):
                fake = fake[::-1]
            text = self.render_like(value, fake)
        elif kind == "zigbee-key":
            text = "00112233445566778899aabbccddeeff"
        elif kind == "telegram-token":
            text = "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        elif kind == "telegram-chat":
            text = "-1001234567890"
        elif kind == "wifi":
            text = "example-wifi" if n == 1 else f"example-wifi-{n}"
        elif kind == "email":
            text = f"user{n}@example.com"
        elif kind == "private-ip":
            text = f"192.0.2.{n}"
        else:
            text = "<redacted>"
        self.seen[key] = text
        return text

    @staticmethod
    def render_like(original: str, octets: list[int]) -> str:
        upper = any(c in "ABCDEF" for c in original)
        fmt = "{:02X}" if upper else "{:02x}"
        o = original.strip()
        if o.startswith("["):
            return "[" + ", ".join("0x" + fmt.format(b) for b in octets) + "]"
        if o.lower().startswith("0x"):
            body = "".join(fmt.format(b) for b in octets)
            if "_" in o:
                body = "_".join(body[i : i + 4] for i in range(0, len(body), 4))
            return o[:2] + body
        for sep in (":", "-"):
            if sep in o:
                return sep.join(fmt.format(b) for b in octets)
        return "".join(fmt.format(b) for b in octets)


def scan_line(path: str, lineno: int, line: str, allow: set[str], anon: Anonymizer) -> list[Finding]:
    if ALLOW_MARKER in line:
        return []
    found: list[Finding] = []
    taken: list[tuple[int, int]] = []

    def add(kind: str, value: str, span: tuple[int, int]) -> None:
        if any(span[0] < e and s < span[1] for s, e in taken):
            return
        taken.append(span)
        if normalize(value) in allow:
            return
        found.append(Finding(path, lineno, kind, value, anon.suggest(kind, value)))

    def address(m: re.Match[str], value: str | None = None) -> None:
        value = value or m.group(0)
        octets = to_bytes(value)
        array = value.lstrip().startswith("[")
        if octets and len(octets) in (6, 8) and not synthetic_address(octets, array):
            add("ieee" if len(octets) == 8 else "eui48", value, m.span())
        else:
            taken.append(m.span())

    for m in TG_TOKEN.finditer(line):
        if len(set(m.group(0).split(":", 1)[1])) > 4:  # not AAAA... placeholders
            add("telegram-token", m.group(0), m.span())
    for m in SEP_ADDR.finditer(line):
        address(m)
    for m in BYTE_ARRAY.finditer(line):
        if ADDR_KEYWORD.search(line):
            address(m, m.group(0))
    for m in HEX64_LITERAL.finditer(line):
        if ADDR_KEYWORD.search(line):
            address(m)
    if ADDR_KEYWORD.search(line):
        for m in BARE_HEX.finditer(line):
            if re.fullmatch(r"\d+", m.group(0)):
                continue
            address(m)
    if KEY_KEYWORD.search(line):
        for m in HEX128.finditer(line):
            octets = to_bytes(m.group(0)) or []
            if normalize(m.group(0)) in PUBLIC_KEYS or synthetic_key(octets):
                taken.append(m.span())
                continue
            add("zigbee-key", m.group(0), m.span())
    for m in TG_CHAT.finditer(line):
        value = m.group(1) or m.group(0)
        digits = value.lstrip("-")
        placeholder = "123456" in digits or len(set(digits.removeprefix("100"))) <= 2
        if not placeholder:
            add("telegram-chat", value, m.span())
    for rx in (WIFI_KV, WIFI_CLI):
        for m in rx.finditer(line):
            value = m.group(1)
            if len(value) >= 3 and not re.search(r"[\[\]…]", value) and not PLACEHOLDER_WORDS.search(value):
                add("wifi", value, m.span(1))
    for m in EMAIL.finditer(line):
        if not SAFE_EMAIL_DOMAINS.search(m.group(0)):
            add("email", m.group(0), m.span())
    for m in PRIVATE_IP.finditer(line):
        add("private-ip", m.group(0), m.span())
    return found


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout


def added_lines(diff_args: list[str]) -> list[tuple[str, int, str]]:
    out = git("diff", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR", *diff_args)
    rows: list[tuple[str, int, str]] = []
    path, lineno = "", 0
    for line in out.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and path:
            rows.append((path, lineno, line[1:]))
            lineno += 1
    return rows


def file_lines(paths: list[str]) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    for p in paths:
        try:
            text = Path(p).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rows.extend((p, i, line) for i, line in enumerate(text.splitlines(), 1))
    return rows


def scan(rows: list[tuple[str, int, str]]) -> list[Finding]:
    allow, anon = load_allowlist(), Anonymizer()
    findings: list[Finding] = []
    for path, lineno, line in rows:
        if SKIP_PATH.search(path.replace("\\", "/")):
            continue
        findings.extend(scan_line(path, lineno, line, allow, anon))
    return findings


def report(findings: list[Finding], hook: bool) -> str:
    lines = []
    if hook:
        lines += [
            "PRIVATE DATA GATE: the commit is blocked. The files being committed contain",
            "values that look like real device, network or personal identifiers.",
            "",
            "Anonymize every finding below in the working tree, `git add` the files again",
            "and retry the commit. Use the suggested placeholder (or another synthetic value)",
            "consistently: the same real value gets the same placeholder in every file, so",
            "logs and docs stay coherent. Do not delete the surrounding content. If a value",
            "is genuinely public or synthetic, add `privacy:allow` to that line or list it",
            "in .privacy-allowlist, and say so to the user.",
            "",
        ]
    for f in findings:
        lines.append(f"{f.path}:{f.line}: {f.kind}: {f.value}  ->  {f.suggestion}")
    if hook:
        lines.append("")
        lines.append(f"{len(findings)} finding(s). Re-check: python scripts/check-private-data.py")
    return "\n".join(lines)


def hook_main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    command = str((payload.get("tool_input") or {}).get("command") or "")
    if not re.search(r"\bgit\b[^\n;|&]*\bcommit\b", command):
        return 0
    if re.search(r"\bgit\b[^\n;|&]*\badd\b", command):
        print(
            "PRIVATE DATA GATE: run `git add` and `git commit` as separate commands, so the "
            "staged content can be checked for device identifiers before the commit.",
            file=sys.stderr,
        )
        return 2
    rows = added_lines(["--cached"])
    if re.search(r"\bcommit\b[^\n;|&]*\s(-a\b|--all\b|-[a-zA-Z]*a[a-zA-Z]*\b)", command):
        rows += added_lines([])
    findings = scan(rows)
    if not findings:
        return 0
    print(report(findings, hook=True), file=sys.stderr)
    return 2


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    if "--hook" in argv:
        return hook_main()
    files = [a for a in argv if not a.startswith("--")]
    if files:
        rows = file_lines(files)
    else:
        rows = added_lines(["--cached"])
        if "--all" in argv:
            rows += added_lines([])
    findings = scan(rows)
    if findings:
        print(report(findings, hook=False))
        print(f"\n{len(findings)} finding(s).")
        return 1
    print("No private data found.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
