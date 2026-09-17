"""Extracts the device-type metadata of the Device Type Library into
panweave-device-library/metadata/devices.toml (identifiers only; the
mandatory clusters come from each device's PICS table). Requires the
pdftotext dump of the specification as the first argument."""
import re
import sys

PICS = {
    'B': 0x0000, 'PC': 0x0001, 'DTMP': 0x0002, 'DTC': 0x0002, 'I': 0x0003, 'G': 0x0004, 'S': 0x0005,
    'OO': 0x0006, 'OOSC': 0x0007, 'LVL': 0x0008, 'LC': 0x0008, 'ALM': 0x0009, 'T': 0x000a,
    'RSSI': 0x000b, 'AI': 0x000c, 'AO': 0x000d, 'AV': 0x000e, 'BI': 0x000f, 'BO': 0x0010,
    'BV': 0x0011, 'MI': 0x0012, 'MO': 0x0013, 'MV': 0x0014, 'CS': 0x0015, 'PART': 0x0016,
    'OTA': 0x0019, 'PWR': 0x001a, 'APLNC': 0x001b, 'PWM': 0x001c, 'POLL': 0x0020,
    'MOBCFG': 0x0022, 'NBCLEAN': 0x0023, 'NEARGW': 0x0024, 'KA': 0x0025,
    'SHDCFG': 0x0100, 'DRLK': 0x0101, 'WNCV': 0x0102, 'BAR': 0x0103, 'PCC': 0x0200,
    'TSTAT': 0x0201, 'FAN': 0x0202, 'DHUM': 0x0203, 'TSUIC': 0x0204, 'CC': 0x0300,
    'BC117': 0x0301, 'BC': 0x0301, 'ILL': 0x0400, 'IM': 0x0400, 'ILLVL': 0x0401, 'TMP': 0x0402,
    'TM': 0x0402, 'PRS': 0x0403, 'FLW': 0x0404, 'RH': 0x0405, 'OCC': 0x0406, 'OS': 0x0406,
    'EC': 0x040a, 'WSPD': 0x040b, 'IASZ': 0x0500, 'IASACE': 0x0501, 'IASWD': 0x0502,
    'TUN': 0x0600, 'SEPR': 0x0700, 'DRLC': 0x0701, 'SEMT': 0x0702, 'SMET': 0x0702,
    'SEMS': 0x0703, 'SETUN': 0x0704, 'SEPP': 0x0705, 'SECA': 0x0707, 'SEEV': 0x0709,
    'SEKE': 0x0800, 'APLNCID': 0x0b00, 'MTRID': 0x0b01, 'APPLEV': 0x0b02, 'APPLST': 0x0b03,
    'EMR': 0x0b04, 'DIAG': 0x0b05, 'TL': 0x1000,
}


def main(path, out):
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    devices, cur = [], None
    for i, l in enumerate(lines):
        m = re.match(r"^\s*\d+\s+(\d+)\.2 Classification\s+ID\s+Class", l)
        if m:
            mm = re.search(r"0x([0-9a-fA-F]{4})\s+(Simple|Dynamic|Node)", lines[i + 1] + " " + lines[i + 2])
            if mm:
                name = "?"
                for k in range(i - 1, max(0, i - 40), -1):
                    # Headings may be split ("T emperature"): join stray letters.
                    h = re.match(r"^\s*\d+\s+(\d+) ([A-Z][A-Za-z/ ()\-]+)$", lines[k])
                    if h and h.group(1) == m.group(1):
                        name = re.sub(r"\b([A-Z]) ([a-z])", r"\1\2", h.group(2).strip())
                        break
                cur = {'id': int(mm.group(1), 16), 'name': name, 'class': mm.group(2),
                       'section': m.group(1), 'pics': set()}
                devices.append(cur)
        if re.search(r"Table \d+\. (.+) PICS Items", l) and cur is not None:
            j = i + 1
            while j < len(lines) and not re.match(r"^\s*\d+\s+\d+ [A-Z]", lines[j]) \
                    and not re.search(r"^\s*\d+\s+\d+\.\d+ ", lines[j]):
                for t in re.findall(r"\b([A-Z][A-Z0-9]*)\.(S|C)\b", lines[j]):
                    cur['pics'].add(t)
                j += 1
    unknown = {c for d in devices for c, _ in d['pics'] if c not in PICS}
    if unknown:
        print("unknown PICS codes:", sorted(unknown), file=sys.stderr)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Device types of the Zigbee Device Type Library (document 23-02016-002):\n"
                "# Table 3 identifiers with each device's mandatory server/client clusters\n"
                "# taken from its PICS table (identifiers only). Produced by\n"
                "# scripts/dtl_metadata.py and maintained by hand afterwards;\n"
                "# `cargo xtask codegen` renders panweave-device-library/src/generated.rs.\n\n")
        for d in sorted(devices, key=lambda d: d['id']):
            s = sorted({PICS[c] for c, r in d['pics'] if r == 'S' and c in PICS})
            c = sorted({PICS[c] for c, r in d['pics'] if r == 'C' and c in PICS})
            f.write("[[device]]\nid = 0x%04X\nname = \"%s\"\nclass = \"%s\"\nsection = \"§%s\"\n"
                    "servers = [%s]\nclients = [%s]\n\n" % (
                        d['id'], d['name'].replace('"', ''), d['class'], d['section'],
                        ", ".join("0x%04X" % x for x in s), ", ".join("0x%04X" % x for x in c)))
    print(len(devices), "devices")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
