"""Scan targets and exclusions.

A spec is one IPv4 address (192.168.1.5), a subnet (192.168.1.128/28) or a last-octet range (192.168.1.50-60).
For scan targets only, a full range (192.168.1.50-192.168.2.20) is also accepted and turned into subnets.
"""
import ipaddress
import re

RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
FULL_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")
ADHOC_MAX = 1 << 16  # addresses in one hand-typed scan
HELP = "Enter an IPv4 address (192.168.1.5), a range (192.168.1.50-60) or a subnet (192.168.1.128/28)"


def normalize(v):
    """One spec in canonical form. Raises ValueError with a readable message."""
    v = v.strip()
    m = RANGE_RE.match(v)
    try:
        if m:
            ipaddress.IPv4Address(m.group(1) + m.group(2))
            if not (int(m.group(2)) <= int(m.group(3)) <= 255):
                raise ValueError
            return v
        if "/" in v:
            return str(ipaddress.IPv4Network(v, strict=False))
        return str(ipaddress.IPv4Address(v))
    except ValueError:
        raise ValueError(HELP)


def covers(spec, ip):
    """True if `spec` (IP, a.b.c.d-e range or CIDR) covers `ip`."""
    try:
        addr = ipaddress.IPv4Address(ip)
        m = RANGE_RE.match(spec)
        if m:
            base = ipaddress.IPv4Address(m.group(1) + m.group(2))
            last = int(addr) & 0xFF
            return (int(addr) >> 8 == int(base) >> 8) and int(m.group(2)) <= last <= int(m.group(3))
        if "/" in spec:
            return addr in ipaddress.IPv4Network(spec, strict=False)
        return addr == ipaddress.IPv4Address(spec)
    except ValueError:
        return False


def size(spec):
    m = RANGE_RE.match(spec)
    if m:
        return int(m.group(3)) - int(m.group(2)) + 1
    return ipaddress.IPv4Network(spec, strict=False).num_addresses if "/" in spec else 1


def parse_list(text):
    """Comma / space / newline separated specs typed by the user -> list of canonical specs for nmap."""
    parts = [p for p in re.split(r"[,\s;]+", (text or "").strip()) if p]
    if not parts:
        raise ValueError("Enter at least one IP address, range or subnet")
    specs = []
    for p in parts:
        m = FULL_RANGE_RE.match(p)
        if m:
            try:
                a, b = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
            except ValueError:
                raise ValueError(f"'{p}': {HELP}")
            if a > b:
                raise ValueError(f"'{p}' runs backwards (the first address must be lower)")
            specs += [str(n) for n in ipaddress.summarize_address_range(a, b)]
            continue
        try:
            specs.append(normalize(p))
        except ValueError:
            raise ValueError(f"'{p}': {HELP}")
    total = sum(size(s) for s in specs)
    if total > ADHOC_MAX:
        raise ValueError(f"That is {total:,} addresses; a hand-typed scan is limited to {ADHOC_MAX:,}. "
                         "Use the saved subnets in Settings for bigger scans.")
    return specs
