"""Settings. Precedence: saved in the web UI (database) > config.env / environment > built-in default.

Every module reads values as config.NAME at call time, so apply() takes effect immediately
(except WEB_HOST / WEB_PORT, which need a restart).
"""
import os

DATA_DIR = os.environ.get("DATA_DIR", "/var/lib/npm-discovery")

DEFAULT_PORTS = "80,81,443,1880,2283,2342,3000,3001,3002,3030,3333,4000,4200,4533,5000,5001,5006,5055,5173,5230,5380,5601,5678,6052,6767,7474,7575,7860,7861,7878,8000,8001,8006,8007,8008,8010,8080,8081,8082,8083,8086,8088,8096,8112,8123,8181,8188,8191,8200,8384,8443,8444,8500,8501,8686,8787,8888,8920,8989,9000,9001,9090,9091,9117,9443,9696,10000,13378,19999,32400,42000-42009"

# name: (type, default as string)
SPEC = {
    "NPM_URL": ("url", ""),
    "NPM_EMAIL": ("str", ""),
    "NPM_PASSWORD": ("secret", ""),
    "NPM_VERIFY_TLS": ("bool", "true"),
    "SCAN_SUBNETS": ("cidrs", ""),
    "BASE_DOMAIN": ("str", ""),
    "SCAN_INTERVAL_HOURS": ("float", "0"),
    "SCAN_ON_START": ("bool", "false"),
    "SCAN_PORTS": ("ports", DEFAULT_PORTS),
    "SCAN_ALL_PORTS": ("bool", "false"),
    "SCAN_GENTLE": ("bool", "false"),
    "PROBE_TIMEOUT": ("float", "5"),
    "DEFAULT_CERT_ID": ("certid", "0"),  # NPM certificate preselected in the New tab; 0 = none
    "WEB_HOST": ("str", "0.0.0.0"),
    "WEB_PORT": ("int", "8080"),
}
RESTART_KEYS = {"WEB_HOST", "WEB_PORT"}
NPM_KEYS = {"NPM_URL", "NPM_EMAIL", "NPM_PASSWORD", "NPM_VERIFY_TLS"}

# Read-only: from config.env only (managed in the UI on the Exclusions tab).
SCAN_EXCLUDE = [s.strip() for s in os.environ.get("SCAN_EXCLUDE", "").split(",") if s.strip()]

_overrides = {}


def raw(name):
    """Current effective value as a string."""
    if name in _overrides:
        return _overrides[name]
    return os.environ.get(name, SPEC[name][1])


def source(name):
    if name in _overrides:
        return "ui"
    return "config" if name in os.environ else "default"


def parse(name, s):
    """Validate and convert a string to the typed value. Raises ValueError with a readable message."""
    import ipaddress
    kind = SPEC[name][0]
    s = str(s).strip()
    if kind == "bool":
        if s.lower() in ("1", "true", "yes", "on"):
            return True
        if s.lower() in ("0", "false", "no", "off", ""):
            return False
        raise ValueError(f"{name}: must be true or false")
    if kind == "int":
        try:
            v = int(s)
        except ValueError:
            raise ValueError(f"{name}: must be a whole number")
        if not 1 <= v <= 65535:
            raise ValueError(f"{name}: must be 1-65535")
        return v
    if kind == "certid":
        if not s.isdigit():
            raise ValueError(f"{name}: must be a certificate id (0 = none)")
        return int(s)
    if kind == "float":
        try:
            v = float(s or 0)
        except ValueError:
            raise ValueError(f"{name}: must be a number")
        if v < 0 or (name == "PROBE_TIMEOUT" and v < 1):
            raise ValueError(f"{name}: value out of range")
        return v
    if kind == "ports":
        out = []
        for p in s.replace("\n", ",").split(","):
            p = p.strip()
            if not p:
                continue
            lo, _, hi = p.partition("-")  # a single port, or a range like 42000-42009
            if not lo.strip().isdigit() or (_ and not hi.strip().isdigit()):
                raise ValueError(f"{name}: '{p}' is not a valid port or range")
            lo, hi = int(lo), int(hi) if _ else int(lo)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"{name}: '{p}' is not a valid port or range")
            out.extend(range(lo, hi + 1))
        out = sorted(set(out))
        if not out:
            raise ValueError(f"{name}: list at least one port")
        return out
    if kind == "cidrs":
        out = []
        for c in s.replace("\n", ",").split(","):
            c = c.strip()
            if c:
                try:
                    ipaddress.IPv4Network(c, strict=False)
                except ValueError:
                    raise ValueError(f"{name}: '{c}' is not a valid IPv4 subnet (e.g. 192.168.1.0/24)")
                out.append(c)
        return out
    if kind == "url":
        s = s.rstrip("/")
        if s and not s.lower().startswith(("http://", "https://")):
            raise ValueError(f"{name}: must start with http:// or https://")
        return s
    if name == "BASE_DOMAIN":
        s = s.strip(".").lower()
    return s


def apply(overrides=None):
    """(Re)load all values into module attributes."""
    if overrides is not None:
        _overrides.clear()
        _overrides.update(overrides)
    g = globals()
    for name in SPEC:
        try:
            g[name] = parse(name, raw(name))
        except ValueError:
            g[name] = parse(name, SPEC[name][1])  # a bad stored value falls back to the default


def problems():
    out = []
    for name, val in (("NPM_URL", NPM_URL), ("NPM_EMAIL", NPM_EMAIL), ("NPM_PASSWORD", NPM_PASSWORD),
                      ("SCAN_SUBNETS", SCAN_SUBNETS), ("BASE_DOMAIN", BASE_DOMAIN)):
        if not val:
            out.append(f"{name} is not set - open the Settings tab")
    return out


apply()
