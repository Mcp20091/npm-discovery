import os


def _bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


NPM_URL = os.environ.get("NPM_URL", "").rstrip("/")
NPM_EMAIL = os.environ.get("NPM_EMAIL", "")
NPM_PASSWORD = os.environ.get("NPM_PASSWORD", "")
NPM_VERIFY_TLS = _bool("NPM_VERIFY_TLS", True)

SCAN_SUBNETS = [s.strip() for s in os.environ.get("SCAN_SUBNETS", "").split(",") if s.strip()]
SCAN_EXCLUDE = [s.strip() for s in os.environ.get("SCAN_EXCLUDE", "").split(",") if s.strip()]
BASE_DOMAIN =os.environ.get("BASE_DOMAIN", "").strip().strip(".")
SCAN_INTERVAL_HOURS = _float("SCAN_INTERVAL_HOURS", 6)
SCAN_ON_START = _bool("SCAN_ON_START", True)
SCAN_PORTS = [int(p) for p in os.environ.get(
    "SCAN_PORTS",
    "80,81,443,3000,3001,5000,5001,8000,8080,8096,8123,8443,9000").split(",") if p.strip().isdigit()]
SCAN_ALL_PORTS = _bool("SCAN_ALL_PORTS", False)
PROBE_TIMEOUT = _float("PROBE_TIMEOUT", 5)

WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = _int("WEB_PORT", 8080)
DATA_DIR = os.environ.get("DATA_DIR", "/var/lib/npm-discovery")


def problems():
    out = []
    for name, val in (("NPM_URL", NPM_URL), ("NPM_EMAIL", NPM_EMAIL), ("NPM_PASSWORD", NPM_PASSWORD),
                      ("SCAN_SUBNETS", SCAN_SUBNETS), ("BASE_DOMAIN", BASE_DOMAIN)):
        if not val:
            out.append(f"{name} is not set in config.env")
    return out
