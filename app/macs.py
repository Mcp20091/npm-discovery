"""MAC addresses and vendor lookup.

An unprivileged TCP connect scan cannot see MAC addresses, so they are read from the kernel's ARP table
after a scan. That only covers hosts on the same network segment as this container.

Vendor names come from the providers enabled in the MAC_PROVIDERS setting, asked in this fixed order, first hit wins:
  nmap        the offline list that ships with nmap (nmap-mac-prefixes)
  ieee        a downloaded offline copy of the IEEE OUI registry (DATA_DIR/oui.csv)
  macvendors  online, api.macvendors.com
  maclookup   online, api.maclookup.app
Online providers are only contacted when enabled AND the user clicked a Look up button (never during a scan),
and they only ever receive the 3-byte manufacturer prefix (OUI), never the full MAC. Every online answer is
cached in the database so a prefix is asked for only once. Vendor names are third-party data: they are
length-capped and stripped of control characters before they are stored.
"""
import csv
import io
import os
import re
import threading
import time

import httpx
from fastapi import APIRouter, HTTPException

from . import config, db

router = APIRouter()

OUI_PATHS = ["/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes"]
# Base URLs can be overridden through the environment (used by the tests to point at a local fake server).
IEEE_URL = os.environ.get("MAC_IEEE_URL", "https://standards-oui.ieee.org/oui/oui.csv")
MACVENDORS_URL = os.environ.get("MAC_MACVENDORS_URL", "https://api.macvendors.com/{oui}")
MACLOOKUP_URL = os.environ.get("MAC_MACLOOKUP_URL", "https://api.maclookup.app/v2/macs/{oui}")
IEEE_MAX_BYTES = 15 * 1024 * 1024
IEEE_TIMEOUT = 60.0
ONLINE_TIMEOUT = 10.0
ONLINE_SPACING = 1.1       # seconds between two online requests (free tiers allow about 1 per second)
RATE_BACKOFF = 300.0       # after a 429 an online provider is left alone for this long
NEG_TTL = 30 * 86400       # an online "unknown" answer is asked again after 30 days
REPLY_MAX = 64 * 1024      # bytes read from an online reply
VENDOR_MAX = 100
PRIVATE = "Private (randomized) address"
SOURCE_LABELS = {
    "nmap": "nmap list (offline)",
    "ieee": "IEEE registry copy (offline)",
    "macvendors": "api.macvendors.com (online, cached)",
    "maclookup": "api.maclookup.app (online, cached)",
    "randomized": "Locally administered (randomized) address; no lookup was done",
}
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")
_oui = None
_ieee = {"mtime": None, "size": None, "map": {}}
_online_lock = threading.Lock()
_last_online = 0.0
_blocked_until = {}        # provider -> time.monotonic() until which it is not contacted after a 429


class ProviderError(Exception):
    """A provider could not answer (offline, DNS, HTTP error, bad reply)."""


class RateLimited(Exception):
    """An online provider answered 429; stop asking."""

    def __init__(self, provider):
        super().__init__(f"{provider} rate limit reached (HTTP 429). Lookups were stopped; try again in a few minutes "
                         f"(the free tier allows about one request per second).")
        self.provider = provider


def read_arp(path="/proc/net/arp"):
    """Return {ip: 'AA:BB:CC:DD:EE:FF'} for complete ARP entries."""
    out = {}
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[2] != "0x0" and p[3] != "00:00:00:00:00:00":
                    out[p[0]] = p[3].upper()
    except OSError:
        pass
    return out


def clean(s):
    """Untrusted vendor text: no control characters, collapsed whitespace, at most 100 characters."""
    if not isinstance(s, str):
        return ""
    return re.sub(r" {2,}", " ", _CTRL.sub(" ", s)).strip()[:VENDOR_MAX].strip()


# ---------- offline lists ----------

def _load():
    global _oui
    if _oui is not None:
        return _oui
    _oui = {}
    for p in OUI_PATHS:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        prefix, _, name = line.strip().partition(" ")
                        _oui[prefix.upper()] = clean(name)
            break
        except OSError:
            continue
    return _oui


def ieee_path():
    return os.path.join(config.DATA_DIR, "oui.csv")


def parse_ieee(raw):
    """Parse the IEEE oui.csv bytes into ({6 hex: name}, skipped_rows). Raises ValueError if it is not that file."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("The IEEE file is not valid UTF-8 text")
    try:
        rd = csv.DictReader(io.StringIO(text, newline=""))
        names = rd.fieldnames or []
        if "Assignment" not in names or "Organization Name" not in names:
            raise ValueError("The file does not look like the IEEE OUI list (expected columns Registry, "
                             "Assignment, Organization Name, Organization Address)")
        out, skipped = {}, 0
        for row in rd:
            a = (row.get("Assignment") or "").strip().upper()
            n = clean(row.get("Organization Name") or "")
            if re.fullmatch(r"[0-9A-F]{6}", a) and n:
                out[a] = n
            else:
                skipped += 1  # MA-M / MA-S blocks have longer assignments and cannot be resolved by 3 bytes
    except csv.Error as e:
        raise ValueError(f"The IEEE file could not be parsed as CSV: {e}")
    if not out:
        raise ValueError("The IEEE file contains no usable entries")
    return out, skipped


def _ieee_map():
    """Entries of the local IEEE copy, reloaded when the file changes. Raises ProviderError if there is none."""
    p = ieee_path()
    try:
        st = os.stat(p)
    except OSError:
        raise ProviderError("The IEEE list has not been downloaded yet (Settings > MAC address lookup > Download IEEE list)")
    if _ieee["mtime"] != st.st_mtime or _ieee["size"] != st.st_size:
        try:
            with open(p, "rb") as f:
                m, _ = parse_ieee(f.read())
        except (OSError, ValueError) as e:
            raise ProviderError(f"The local IEEE list is unusable ({e}); download it again")
        _ieee.update(mtime=st.st_mtime, size=st.st_size, map=m)
    return _ieee["map"]


def ieee_status():
    try:
        st = os.stat(ieee_path())
    except OSError:
        return {"exists": False}
    try:
        return {"exists": True, "entries": len(_ieee_map()), "date": st.st_mtime, "age_days": (time.time() - st.st_mtime) / 86400}
    except ProviderError as e:
        return {"exists": True, "entries": 0, "date": st.st_mtime, "age_days": (time.time() - st.st_mtime) / 86400, "error": str(e)}


# ---------- online providers ----------

def _fetch_text(url):
    """GET a small reply. Returns (status, body text). Raises ProviderError on network problems."""
    try:
        with httpx.Client(timeout=ONLINE_TIMEOUT, verify=True, follow_redirects=False,
                          headers={"User-Agent": "npm-discovery"}) as c:
            with c.stream("GET", url) as r:
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > REPLY_MAX:
                        raise ProviderError("reply too large")
                return r.status_code, body.decode("utf-8", errors="replace")
    except httpx.TimeoutException:
        raise ProviderError("timed out")
    except httpx.HTTPError as e:
        raise ProviderError(f"{type(e).__name__}: {str(e)[:100]}")


def _ask_macvendors(oui):
    status, body = _fetch_text(MACVENDORS_URL.format(oui=oui))
    if status == 404:
        return None
    if status == 429:
        raise RateLimited("macvendors")
    if status != 200:
        raise ProviderError(f"HTTP {status}")
    body = body.strip()
    if body.startswith("{") or "<" in body[:20]:
        raise ProviderError("unexpected reply")
    return clean(body) or None


def _ask_maclookup(oui):
    status, body = _fetch_text(MACLOOKUP_URL.format(oui=oui))
    if status == 429:
        raise RateLimited("maclookup")
    if status == 404:
        return None
    if status != 200:
        raise ProviderError(f"HTTP {status}")
    try:
        import json
        j = json.loads(body)
    except ValueError:
        raise ProviderError("reply is not JSON")
    if not isinstance(j, dict):
        raise ProviderError("unexpected reply")
    if j.get("success") is False and "many" in str(j.get("error", "")).lower():
        raise RateLimited("maclookup")
    if j.get("found") is True:
        return clean(j.get("company")) or None
    return None


ONLINE = {"macvendors": ("api.macvendors.com", _ask_macvendors), "maclookup": ("api.maclookup.app", _ask_maclookup)}


def _online(provider, oui_hex, retry=False):
    """Cached online lookup of one prefix. Returns the vendor or None; raises ProviderError / RateLimited.
    retry=True asks again even if the provider recently said it does not know the prefix."""
    row = db.q("SELECT vendor, ts FROM oui_cache WHERE oui=? AND provider=?", (oui_hex, provider))
    if row and (row[0]["vendor"] or (not retry and time.time() - (row[0]["ts"] or 0) < NEG_TTL)):
        return row[0]["vendor"]
    global _last_online
    host, fn = ONLINE[provider]
    oui = ":".join(oui_hex[i:i + 2] for i in (0, 2, 4))  # only the 3-byte prefix leaves this machine
    with _online_lock:
        if time.monotonic() < _blocked_until.get(provider, 0):
            raise RateLimited(provider)
        wait = _last_online + ONLINE_SPACING - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            v = fn(oui)
        except RateLimited:
            _blocked_until[provider] = time.monotonic() + RATE_BACKOFF
            raise
        finally:
            _last_online = time.monotonic()
    db.x("INSERT OR REPLACE INTO oui_cache(oui, provider, vendor, ts) VALUES(?,?,?,?)", (oui_hex, provider, v, time.time()))
    return v


# ---------- lookup ----------

def norm_mac(mac):
    h = re.sub(r"[:\-.]", "", mac or "").upper()
    return h if re.fullmatch(r"[0-9A-F]{12}", h) else None


class Batch:
    """Collects provider problems during one user action; a provider that failed with a network error is skipped
    for the rest of the batch instead of timing out once per host."""

    def __init__(self):
        self.failed, self.warnings, self.stopped = set(), [], None

    def warn(self, msg):
        if msg not in self.warnings:
            self.warnings.append(msg)


def resolve(oui_hex, batch, retry=False):
    """-> (vendor, source, complete). vendor None = no provider knew it; complete False = at least one enabled
    provider could not be asked, so 'unknown' is not a reliable answer."""
    if int(oui_hex[1], 16) & 0x2:  # locally administered bit: phones randomise their MAC
        return PRIVATE, "randomized", True
    complete = True
    for p in config.MAC_PROVIDERS:
        if p in batch.failed:
            complete = False
            continue
        try:
            if p == "nmap":
                m = _load()
                if not m:
                    raise ProviderError("the nmap vendor list is not installed (/usr/share/nmap/nmap-mac-prefixes)")
                v = m.get(oui_hex)
            elif p == "ieee":
                v = _ieee_map().get(oui_hex)
            else:
                v = _online(p, oui_hex, retry)
        except ProviderError as e:
            label = ONLINE[p][0] if p in ONLINE else p
            batch.warn(f"{label}: {e}")
            batch.failed.add(p)
            complete = False
            continue
        if v:
            return v, p, True
    return None, None, complete


def _store(rid_list, vendor, source):
    for rid in rid_list:
        db.x("UPDATE discoveries SET vendor=?, vendor_source=? WHERE id=?", (vendor, source, rid))


UNKNOWN = "Unknown vendor"  # stored when no provider knew the prefix (vendor_source stays NULL)


@router.post("/api/discoveries/{rid}/vendor")
def lookup_one(rid: int, retry: bool = False):
    rows = db.q("SELECT id, mac FROM discoveries WHERE id=?", (rid,))
    if not rows:
        raise HTTPException(404, "Unknown discovery")
    h = norm_mac(rows[0]["mac"])
    if not h:
        raise HTTPException(400, "No MAC address known for this host")
    if not config.MAC_PROVIDERS and int(h[1], 16) & 0x2 == 0:
        raise HTTPException(400, "No MAC lookup provider is enabled (Settings > MAC address lookup)")
    b = Batch()
    try:
        v, src, complete = resolve(h[:6], b, retry)
    except RateLimited as e:
        raise HTTPException(429, str(e))
    if v is None and not complete:
        raise HTTPException(502, "Could not look up this vendor: " + "; ".join(b.warnings))
    # the vendor is per MAC prefix, so every service on this host gets the same answer
    _store([r["id"] for r in db.q("SELECT id FROM discoveries WHERE mac=?", (rows[0]["mac"],))], v or UNKNOWN, src)
    return {"vendor": v or UNKNOWN, "source": src, "warnings": b.warnings}


@router.post("/api/vendors/lookup")
def lookup_all(retry: bool = False):
    """Looks up MACs without a vendor; retry=True also asks again for the ones no provider knew."""
    rows = db.q("SELECT id, mac FROM discoveries WHERE mac IS NOT NULL AND (vendor IS NULL"
                + (" OR (vendor=? AND vendor_source IS NULL))" if retry else ")"), (UNKNOWN,) if retry else ())
    by_oui = {}
    for r in rows:
        h = norm_mac(r["mac"])
        if h:
            by_oui.setdefault(h[:6], []).append(r["id"])
    if not config.MAC_PROVIDERS and any(int(o[1], 16) & 2 == 0 for o in by_oui):
        raise HTTPException(400, "No MAC lookup provider is enabled (Settings > MAC address lookup)")
    b = Batch()
    done = found = 0
    for oui, ids in by_oui.items():
        try:
            v, src, complete = resolve(oui, b, retry)
        except RateLimited as e:
            b.stopped = str(e)
            break
        if v is None and not complete:
            continue
        _store(ids, v or UNKNOWN, src)
        done += len(ids)
        found += len(ids) if v else 0
    warnings = list(b.warnings)
    if b.stopped:
        warnings.insert(0, b.stopped)
    return {"looked_up": done, "found": found, "not_looked_up": sum(len(v) for v in by_oui.values()) - done, "warnings": warnings}


# ---------- IEEE list download ----------

@router.get("/api/macs/ieee")
def ieee_info():
    return ieee_status()


@router.post("/api/macs/ieee/download")
def ieee_download():
    """Fetch the IEEE OUI registry (the server does this, the browser never contacts IEEE), check it, and only then
    replace DATA_DIR/oui.csv atomically so a failed or malformed download keeps the old copy."""
    try:
        with httpx.Client(timeout=IEEE_TIMEOUT, verify=True, follow_redirects=True,
                          headers={"User-Agent": "npm-discovery"}) as c:
            with c.stream("GET", IEEE_URL) as r:
                if r.status_code != 200:
                    raise HTTPException(502, f"IEEE server answered HTTP {r.status_code}")
                if IEEE_URL.startswith("https://") and r.url.scheme != "https":
                    raise HTTPException(502, "IEEE download was redirected to an unencrypted address; refused")
                cl = r.headers.get("content-length", "")
                if cl.isdigit() and int(cl) > IEEE_MAX_BYTES:
                    raise HTTPException(502, "IEEE file is larger than the 15 MB limit; refused")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > IEEE_MAX_BYTES:
                        raise HTTPException(502, "IEEE file is larger than the 15 MB limit; refused")
    except httpx.TimeoutException:
        raise HTTPException(502, "Downloading the IEEE list timed out")
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Could not download the IEEE list ({type(e).__name__}); is the container online?")
    try:
        entries, skipped = parse_ieee(bytes(buf))
    except ValueError as e:
        raise HTTPException(502, str(e))
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp = ieee_path() + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(buf)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, ieee_path())
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise HTTPException(500, f"Could not save the IEEE list: {e.strerror or e}")
    _ieee.update(mtime=None, size=None, map={})
    return {**ieee_status(), "skipped": skipped}
