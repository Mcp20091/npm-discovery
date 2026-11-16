"""MAC addresses and vendor lookup.

An unprivileged TCP connect scan cannot see MAC addresses, so they are read from the kernel's ARP table
after a scan. That only covers hosts on the same network segment as this container. Vendor names come from
the offline database that ships with nmap (nmap-mac-prefixes); nothing is sent to the internet.
"""
import os

from fastapi import APIRouter, HTTPException

from . import db

router = APIRouter()
OUI_PATHS = ["/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes"]
_oui = None


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
                        _oui[prefix.upper()] = name.strip()
            break
        except OSError:
            continue
    return _oui


def vendor_of(mac):
    """Vendor name, 'Private (randomized) address' for locally administered MACs, or None if unknown.
    Raises LookupError if the vendor database is not installed."""
    db_ = _load()
    if not db_:
        raise LookupError("Vendor database not found (it comes with nmap: /usr/share/nmap/nmap-mac-prefixes)")
    hexs = mac.replace(":", "").replace("-", "").upper()
    if len(hexs) < 6:
        return None
    if int(hexs[1], 16) & 0x2:  # locally administered bit: phones randomise their MAC
        return "Private (randomized) address"
    return db_.get(hexs[:6])


def _lookup_row(row):
    try:
        v = vendor_of(row["mac"]) or "Unknown vendor"
    except LookupError as e:
        raise HTTPException(503, str(e))
    db.x("UPDATE discoveries SET vendor=? WHERE id=?", (v, row["id"]))
    return v


@router.post("/api/discoveries/{rid}/vendor")
async def lookup_one(rid: int):
    rows = db.q("SELECT id, mac FROM discoveries WHERE id=?", (rid,))
    if not rows:
        raise HTTPException(404, "Unknown discovery")
    if not rows[0]["mac"]:
        raise HTTPException(400, "No MAC address known for this host")
    return {"vendor": _lookup_row(rows[0])}


@router.post("/api/vendors/lookup")
async def lookup_all():
    n = 0
    for r in db.q("SELECT id, mac FROM discoveries WHERE mac IS NOT NULL AND vendor IS NULL"):
        _lookup_row(r)
        n += 1
    return {"looked_up": n}
