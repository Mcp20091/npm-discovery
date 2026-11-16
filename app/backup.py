"""Backup / restore and scan history.

A backup is one JSON file: settings, exclusions, saved host names and (optionally) discoveries with their dismissals,
scan history and each scan's service list. Passwords (NPM password, web page password hash) are only
included when asked for. Restoring REPLACES every section that is present in the file.

main.py fills in `hooks` (normalize_exclusion, reload) so this module never imports main.
"""
import ipaddress
import json
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from . import config, db

router = APIRouter()
hooks = {}
FORMAT = 1
SECRET_KEYS = {"NPM_PASSWORD", "_auth_hash"}
DISC_COLS = ("ip", "port", "scheme", "title", "server", "hostname", "first_seen", "last_seen", "dismissed", "missing", "mac", "vendor")
SCAN_COLS = ("id", "started", "finished", "status", "error", "found", "new_count", "gone_count")
HIT_COLS = ("scan_id", "ip", "port", "scheme", "title", "server", "hostname")
LOG_COLS = ("scan_id", "ts", "level", "msg")


@router.get("/api/history")
async def history():
    return {"items": db.q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (db.HISTORY_KEEP,))}


@router.get("/api/history/{scan_id}/log")
async def history_log(scan_id: int):
    return {"items": db.q("SELECT ts, level, msg FROM scan_log WHERE scan_id=? ORDER BY rowid", (scan_id,))}


@router.get("/api/history/{scan_id}")
async def history_detail(scan_id: int):
    return {"items": db.q("SELECT ip, port, scheme, title, server, hostname FROM scan_hits "
                          "WHERE scan_id=? ORDER BY ip, port", (scan_id,))}


@router.get("/api/backup")
async def backup(results: bool = True, secrets: bool = False):
    out = {
        "app": "npm-discovery", "format": FORMAT, "created": time.time(), "includes_secrets": secrets,
        "settings": {r["key"]: r["value"] for r in db.q("SELECT key, value FROM settings")
                     if secrets or r["key"] not in SECRET_KEYS},
        "exclusions": [r["value"] for r in db.q("SELECT value FROM exclusions ORDER BY id")],
        "host_names": {r["ip"]: r["name"] for r in db.q("SELECT ip, name FROM host_names ORDER BY ip")},
        "notes": [dict(r) for r in db.q("SELECT kind, key, note FROM notes ORDER BY kind, key")],
    }
    if results:
        out["discoveries"] = db.q("SELECT %s FROM discoveries ORDER BY id" % ",".join(DISC_COLS))
        out["scans"] = db.q("SELECT %s FROM scans ORDER BY id" % ",".join(SCAN_COLS))
        out["scan_hits"] = db.q("SELECT %s FROM scan_hits" % ",".join(HIT_COLS))
        out["scan_log"] = db.q("SELECT %s FROM scan_log ORDER BY rowid" % ",".join(LOG_COLS))
    name = time.strftime("npm-discovery-backup-%Y%m%d-%H%M.json")
    return Response(json.dumps(out, indent=1), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


NUM_COLS = {"ts", "port", "first_seen", "last_seen", "dismissed", "missing", "id", "started", "finished", "found",
            "new_count", "gone_count", "scan_id"}


def _check_row(d, cols, what):
    """The UI inserts some of these values into HTML unescaped (ports, counts) or into links (scheme), so a
    restored file must not be able to smuggle text into numeric columns or a javascript: scheme."""
    if not isinstance(d, dict):
        raise HTTPException(400, f"Backup has a malformed {what}")
    for c in cols:
        v = d.get(c)
        if v is None:
            continue
        if c in NUM_COLS:
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        elif c == "scheme":
            ok = v in ("http", "https")
        else:
            ok = isinstance(v, str)
        if not ok:
            raise HTTPException(400, f"Backup has an invalid {c} in a {what}")
    return tuple(d.get(c) for c in cols)


def _validate(data):
    """Check the whole file before touching the database. Returns cleaned sections."""
    if not isinstance(data, dict) or data.get("app") != "npm-discovery":
        raise HTTPException(400, "This is not an NPM Discovery backup file")
    if data.get("format") != FORMAT:
        raise HTTPException(400, f"Unsupported backup format {data.get('format')}")
    clean = {}
    if "settings" in data:
        s = {}
        for k, v in (data["settings"] or {}).items():
            if k == "_auth_hash":
                if not isinstance(v, str) or v.count("$") != 2:
                    raise HTTPException(400, "Backup has an invalid web page password entry")
            elif k not in config.SPEC:
                raise HTTPException(400, f"Backup has an unknown setting: {k}")
            else:
                try:
                    config.parse(k, v)
                except ValueError as e:
                    raise HTTPException(400, str(e))
            s[k] = str(v)
        clean["settings"] = s
    if "exclusions" in data:
        clean["exclusions"] = [hooks["normalize"](v) for v in data["exclusions"] or []]
    if "host_names" in data:
        hn = data["host_names"] or {}
        if not isinstance(hn, dict):
            raise HTTPException(400, "Backup has malformed host names")
        names = []
        for ip, name in hn.items():
            try:
                ip = str(ipaddress.IPv4Address(ip))
            except ValueError:
                raise HTTPException(400, f"Backup has a host name for an invalid IP: {ip}")
            if not isinstance(name, str) or len(name.strip()) > 100:
                raise HTTPException(400, f"Backup has an invalid host name for {ip}")
            if name.strip():
                names.append((ip, name.strip()))
        clean["host_names"] = names
    if "notes" in data:
        raw = data["notes"] or []
        if not isinstance(raw, list):
            raise HTTPException(400, "Backup has malformed notes")
        notes = {}
        for n in raw:
            if not (isinstance(n, dict) and all(isinstance(n.get(k), str) for k in ("kind", "key", "note"))):
                raise HTTPException(400, "Backup has a malformed note")
            if n["kind"] not in ("host", "service"):
                raise HTTPException(400, "Backup has a note of an unknown kind")
            ip, sep, port = n["key"].strip().partition(":")
            try:
                ip = str(ipaddress.IPv4Address(ip))
            except ValueError:
                raise HTTPException(400, f"Backup has a note for an invalid IP: {n['key']}")
            if n["kind"] == "host":
                key = ip if not sep else None
            else:
                key = f"{ip}:{int(port)}" if port.isascii() and port.isdigit() and 1 <= int(port) <= 65535 else None
            if key is None:
                raise HTTPException(400, f"Backup has a note with an invalid key: {n['key']}")
            text = n["note"].strip()
            if len(text) > 2000:
                raise HTTPException(400, f"Backup has a note that is too long: {key}")
            if text:
                notes[(n["kind"], key)] = text
        clean["notes"] = [(k, key, t) for (k, key), t in notes.items()]
    if "discoveries" in data:
        rows = []
        for d in data["discoveries"] or []:
            if not (isinstance(d, dict) and isinstance(d.get("ip"), str) and isinstance(d.get("port"), int)):
                raise HTTPException(400, "Backup has a malformed discovery")
            rows.append(_check_row(d, DISC_COLS, "discovery"))
        clean["discoveries"] = rows
    if "scans" in data:
        clean["scans"] = [_check_row(s, SCAN_COLS, "scan") for s in data["scans"] or []]
        clean["scan_hits"] = [_check_row(h, HIT_COLS, "scan result") for h in data.get("scan_hits") or []]
        logs = []
        for l in data.get("scan_log") or []:  # absent in older backups
            row = _check_row(l, LOG_COLS, "scan log line")
            if row[2] not in ("info", "warn", "error"):
                raise HTTPException(400, "Backup has an invalid level in a scan log line")
            logs.append(row[:3] + ((row[3] or "")[:500],))
        clean["scan_log"] = logs
    return clean


@router.post("/api/restore")
async def restore(request: Request):
    try:
        data = json.loads(await request.body())
    except ValueError:
        raise HTTPException(400, "That file is not valid JSON")
    clean = _validate(data)
    with db._lock:
        c = db._conn
        try:
            if "settings" in clean:
                # keep saved passwords unless the file carries them
                keep = [k for k in SECRET_KEYS if k not in clean["settings"]]
                c.execute("DELETE FROM settings WHERE key NOT IN (%s)" % ",".join("?" * len(keep)) if keep
                          else "DELETE FROM settings", keep)
                c.executemany("INSERT OR REPLACE INTO settings VALUES(?,?)", list(clean["settings"].items()))
            if "exclusions" in clean:
                c.execute("DELETE FROM exclusions")
                c.executemany("INSERT OR IGNORE INTO exclusions(value, added) VALUES(?,?)",
                              [(v, time.time()) for v in clean["exclusions"]])
            if "host_names" in clean:
                c.execute("DELETE FROM host_names")
                c.executemany("INSERT OR REPLACE INTO host_names VALUES(?,?)", clean["host_names"])
            if "notes" in clean:
                c.execute("DELETE FROM notes")
                c.executemany("INSERT OR REPLACE INTO notes VALUES(?,?,?)", clean["notes"])
            if "discoveries" in clean:
                c.execute("DELETE FROM discoveries")
                c.executemany("INSERT OR REPLACE INTO discoveries(%s) VALUES(%s)" % (
                    ",".join(DISC_COLS), ",".join("?" * len(DISC_COLS))), clean["discoveries"])
            if "scans" in clean:
                c.execute("DELETE FROM scans")
                c.execute("DELETE FROM scan_hits")
                c.execute("DELETE FROM scan_log")  # scan ids come from the file; its own log lines replace these
                c.executemany("INSERT INTO scans(%s) VALUES(%s)" % (
                    ",".join(SCAN_COLS), ",".join("?" * len(SCAN_COLS))), clean["scans"])
                c.executemany("INSERT INTO scan_hits(%s) VALUES(%s)" % (
                    ",".join(HIT_COLS), ",".join("?" * len(HIT_COLS))), clean["scan_hits"])
                c.executemany("INSERT INTO scan_log(%s) VALUES(%s)" % (
                    ",".join(LOG_COLS), ",".join("?" * len(LOG_COLS))), clean["scan_log"])
            c.commit()
        except Exception:
            c.rollback()
            raise
    hooks["reload"]()
    return {"ok": True, "restored": sorted(k for k in clean if k not in ("scan_hits", "scan_log"))}
