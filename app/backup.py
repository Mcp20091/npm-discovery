"""Backup / restore and scan history.

A backup is one JSON file: settings, exclusions and (optionally) discoveries with their dismissals,
scan history and each scan's service list. Passwords (NPM password, web page password hash) are only
included when asked for. Restoring REPLACES every section that is present in the file.

main.py fills in `hooks` (normalize_exclusion, reload) so this module never imports main.
"""
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


@router.get("/api/history")
async def history():
    return {"items": db.q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (db.HISTORY_KEEP,))}


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
    }
    if results:
        out["discoveries"] = db.q("SELECT %s FROM discoveries ORDER BY id" % ",".join(DISC_COLS))
        out["scans"] = db.q("SELECT %s FROM scans ORDER BY id" % ",".join(SCAN_COLS))
        out["scan_hits"] = db.q("SELECT %s FROM scan_hits" % ",".join(HIT_COLS))
    name = time.strftime("npm-discovery-backup-%Y%m%d-%H%M.json")
    return Response(json.dumps(out, indent=1), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


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
    if "discoveries" in data:
        rows = []
        for d in data["discoveries"] or []:
            if not (isinstance(d.get("ip"), str) and isinstance(d.get("port"), int)):
                raise HTTPException(400, "Backup has a malformed discovery")
            rows.append(tuple(d.get(c) for c in DISC_COLS))
        clean["discoveries"] = rows
    if "scans" in data:
        clean["scans"] = [tuple(s.get(c) for c in SCAN_COLS) for s in data["scans"] or []]
        clean["scan_hits"] = [tuple(h.get(c) for c in HIT_COLS) for h in data.get("scan_hits") or []]
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
            if "discoveries" in clean:
                c.execute("DELETE FROM discoveries")
                c.executemany("INSERT OR REPLACE INTO discoveries(%s) VALUES(%s)" % (
                    ",".join(DISC_COLS), ",".join("?" * len(DISC_COLS))), clean["discoveries"])
            if "scans" in clean:
                c.execute("DELETE FROM scans")
                c.execute("DELETE FROM scan_hits")
                c.executemany("INSERT INTO scans(%s) VALUES(%s)" % (
                    ",".join(SCAN_COLS), ",".join("?" * len(SCAN_COLS))), clean["scans"])
                c.executemany("INSERT INTO scan_hits(%s) VALUES(%s)" % (
                    ",".join(HIT_COLS), ",".join("?" * len(HIT_COLS))), clean["scan_hits"])
            c.commit()
        except Exception:
            c.rollback()
            raise
    hooks["reload"]()
    return {"ok": True, "restored": sorted(k for k in clean if k != "scan_hits")}
