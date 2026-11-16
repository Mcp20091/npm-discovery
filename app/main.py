import asyncio
import ipaddress
import logging
import os
import re
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import auth, backup, config, db, macs, scanner, targets
from .npm import NpmClient, NpmError

log = logging.getLogger("npm-discovery")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

STATIC = os.path.join(os.path.dirname(__file__), "static")
npm = None
_cache = {"hosts": None, "error": None, "at": 0.0}
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


async def refresh_hosts(force=False):
    if not force and time.time() - _cache["at"] < 20:
        return
    try:
        _cache["hosts"] = await npm.proxy_hosts()
        _cache["error"] = None
    except NpmError as e:
        _cache["hosts"] = None
        _cache["error"] = str(e)
    _cache["at"] = time.time()


async def scan_and_refresh(only=None):
    await scanner.run_scan(only)
    await refresh_hosts(force=True)


async def scheduler():
    """Re-reads settings every 30s so interval changes made in the UI apply without a restart."""
    if config.SCAN_ON_START:
        await asyncio.sleep(5)
        await scan_and_refresh()
    while True:
        await asyncio.sleep(30)
        hours = config.SCAN_INTERVAL_HOURS
        if hours <= 0 or scanner.state["running"]:
            continue
        last = db.q("SELECT MAX(started) AS m FROM scans")[0]["m"] or 0
        if time.time() - last >= hours * 3600:
            await scan_and_refresh()


def load_settings():
    db.init()
    config.apply({r["key"]: r["value"] for r in db.q("SELECT key, value FROM settings")})


@asynccontextmanager
async def lifespan(app):
    global npm
    load_settings()
    for p in config.problems():
        log.error(p)
    npm = NpmClient()
    task = asyncio.create_task(scheduler())
    yield
    task.cancel()


app = FastAPI(title="NPM Discovery", lifespan=lifespan)
app.middleware("http")(auth.middleware)
app.include_router(auth.router)
app.include_router(backup.router)
app.include_router(macs.router)


def suggest(row):
    title = (row["title"] or "").strip()
    if title:
        first = re.split(r"\s[-|:–—]\s|[|:]", title)[0]
        slug = re.sub(r"[^a-z0-9]+", "-", first.lower()).strip("-")[:30].strip("-")
        if slug:
            return slug
    host = (row["hostname"] or "").split(".")[0].lower()
    host = re.sub(r"[^a-z0-9-]+", "-", host).strip("-")
    if host and not re.fullmatch(r"[\d-]+", host):
        return host
    return f"host-{row['ip'].split('.')[-1]}-{row['port']}"


def match_proxy(row, hosts):
    names = {row["ip"]}
    if row["hostname"]:
        names.add(row["hostname"].lower())
    out = []
    for h in hosts or []:
        if int(h.get("forward_port", 0)) == row["port"] and str(h.get("forward_host", "")).lower() in names:
            out.append(h)
    return out


def proxy_links(h):
    """Clickable addresses of an NPM proxy host (https when it has a certificate)."""
    scheme = "https" if h.get("certificate_id") else "http"
    return [{"domain": d, "url": f"{scheme}://{d}/"} for d in h.get("domain_names", []) if "*" not in d]


def taken_domains():
    return sorted({d.lower() for h in _cache["hosts"] or [] for d in h.get("domain_names", [])})


@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/status")
async def status():
    last = db.q("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    return {"running": scanner.state["running"], "last": last[0] if last else None,
            "base_domain": config.BASE_DOMAIN, "config_problems": config.problems(),
            "interval_hours": config.SCAN_INTERVAL_HOURS,
            "subnets": config.SCAN_SUBNETS,
            "exclusion_count": len(config.SCAN_EXCLUDE) + db.q("SELECT COUNT(*) AS n FROM exclusions")[0]["n"],
            "auth": auth.enabled(),
            "progress": {k: scanner.state[k] for k in ("phase", "done", "total", "started")}
            if scanner.state["running"] else None}


class ScanReq(BaseModel):
    targets: str | None = None  # empty = the saved subnets; otherwise IPs / ranges / subnets typed by the user


@app.post("/api/scan")
async def scan_now(req: ScanReq | None = None):
    if scanner.state["running"]:
        raise HTTPException(409, "A scan is already running")
    only = None
    if req and req.targets and req.targets.strip():
        try:
            only = targets.parse_list(req.targets)
        except ValueError as e:
            raise HTTPException(400, str(e))
    asyncio.create_task(scan_and_refresh(only))
    await asyncio.sleep(0.1)
    return {"started": True}


@app.post("/api/scan/stop")
async def scan_stop():
    if not scanner.stop_scan():
        raise HTTPException(409, "No scan is running")
    return {"stopping": True}


@app.get("/api/discoveries")
async def discoveries():
    await refresh_hosts()
    items = []
    excl = all_exclusions()
    names = {n["ip"]: n["name"] for n in db.q("SELECT ip, name FROM host_names")}
    notes = {(n["kind"], n["key"]): n["note"] for n in db.q("SELECT kind, key, note FROM notes")}
    for r in db.q("SELECT * FROM discoveries ORDER BY ip, port"):
        if any(excl_covers(s, r["ip"]) for s in excl):
            continue
        proxies = match_proxy(r, _cache["hosts"])
        r["state"] = "dismissed" if r["dismissed"] else ("proxied" if proxies else "new")
        r["proxy_domains"] = [", ".join(h.get("domain_names", [])) for h in proxies]
        r["proxy_links"] = [link for h in proxies for link in proxy_links(h)]
        r["suggestion"] = suggest(r)
        r["host_name"] = names.get(r["ip"], "")
        r["note"] = notes.get(("service", f"{r['ip']}:{r['port']}"), "")
        r["host_note"] = notes.get(("host", r["ip"]), "")
        items.append(r)
    last = db.q("SELECT started FROM scans WHERE status='finished' ORDER BY id DESC LIMIT 1")
    return {"items": items, "npm_error": _cache["error"], "taken": taken_domains(),
            "last_scan_started": last[0]["started"] if last else None}


NOTE_MAX = 2000


class NoteReq(BaseModel):
    kind: str
    key: str
    note: str = ""


def check_note_key(kind, key):
    """Returns the canonical key ('ip' for hosts, 'ip:port' for services) or raises 400."""
    if kind not in ("host", "service"):
        raise HTTPException(400, "Unknown note kind")
    ip, sep, port = key.strip().partition(":")
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ValueError:
        raise HTTPException(400, "Not a valid IPv4 address")
    if kind == "host":
        if sep:
            raise HTTPException(400, "A host note is keyed by IP only")
        return ip
    if not (port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
        raise HTTPException(400, "Not a valid port")
    return f"{ip}:{int(port)}"


@app.put("/api/notes")
async def set_note(req: NoteReq):
    key = check_note_key(req.kind, req.key)
    note = req.note.strip()
    if len(note) > NOTE_MAX:
        raise HTTPException(400, f"Note is too long (max {NOTE_MAX} characters)")
    if note:
        db.x("INSERT INTO notes(kind, key, note) VALUES(?,?,?) ON CONFLICT(kind, key) DO UPDATE SET note=excluded.note",
             (req.kind, key, note))
    else:
        db.x("DELETE FROM notes WHERE kind=? AND key=?", (req.kind, key))
    return {"ok": True, "kind": req.kind, "key": key, "note": note}


class HostNameReq(BaseModel):
    ip: str
    name: str = ""


@app.put("/api/hosts/name")
async def set_host_name(req: HostNameReq):
    try:
        ip = str(ipaddress.IPv4Address(req.ip.strip()))
    except ValueError:
        raise HTTPException(400, "Not a valid IPv4 address")
    name = req.name.strip()
    if len(name) > 100:
        raise HTTPException(400, "Name is too long (max 100 characters)")
    if name:
        db.x("INSERT INTO host_names(ip, name) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name", (ip, name))
    else:
        db.x("DELETE FROM host_names WHERE ip=?", (ip,))
    return {"ok": True, "ip": ip, "name": name}


@app.get("/api/certificates")
async def certificates():
    try:
        certs = await npm.certificates()
    except NpmError as e:
        return JSONResponse({"error": str(e), "items": []}, status_code=502)
    def label(c):  # short label for the dropdowns; the full domain list is kept in "domains" for tooltips
        doms = c.get("domain_names", [])
        if c.get("nice_name"):
            return c["nice_name"]
        return (doms[0] if doms else f"Certificate {c['id']}") + (f" (+{len(doms) - 1} more)" if len(doms) > 1 else "")
    return {"items": [{"id": c["id"], "name": label(c), "domains": c.get("domain_names", [])} for c in certs]}


def _row(rid):
    rows = db.q("SELECT * FROM discoveries WHERE id=?", (rid,))
    if not rows:
        raise HTTPException(404, "Unknown discovery")
    return rows[0]


@app.post("/api/discoveries/{rid}/dismiss")
async def dismiss(rid: int):
    _row(rid)
    db.x("UPDATE discoveries SET dismissed=1 WHERE id=?", (rid,))
    return {"ok": True}


@app.post("/api/discoveries/{rid}/restore")
async def restore(rid: int):
    _row(rid)
    db.x("UPDATE discoveries SET dismissed=0 WHERE id=?", (rid,))
    return {"ok": True}


@app.delete("/api/discoveries/{rid}")
async def forget(rid: int):
    """Drop a discovery (meant for GONE ones). If a later scan finds it again it comes back as new."""
    _row(rid)
    db.x("DELETE FROM discoveries WHERE id=?", (rid,))
    return {"ok": True}


class SettingsReq(BaseModel):
    values: dict


def settings_view():
    out = {}
    for name, (kind, _) in config.SPEC.items():
        out[name] = {"value": "" if kind == "secret" else config.raw(name), "source": config.source(name)}
    out["NPM_PASSWORD"]["set"] = bool(config.NPM_PASSWORD)
    return out


@app.get("/api/settings")
async def get_settings():
    return {"settings": settings_view(), "restart_keys": sorted(config.RESTART_KEYS)}


@app.put("/api/settings")
async def put_settings(req: SettingsReq):
    global npm
    clean = {}
    for name, val in req.values.items():
        if name not in config.SPEC:
            raise HTTPException(400, f"Unknown setting {name}")
        if config.SPEC[name][0] == "secret" and str(val) == "":
            continue  # blank password = keep the saved one
        if isinstance(val, bool):
            val = "true" if val else "false"
        try:
            config.parse(name, val)
        except ValueError as e:
            raise HTTPException(400, str(e))
        clean[name] = str(val).strip()
    before = {k: config.raw(k) for k in config.NPM_KEYS}
    for k, v in clean.items():
        db.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
    load_settings()
    restart = [k for k in clean if k in config.RESTART_KEYS and clean[k] != os.environ.get(k, config.SPEC[k][1])]
    if any(config.raw(k) != before[k] for k in config.NPM_KEYS):
        npm = NpmClient()
        _cache.update(hosts=None, error=None, at=0.0)
    return {"ok": True, "restart_needed": bool(restart)}


@app.delete("/api/settings")
async def reset_settings():
    global npm
    db.x("DELETE FROM settings WHERE key NOT LIKE '!_auth!_%' ESCAPE '!'")  # keep the web password
    load_settings()
    npm = NpmClient()
    _cache.update(hosts=None, error=None, at=0.0)
    return {"ok": True}


@app.post("/api/npm/test")
async def test_npm():
    try:
        hosts = await npm.proxy_hosts()
    except NpmError as e:
        raise HTTPException(502, str(e))
    await refresh_hosts(force=True)
    return {"ok": True, "proxy_hosts": len(hosts)}


@app.post("/api/restart")
async def restart():
    # systemd (Restart=on-failure) brings the service straight back up
    asyncio.get_running_loop().call_later(0.5, os._exit, 1)
    return {"ok": True}


def normalize_exclusion(v):
    try:
        return targets.normalize(v)
    except ValueError as e:
        raise HTTPException(400, str(e))


excl_covers = targets.covers


def all_exclusions():
    return config.SCAN_EXCLUDE + [r["value"] for r in db.q("SELECT value FROM exclusions")]


class ExclReq(BaseModel):
    value: str


@app.get("/api/exclusions")
async def exclusions():
    return {"items": db.q("SELECT id, value, added FROM exclusions ORDER BY id"),
            "from_config": config.SCAN_EXCLUDE}


@app.post("/api/exclusions")
async def add_exclusion(req: ExclReq):
    v = normalize_exclusion(req.value)
    db.x("INSERT OR IGNORE INTO exclusions(value, added) VALUES(?, ?)", (v, time.time()))
    for r in db.q("SELECT id, ip FROM discoveries"):
        if excl_covers(v, r["ip"]):
            db.x("DELETE FROM discoveries WHERE id=?", (r["id"],))
    return {"ok": True, "value": v}


@app.delete("/api/exclusions/{eid}")
async def remove_exclusion(eid: int):
    db.x("DELETE FROM exclusions WHERE id=?", (eid,))
    return {"ok": True}


class AddReq(BaseModel):
    subdomain: str
    block_exploits: bool = True
    websockets: bool = True
    certificate_id: int | None = None


@app.post("/api/discoveries/{rid}/add")
async def add(rid: int, req: AddReq):
    row = _row(rid)
    sub = req.subdomain.strip().lower().strip(".")
    if not sub or not all(LABEL_RE.match(p) for p in sub.split(".")):
        raise HTTPException(400, "Subdomain may only contain letters, digits and hyphens (dots allowed between labels)")
    domain = f"{sub}.{config.BASE_DOMAIN}"
    await refresh_hosts()
    if domain.lower() in taken_domains():
        raise HTTPException(409, f"{domain} is already used by a proxy host in NPM - pick another subdomain")
    cert = req.certificate_id or 0
    if cert:  # a saved default may point at a certificate that was deleted in NPM since
        try:
            known = {c.get("id") for c in await npm.certificates()}
        except NpmError as e:
            raise HTTPException(502, str(e))
        if cert not in known:
            raise HTTPException(400, f"SSL certificate {cert} no longer exists in NPM - pick another one "
                                     "(and update the default in Settings)")
    payload = {
        "domain_names": [domain],
        "forward_scheme": row["scheme"],
        "forward_host": row["ip"],
        "forward_port": row["port"],
        "block_exploits": req.block_exploits,
        "allow_websocket_upgrade": req.websockets,
        "caching_enabled": False,
        "certificate_id": cert,
        "ssl_forced": bool(cert),
        "http2_support": bool(cert),
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "enabled": True,
        "advanced_config": "",
        "meta": {},
        "locations": [],
    }
    try:
        created = await npm.create_proxy_host(payload)
    except NpmError as e:
        raise HTTPException(502, str(e))
    await refresh_hosts(force=True)
    return {"ok": True, "domain": domain, "id": created.get("id")}


def reload_after_restore():
    global npm
    load_settings()
    npm = NpmClient()
    _cache.update(hosts=None, error=None, at=0.0)


backup.hooks.update(normalize=normalize_exclusion, reload=reload_after_restore)

if __name__ == "__main__":
    load_settings()  # so WEB_HOST / WEB_PORT saved in the UI are honoured
    uvicorn.run(app, host=config.WEB_HOST, port=config.WEB_PORT, log_level="info")
