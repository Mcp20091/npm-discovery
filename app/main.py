import asyncio
import logging
import os
import re
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import config, db, scanner
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


async def scan_and_refresh():
    await scanner.run_scan()
    await refresh_hosts(force=True)


async def scheduler():
    if config.SCAN_ON_START:
        await asyncio.sleep(5)
        await scan_and_refresh()
    if config.SCAN_INTERVAL_HOURS <= 0:
        return
    while True:
        await asyncio.sleep(config.SCAN_INTERVAL_HOURS * 3600)
        await scan_and_refresh()


@asynccontextmanager
async def lifespan(app):
    global npm
    for p in config.problems():
        log.error(p)
    db.init()
    npm = NpmClient()
    task = asyncio.create_task(scheduler())
    yield
    task.cancel()


app = FastAPI(title="NPM Discovery", lifespan=lifespan)


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
            out.append(", ".join(h.get("domain_names", [])))
    return out


@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/status")
async def status():
    last = db.q("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    return {"running": scanner.state["running"], "last": last[0] if last else None,
            "base_domain": config.BASE_DOMAIN, "config_problems": config.problems(),
            "interval_hours": config.SCAN_INTERVAL_HOURS}


@app.post("/api/scan")
async def scan_now():
    if scanner.state["running"]:
        raise HTTPException(409, "A scan is already running")
    asyncio.create_task(scan_and_refresh())
    await asyncio.sleep(0.1)
    return {"started": True}


@app.get("/api/discoveries")
async def discoveries():
    await refresh_hosts()
    items = []
    for r in db.q("SELECT * FROM discoveries ORDER BY ip, port"):
        proxies = match_proxy(r, _cache["hosts"])
        r["state"] = "dismissed" if r["dismissed"] else ("proxied" if proxies else "new")
        r["proxy_domains"] = proxies
        r["suggestion"] = suggest(r)
        items.append(r)
    return {"items": items, "npm_error": _cache["error"]}


@app.get("/api/certificates")
async def certificates():
    try:
        certs = await npm.certificates()
    except NpmError as e:
        return JSONResponse({"error": str(e), "items": []}, status_code=502)
    return {"items": [{"id": c["id"], "name": c.get("nice_name") or ", ".join(c.get("domain_names", [])),
                       "domains": c.get("domain_names", [])} for c in certs]}


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
    cert = req.certificate_id or 0
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


if __name__ == "__main__":
    uvicorn.run(app, host=config.WEB_HOST, port=config.WEB_PORT, log_level="info")
