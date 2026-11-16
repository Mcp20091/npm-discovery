import asyncio
import re
import socket
import time
import xml.etree.ElementTree as ET
from html import unescape
from urllib.parse import urljoin, urlparse

import httpx

from . import config, db, macs

TLS_FIRST = {443, 8443, 8444, 9443, 4443, 5001, 8006, 8007}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
state = {"running": False, "stop": False, "proc": None, "tasks": []}


class ScanStopped(Exception):
    pass


def stop_scan():
    """Kill nmap and cancel probes of the running scan. Returns False if none is running."""
    if not state["running"]:
        return False
    state["stop"] = True
    proc = state["proc"]
    if proc and proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    for t in state["tasks"]:
        t.cancel()
    return True


def nmap_args():
    timing = ["-T2", "--max-rate", "20", "--max-parallelism", "5", "--scan-delay", "50ms"] if config.SCAN_GENTLE else ["-T4"]
    args = ["nmap", "-sT", "-Pn", "-n", "--open", *timing, "--max-retries", "1", "-oX", "-"]
    args += ["-p-"] if config.SCAN_ALL_PORTS else ["-p", ",".join(map(str, config.SCAN_PORTS))]
    excl = config.SCAN_EXCLUDE + [r["value"] for r in db.q("SELECT value FROM exclusions")]
    if excl:
        args += ["--exclude", ",".join(excl)]
    args += config.SCAN_SUBNETS
    return args


async def run_nmap():
    args = nmap_args()
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed")
    state["proc"] = proc
    if state["stop"]:  # stop pressed while nmap was starting
        proc.kill()
    out, err = await proc.communicate()
    state["proc"] = None
    if state["stop"]:
        raise ScanStopped()
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {err.decode(errors='replace').strip()[:300]}")
    found = []
    for host in ET.fromstring(out).iter("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        if not addr:
            continue
        for p in host.iter("port"):
            st = p.find("state")
            if st is not None and st.get("state") == "open":
                found.append((addr, int(p.get("portid"))))
    return found


async def read_body(client, url):
    async with client.stream("GET", url) as r:
        buf = b""
        async for chunk in r.aiter_bytes():
            buf += chunk
            if len(buf) > 65536:
                break
        return r, buf


async def probe(client, ip, port):
    """Return scheme/title/server if the port answers HTTP(S), else None."""
    order = ["https", "http"] if port in TLS_FIRST else ["http", "https"]
    for scheme in order:
        url = f"{scheme}://{ip}:{port}/"
        try:
            for _ in range(4):  # follow redirects only when they stay on this host
                r, body = await read_body(client, url)
                loc = r.headers.get("location")
                if r.status_code in (301, 302, 303, 307, 308) and loc:
                    nxt = urljoin(url, loc)
                    if urlparse(nxt).hostname == ip:
                        url = nxt
                        continue
                break
        except Exception:
            continue
        m = TITLE_RE.search(body.decode("utf-8", errors="replace"))
        title = re.sub(r"\s+", " ", unescape(m.group(1))).strip()[:200] if m else ""
        return {"scheme": scheme, "title": title, "server": r.headers.get("server", "")[:200]}
    return None


async def rdns(ip):
    try:
        loop = asyncio.get_running_loop()
        return (await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 3))[0]
    except Exception:
        return ""


async def run_scan():
    """Returns False if a scan was already running."""
    if state["running"]:
        return False
    state.update(running=True, stop=False, proc=None, tasks=[])
    started = time.time()
    scan_id = db.x("INSERT INTO scans(started,status) VALUES(?, 'running')", (started,)).lastrowid
    try:
        if not config.SCAN_SUBNETS:
            raise RuntimeError("SCAN_SUBNETS is not set")
        open_ports = await run_nmap()
        sem = asyncio.Semaphore(3 if config.SCAN_GENTLE else 30)
        names = {}
        async with httpx.AsyncClient(verify=False, timeout=config.PROBE_TIMEOUT,
                                     follow_redirects=False) as client:
            async def one(ip, port):
                async with sem:
                    info = await probe(client, ip, port)
                    if not info:
                        return None
                    if ip not in names:
                        names[ip] = asyncio.ensure_future(rdns(ip))
                    info.update(ip=ip, port=port, hostname=await names[ip])
                    return info
            state["tasks"] = [asyncio.ensure_future(one(i, p)) for i, p in open_ports]
            if state["stop"]:
                stop_scan()
            done = await asyncio.gather(*state["tasks"], return_exceptions=True)
            if state["stop"]:
                raise ScanStopped()
            for r in done:
                if isinstance(r, BaseException):
                    raise r
            results = [r for r in done if r]
        arp = macs.read_arp()  # only hosts on this segment show up
        for r in results:
            r["mac"] = arp.get(r["ip"])
        new, gone = db.save_scan_results(results, started, scan_id)
        db.x("UPDATE scans SET status='finished', finished=?, found=?, new_count=?, gone_count=? WHERE id=?",
             (time.time(), len(results), new, gone, scan_id))
    except ScanStopped:
        db.x("UPDATE scans SET status='stopped', finished=? WHERE id=?", (time.time(), scan_id))
    except Exception as e:
        db.x("UPDATE scans SET status='failed', finished=?, error=? WHERE id=?",
             (time.time(), str(e), scan_id))
    finally:
        state.update(running=False, stop=False, proc=None, tasks=[])
    return True
