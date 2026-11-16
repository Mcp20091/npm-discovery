import asyncio
import logging
import re
import socket
import time
import xml.etree.ElementTree as ET
from html import unescape
from urllib.parse import urljoin, urlparse

import httpx

from . import config, db, macs

log = logging.getLogger("npm-discovery")
TLS_FIRST = {443, 8443, 8444, 9443, 4443, 5001, 8006, 8007}
HOSTNAME_RE = re.compile(r"[A-Za-z0-9_]([A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
LOG_MAX = 400  # lines stored per scan
state = {"running": False, "stop": False, "proc": None, "tasks": [], "targets": None,
         "phase": "", "done": 0, "total": 0, "started": 0.0}  # phase/done/total feed the progress shown in the UI


def make_logger(scan_id):
    """Writes each line to the service log and to the scan's own log (shown in History)."""
    n = [0]

    def L(level, msg):
        {"warn": log.warning, "error": log.error}.get(level, log.info)("[scan %s] %s", scan_id, msg)
        if n[0] >= LOG_MAX:
            return
        n[0] += 1
        if n[0] == LOG_MAX:
            msg = "(log limit reached; further lines for this scan are not stored)"
        db.x("INSERT INTO scan_log(scan_id, ts, level, msg) VALUES(?,?,?,?)", (scan_id, time.time(), level, msg[:500]))
    return L


def why(e):
    """Short plain-English reason a web probe failed."""
    s = str(e).lower()
    if isinstance(e, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        return "timed out"
    if "refused" in s:
        return "connection refused"
    if "reset" in s or "forcibly closed" in s:
        return "connection reset"
    if "ssl" in s or "tls" in s or "certificate" in s or "handshake" in s:
        return "TLS/SSL error"
    if isinstance(e, (httpx.RemoteProtocolError, httpx.ReadError)):
        return "closed without a valid web reply"
    if isinstance(e, httpx.ConnectError):
        return "could not connect"
    return type(e).__name__


# reasons that suggest something dropped or reset the connection on purpose
BLOCKISH = ("timed out", "connection reset", "connection refused")


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
    args += state.get("targets") or config.SCAN_SUBNETS  # a hand-typed scan overrides the saved subnets
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
    root = ET.fromstring(out)
    fin, hosts = root.find("runstats/finished"), root.find("runstats/hosts")
    state["nmap_info"] = {
        "args": args,
        "elapsed": fin.get("elapsed") if fin is not None else "?",
        "hosts": f"{hosts.get('total')} addresses scanned" if hosts is not None else "",
        "warnings": [ln.strip() for ln in err.decode(errors="replace").splitlines() if ln.strip()],
    }
    found = []
    for host in root.iter("host"):
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


async def probe(client, ip, port, fails=None):
    """Return scheme/title/server if the port answers HTTP(S), else None (reason goes into fails)."""
    reasons = []
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
        except Exception as e:
            reasons.append(f"{scheme}: {why(e)}")
            continue
        m = TITLE_RE.search(body.decode("utf-8", errors="replace"))
        title = re.sub(r"\s+", " ", unescape(m.group(1))).strip()[:200] if m else ""
        return {"scheme": scheme, "title": title, "server": r.headers.get("server", "")[:200]}
    if fails is not None:
        fails[(ip, port)] = "; ".join(reasons)
    return None


async def rdns(ip):
    try:
        loop = asyncio.get_running_loop()
        name = (await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 3))[0]
    except Exception:
        return ""
    # PTR records are untrusted: the UI builds an open-in-new-tab link from this, so only plain hostnames pass
    return name if HOSTNAME_RE.fullmatch(name) else ""


def _ipkey(ip):
    return tuple(int(o) for o in ip.split("."))


async def run_scan(only=None):
    """Returns False if a scan was already running. `only` = hand-typed targets instead of the saved subnets."""
    if state["running"]:
        return False
    started = time.time()
    state.update(running=True, stop=False, proc=None, tasks=[], targets=only,
                 phase="port scan", done=0, total=0, started=started)
    state.pop("nmap_info", None)
    scan_id = db.x("INSERT INTO scans(started,status) VALUES(?, 'running')", (started,)).lastrowid
    L = make_logger(scan_id)
    try:
        if not (only or config.SCAN_SUBNETS):
            raise RuntimeError("SCAN_SUBNETS is not set")
        excl = config.SCAN_EXCLUDE + [r["value"] for r in db.q("SELECT value FROM exclusions")]
        L("info", "%s: %s. %d excluded entries (excluded addresses are skipped here too). %s. %s mode." % (
            "Targeted scan started" if only else "Scan started. Subnets", ", ".join(only or config.SCAN_SUBNETS), len(excl),
            "All 65535 ports" if config.SCAN_ALL_PORTS else f"{len(config.SCAN_PORTS)} ports",
            "Gentle" if config.SCAN_GENTLE else "Normal"))
        open_ports = await run_nmap()
        nm = state.pop("nmap_info", None)
        if nm:
            L("info", "nmap command: " + " ".join(nm["args"]))
            L("info", f"nmap finished in {nm['elapsed']}s ({nm['hosts']})")
            for w in nm["warnings"][:10]:
                L("warn", "nmap said: " + w)
        by_host = {}
        for ip, port in open_ports:
            by_host.setdefault(ip, []).append(port)
        L("info", f"nmap found {len(open_ports)} open ports on {len(by_host)} hosts. Addresses that silently drop "
                  "connections look the same as empty addresses, so they cannot be listed here.")
        # Linux drops ARP entries quickly once a /24 sweep fills its table, so one read at the very end misses
        # hosts. Read it after nmap and again right after each probe (the connection just made refreshes the
        # entry), and merge.
        arp = macs.read_arp()
        fails = {}
        state.update(phase="web probe", done=0, total=len(open_ports))
        sem = asyncio.Semaphore(3 if config.SCAN_GENTLE else 30)
        names = {}
        async with httpx.AsyncClient(verify=False, timeout=config.PROBE_TIMEOUT,
                                     follow_redirects=False) as client:
            async def one(ip, port):
                async with sem:
                    try:
                        info = await probe(client, ip, port, fails)
                    finally:
                        state["done"] += 1
                    if not info:
                        return None
                    arp.update(macs.read_arp())
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
        ok = {(r["ip"], r["port"]) for r in results}
        for ip in sorted(by_host, key=_ipkey):
            bad = [p for p in sorted(by_host[ip]) if (ip, p) not in ok]
            for p in bad:
                reason = fails.get((ip, p), "no reply")
                L("warn" if any(b in reason for b in BLOCKISH) else "info",
                  f"{ip}:{p} is open but no web page answered ({reason})")
            if bad and len(bad) == len(by_host[ip]) and any(
                    any(b in fails.get((ip, p), "") for b in BLOCKISH) for p in bad):
                L("warn", f"{ip}: every open port failed the web probe. A firewall or security program on that "
                          "device, or between it and this container, may be blocking or resetting the scan.")
        hosts_ok = {r["ip"] for r in results}
        L("info", f"{len(results)} web services answered on {len(hosts_ok)} hosts; "
                  f"{len(open_ports) - len(results)} open ports did not answer as web pages.")
        arp.update(macs.read_arp())  # only hosts on the same network segment as this container show up
        for r in results:
            r["mac"] = arp.get(r["ip"])
        L("info", f"MAC address known for {len({r['ip'] for r in results if r['mac']})} of {len(hosts_ok)} hosts "
                  f"(ARP table had {len(arp)} entries; hosts on another network segment never show a MAC).")
        new, gone = db.save_scan_results(results, started, scan_id, scope=only)
        L("info", f"Finished in {int(time.time() - started)}s: {len(results)} services, {new} new, {gone} gone.")
        db.x("UPDATE scans SET status='finished', finished=?, found=?, new_count=?, gone_count=? WHERE id=?",
             (time.time(), len(results), new, gone, scan_id))
    except ScanStopped:
        L("warn", "Scan stopped by user. Nothing from this run was saved.")
        db.x("UPDATE scans SET status='stopped', finished=? WHERE id=?", (time.time(), scan_id))
    except Exception as e:
        L("error", f"Scan failed: {e}")
        db.x("UPDATE scans SET status='failed', finished=?, error=? WHERE id=?",
             (time.time(), str(e), scan_id))
    finally:
        state.update(running=False, stop=False, proc=None, tasks=[], targets=None, phase="", done=0, total=0)
    return True
