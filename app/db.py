import os
import sqlite3
import threading
import time

from . import config, targets

_lock = threading.RLock()
_conn = None


def init():
    global _conn
    if _conn is not None:
        return
    os.makedirs(config.DATA_DIR, exist_ok=True)
    path = os.path.join(config.DATA_DIR, "discovery.db")
    _conn = sqlite3.connect(path, check_same_thread=False)
    try:
        os.chmod(path, 0o600)  # settings include the NPM password
    except OSError:
        pass
    _conn.row_factory = sqlite3.Row
    with _lock:
        _conn.executescript("""
        CREATE TABLE IF NOT EXISTS discoveries(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL, port INTEGER NOT NULL,
            scheme TEXT, title TEXT, server TEXT, hostname TEXT,
            first_seen REAL, last_seen REAL,
            dismissed INTEGER NOT NULL DEFAULT 0,
            missing INTEGER NOT NULL DEFAULT 0,
            UNIQUE(ip, port));
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS exclusions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL UNIQUE, added REAL);
        CREATE TABLE IF NOT EXISTS host_names(ip TEXT PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notes(
            kind TEXT NOT NULL, key TEXT NOT NULL, note TEXT NOT NULL, PRIMARY KEY(kind, key));
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started REAL, finished REAL, status TEXT, error TEXT, found INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS scan_hits(
            scan_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL,
            scheme TEXT, title TEXT, server TEXT, hostname TEXT);
        CREATE INDEX IF NOT EXISTS scan_hits_scan ON scan_hits(scan_id);
        CREATE TABLE IF NOT EXISTS scan_log(scan_id INTEGER NOT NULL, ts REAL, level TEXT, msg TEXT);
        CREATE INDEX IF NOT EXISTS scan_log_scan ON scan_log(scan_id);
        CREATE TABLE IF NOT EXISTS oui_cache(
            oui TEXT NOT NULL, provider TEXT NOT NULL, vendor TEXT, ts REAL, PRIMARY KEY(oui, provider));
        """)
        cols = {r["name"] for r in _conn.execute("PRAGMA table_info(scans)")}
        for c in ("new_count", "gone_count"):  # added after v1: upgrade existing databases
            if c not in cols:
                _conn.execute(f"ALTER TABLE scans ADD COLUMN {c} INTEGER DEFAULT 0")
        dcols = {r["name"] for r in _conn.execute("PRAGMA table_info(discoveries)")}
        for c in ("mac", "vendor", "vendor_source"):
            if c not in dcols:
                _conn.execute(f"ALTER TABLE discoveries ADD COLUMN {c} TEXT")
        _conn.execute("UPDATE scans SET status='failed', error='Interrupted by restart', finished=? "
                      "WHERE status='running'", (time.time(),))
        _conn.commit()


def q(sql, args=()):
    with _lock:
        return [dict(r) for r in _conn.execute(sql, args).fetchall()]


def x(sql, args=()):
    with _lock:
        cur = _conn.execute(sql, args)
        _conn.commit()
        return cur


HISTORY_KEEP = 100  # scans (and their per-scan service lists) kept


def save_scan_results(results, scan_start, scan_id=None, scope=None):
    """results: dicts with ip, port, scheme, title, server, hostname. Rows not seen become missing.
    Returns (new_count, gone_count) and records the scan's service list for the History tab.
    `scope` limits which hosts can be marked missing (a hand-typed scan only looked at those targets)."""
    now = time.time()
    with _lock:
        known = {(r["ip"], r["port"]) for r in _conn.execute("SELECT ip, port FROM discoveries")}
        new = sum(1 for r in results if (r["ip"], r["port"]) not in known)
        if scan_id is not None:
            _conn.executemany("INSERT INTO scan_hits VALUES(?,?,?,?,?,?,?)",
                              [(scan_id, r["ip"], r["port"], r["scheme"], r["title"], r["server"], r["hostname"])
                               for r in results])
            _conn.execute("DELETE FROM scan_hits WHERE scan_id NOT IN "
                          "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)", (HISTORY_KEEP,))
            _conn.execute("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                          (HISTORY_KEEP,))
            _conn.execute("DELETE FROM scan_log WHERE scan_id NOT IN (SELECT id FROM scans)")
        for r in results:
            _conn.execute("""
                INSERT INTO discoveries(ip,port,scheme,title,server,hostname,first_seen,last_seen,missing,mac)
                VALUES(?,?,?,?,?,?,?,?,0,?)
                ON CONFLICT(ip,port) DO UPDATE SET scheme=excluded.scheme, title=excluded.title,
                  server=excluded.server, hostname=excluded.hostname,
                  last_seen=excluded.last_seen, missing=0,
                  vendor=CASE WHEN excluded.mac IS NOT NULL AND excluded.mac IS NOT discoveries.mac
                              THEN NULL ELSE vendor END,
                  vendor_source=CASE WHEN excluded.mac IS NOT NULL AND excluded.mac IS NOT discoveries.mac
                              THEN NULL ELSE vendor_source END,
                  mac=COALESCE(excluded.mac, mac)""",
                         (r["ip"], r["port"], r["scheme"], r["title"], r["server"], r["hostname"], now, now,
                          r.get("mac")))
        # anything in scope that this scan did not see again (its last_seen is still older than the scan)
        in_scope = (lambda ip: True) if scope is None else (lambda ip: any(targets.covers(s, ip) for s in scope))
        stale = [r["id"] for r in _conn.execute(
            "SELECT id, ip FROM discoveries WHERE missing=0 AND last_seen < ?", (scan_start,)) if in_scope(r["ip"])]
        _conn.executemany("UPDATE discoveries SET missing=1 WHERE id=?", [(i,) for i in stale])
        gone = len(stale)
        _conn.commit()
    return new, gone
