import os
import sqlite3
import threading
import time

from . import config

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
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started REAL, finished REAL, status TEXT, error TEXT, found INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS scan_hits(
            scan_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL,
            scheme TEXT, title TEXT, server TEXT, hostname TEXT);
        CREATE INDEX IF NOT EXISTS scan_hits_scan ON scan_hits(scan_id);
        """)
        cols = {r["name"] for r in _conn.execute("PRAGMA table_info(scans)")}
        for c in ("new_count", "gone_count"):  # added after v1: upgrade existing databases
            if c not in cols:
                _conn.execute(f"ALTER TABLE scans ADD COLUMN {c} INTEGER DEFAULT 0")
        dcols = {r["name"] for r in _conn.execute("PRAGMA table_info(discoveries)")}
        for c in ("mac", "vendor"):
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


def save_scan_results(results, scan_start, scan_id=None):
    """results: dicts with ip, port, scheme, title, server, hostname. Rows not seen become missing.
    Returns (new_count, gone_count) and records the scan's service list for the History tab."""
    now = time.time()
    with _lock:
        known = {(r["ip"], r["port"]) for r in _conn.execute("SELECT ip, port FROM discoveries")}
        new = sum(1 for r in results if (r["ip"], r["port"]) not in known)
        gone = _conn.execute("SELECT COUNT(*) FROM discoveries WHERE missing=0 AND last_seen < ?",
                             (scan_start,)).fetchone()[0]
        if scan_id is not None:
            _conn.executemany("INSERT INTO scan_hits VALUES(?,?,?,?,?,?,?)",
                              [(scan_id, r["ip"], r["port"], r["scheme"], r["title"], r["server"], r["hostname"])
                               for r in results])
            _conn.execute("DELETE FROM scan_hits WHERE scan_id NOT IN "
                          "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)", (HISTORY_KEEP,))
            _conn.execute("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                          (HISTORY_KEEP,))
        for r in results:
            _conn.execute("""
                INSERT INTO discoveries(ip,port,scheme,title,server,hostname,first_seen,last_seen,missing,mac)
                VALUES(?,?,?,?,?,?,?,?,0,?)
                ON CONFLICT(ip,port) DO UPDATE SET scheme=excluded.scheme, title=excluded.title,
                  server=excluded.server, hostname=excluded.hostname,
                  last_seen=excluded.last_seen, missing=0,
                  vendor=CASE WHEN excluded.mac IS NOT NULL AND excluded.mac IS NOT discoveries.mac
                              THEN NULL ELSE vendor END,
                  mac=COALESCE(excluded.mac, mac)""",
                         (r["ip"], r["port"], r["scheme"], r["title"], r["server"], r["hostname"], now, now,
                          r.get("mac")))
        _conn.execute("UPDATE discoveries SET missing=1 WHERE last_seen < ?", (scan_start,))
        _conn.commit()
    return new, gone
