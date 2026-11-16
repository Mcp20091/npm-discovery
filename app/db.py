import os
import sqlite3
import threading
import time

from . import config

_lock = threading.RLock()
_conn = None


def init():
    global _conn
    os.makedirs(config.DATA_DIR, exist_ok=True)
    _conn = sqlite3.connect(os.path.join(config.DATA_DIR, "discovery.db"), check_same_thread=False)
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
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started REAL, finished REAL, status TEXT, error TEXT, found INTEGER DEFAULT 0);
        """)
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


def save_scan_results(results, scan_start):
    """results: dicts with ip, port, scheme, title, server, hostname. Rows not seen become missing."""
    now = time.time()
    with _lock:
        for r in results:
            _conn.execute("""
                INSERT INTO discoveries(ip,port,scheme,title,server,hostname,first_seen,last_seen,missing)
                VALUES(?,?,?,?,?,?,?,?,0)
                ON CONFLICT(ip,port) DO UPDATE SET scheme=excluded.scheme, title=excluded.title,
                  server=excluded.server, hostname=excluded.hostname,
                  last_seen=excluded.last_seen, missing=0""",
                         (r["ip"], r["port"], r["scheme"], r["title"], r["server"], r["hostname"], now, now))
        _conn.execute("UPDATE discoveries SET missing=1 WHERE last_seen < ?", (scan_start,))
        _conn.commit()
