"""Optional web-page password.

Off by default. When a password is set (Settings tab) every /api/* route and the
main page require a session cookie; browsers without one get static/login.html.
Only a salted scrypt hash is stored (settings key `_auth_hash`). Sessions are
random tokens kept in memory, so a service restart logs everyone out.
"""
import asyncio
import hashlib
import hmac
import os
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import db

KEY = "_auth_hash"
COOKIE = "npmd_session"
SESSION_SECONDS = 12 * 3600
MAX_FAILS = 5            # failed logins per IP ...
WINDOW = 300             # ... within this many seconds lock the IP out ...
LOCKOUT = 300            # ... for this many seconds
FAIL_DELAY = 1.0
MIN_LEN = 8
OPEN_PATHS = {"/api/login", "/api/logout"}
STATIC = os.path.join(os.path.dirname(__file__), "static")

router = APIRouter()
_sessions = {}   # token -> expiry
_fails = {}      # ip -> [timestamps]
_locked = {}     # ip -> until


def _hash(password, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def _verify(password, stored):
    try:
        _, salt, _ = stored.split("$")
        return hmac.compare_digest(_hash(password, bytes.fromhex(salt)), stored)
    except ValueError:
        return False


def _stored():
    rows = db.q("SELECT value FROM settings WHERE key=?", (KEY,))
    return rows[0]["value"] if rows else None


def enabled():
    return _stored() is not None


def _valid(request):
    tok = request.cookies.get(COOKIE)
    exp = _sessions.get(tok)
    if exp is None:
        return False
    if exp < time.time():
        _sessions.pop(tok, None)
        return False
    return True


def _ip(request):
    return request.client.host if request.client else "?"


def _new_session(request, response):
    now = time.time()
    for t in [t for t, e in _sessions.items() if e < now]:
        del _sessions[t]
    tok = secrets.token_urlsafe(32)
    _sessions[tok] = now + SESSION_SECONDS
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(COOKIE, tok, max_age=SESSION_SECONDS, httponly=True, samesite="strict", secure=secure, path="/")


async def middleware(request: Request, call_next):
    path = request.url.path
    if (path == "/" or path.startswith("/api/")) and path not in OPEN_PATHS and enabled() and not _valid(request):
        if path == "/":
            return FileResponse(os.path.join(STATIC, "login.html"), headers={"Cache-Control": "no-store"})
        return JSONResponse({"detail": "Login required"}, status_code=401)
    return await call_next(request)


class LoginReq(BaseModel):
    password: str


@router.post("/api/login")
async def login(req: LoginReq, request: Request):
    ip, now = _ip(request), time.time()
    if _locked.get(ip, 0) > now:
        raise HTTPException(429, f"Too many failed attempts. Try again in {int(_locked[ip] - now) + 1} seconds.")
    stored = _stored()
    if stored is None:
        return {"ok": True}  # no password set: nothing to log in to
    if not await asyncio.to_thread(_verify, req.password, stored):
        recent = [t for t in _fails.get(ip, []) if t > now - WINDOW] + [now]
        _fails[ip] = recent
        if len(recent) >= MAX_FAILS:
            _locked[ip] = now + LOCKOUT
            _fails.pop(ip, None)
        await asyncio.sleep(FAIL_DELAY)
        raise HTTPException(401, "Wrong password")
    _fails.pop(ip, None)
    resp = JSONResponse({"ok": True})
    _new_session(request, resp)
    return resp


@router.post("/api/logout")
async def logout(request: Request):
    _sessions.pop(request.cookies.get(COOKIE), None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


class PasswordReq(BaseModel):
    password: str


@router.put("/api/password")
async def set_password(req: PasswordReq, request: Request):
    if len(req.password) < MIN_LEN:
        raise HTTPException(400, f"Password must be at least {MIN_LEN} characters")
    h = await asyncio.to_thread(_hash, req.password)
    db.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (KEY, h))
    _sessions.clear()  # a changed password signs everyone else out
    resp = JSONResponse({"ok": True})
    _new_session(request, resp)
    return resp


@router.delete("/api/password")
async def remove_password():
    db.x("DELETE FROM settings WHERE key=?", (KEY,))
    _sessions.clear()
    return {"ok": True}
