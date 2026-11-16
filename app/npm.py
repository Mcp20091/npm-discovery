"""Client for the Nginx Proxy Manager API.

Shapes checked against NPM source (backend/schema):
  POST /api/tokens {identity, secret} -> {token, expires} (or a 2FA challenge object)
  GET  /api/tokens (Bearer)           -> refreshed {token, expires}
  GET  /api/nginx/proxy-hosts         -> [ {id, domain_names, forward_host, forward_port, ...} ]
  POST /api/nginx/proxy-hosts         -> requires domain_names, forward_scheme, forward_host, forward_port
  GET  /api/nginx/certificates        -> [ {id, nice_name, domain_names, ...} ]
Errors look like {"error": {"code": N, "message": "..."}}.
"""
import time
from datetime import datetime, timezone

import httpx

from . import config


class NpmError(Exception):
    pass


class NpmClient:
    def __init__(self):
        self._token = None
        self._expires = 0.0
        self._http = httpx.AsyncClient(base_url=config.NPM_URL, verify=config.NPM_VERIFY_TLS, timeout=15)

    @staticmethod
    def _msg(r):
        try:
            j = r.json()
            err = j.get("error", j)
            if isinstance(err, dict):
                return err.get("message") or str(err)
            return str(err)
        except Exception:
            return r.text[:200] or f"HTTP {r.status_code}"

    @staticmethod
    def _parse_expires(s):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
        except Exception:
            return time.time() + 3600

    def _set(self, j):
        if j.get("requires_2fa") or "token" not in j:
            raise NpmError("NPM account has 2FA enabled; use an account without 2FA for this app")
        self._token = j["token"]
        self._expires = self._parse_expires(j.get("expires", ""))

    async def _request(self, method, url, **kw):
        try:
            return await self._http.request(method, url, **kw)
        except httpx.HTTPError as e:
            raise NpmError(f"Cannot reach NPM at {config.NPM_URL}: {e.__class__.__name__} {e}") from e

    async def _login(self):
        r = await self._request("POST", "/api/tokens",
                                json={"identity": config.NPM_EMAIL, "secret": config.NPM_PASSWORD})
        if r.status_code != 200:
            raise NpmError(f"NPM login failed ({r.status_code}): {self._msg(r)}")
        self._set(r.json())

    async def _ensure_token(self):
        left = self._expires - time.time()
        if self._token and left > 3600:
            return
        if self._token and left > 0:
            r = await self._request("GET", "/api/tokens", headers={"Authorization": f"Bearer {self._token}"})
            if r.status_code == 200:
                try:
                    self._set(r.json())
                    return
                except NpmError:
                    pass
        await self._login()

    async def call(self, method, path, **kw):
        await self._ensure_token()
        for attempt in (0, 1):
            r = await self._request(method, path, headers={"Authorization": f"Bearer {self._token}"}, **kw)
            if r.status_code == 401 and attempt == 0:
                await self._login()
                continue
            break
        if r.status_code >= 400:
            raise NpmError(f"NPM {method} {path} failed ({r.status_code}): {self._msg(r)}")
        return r.json()

    async def proxy_hosts(self):
        return await self.call("GET", "/api/nginx/proxy-hosts")

    async def certificates(self):
        return await self.call("GET", "/api/nginx/certificates")

    async def create_proxy_host(self, payload):
        return await self.call("POST", "/api/nginx/proxy-hosts", json=payload)
