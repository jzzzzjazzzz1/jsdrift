"""Scope-guarded HTTP client (stdlib only).

Design rules:
  * every request - and every redirect hop - is checked against the Scope *before* it is sent
  * global rate limit with jitter, bounded retries on 429/503, and an abort switch if the server
    keeps throttling us (we back off rather than push)
  * response size is capped *after* decompression (zip-bomb safe)
"""
from __future__ import annotations

import gzip
import random
import ssl
import threading
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field

from .scope import Scope


class ScopeBlocked(Exception):
    def __init__(self, url: str, reason: str):
        super().__init__(f"{url}: {reason}")
        self.url, self.reason = url, reason


@dataclass
class Response:
    url: str
    final_url: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""
    blocked: bool = False
    too_large: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and not self.error

    @property
    def text(self) -> str:
        t = self.body.decode("utf-8", errors="replace")
        return t[1:] if t.startswith("﻿") else t


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, scope: Scope):
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        d = self.scope.check(newurl)
        if not d:
            raise ScopeBlocked(newurl, f"redirect target rejected: {d.reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _Limiter:
    def __init__(self, delay: float):
        self.delay, self._next, self._lock = max(0.0, delay), 0.0, threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.delay * (1 + random.random() * 0.25)
        if start > now:
            time.sleep(start - now)


class Fetcher:
    def __init__(self, scope: Scope, headers: dict | None = None, user_agent: str = "jsdrift",
                 delay: float = 0.5, timeout: float = 20.0, max_bytes: int = 8 * 1024 * 1024,
                 proxy: str = "", verify_tls: bool = True, trust_env: bool = True, max_throttles: int = 6):
        self.scope = scope
        self.headers = {"User-Agent": user_agent, "Accept": "*/*", "Accept-Encoding": "gzip, deflate", **(headers or {})}
        self.timeout, self.max_bytes = timeout, max_bytes
        self.limiter = _Limiter(delay)
        self.blocked: dict[str, str] = {}
        self.requests = 0
        self.bytes = 0
        self.throttled = 0
        self.max_throttles = max_throttles
        self._lock = threading.Lock()
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers: list = [_ScopedRedirect(scope), urllib.request.HTTPSHandler(context=ctx)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        elif not trust_env:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def aborted(self) -> bool:
        return self.throttled >= self.max_throttles

    def _note_block(self, url: str, reason: str) -> Response:
        with self._lock:
            self.blocked[url] = reason
        return Response(url, error=f"blocked by scope: {reason}", blocked=True)

    def get(self, url: str, extra_headers: dict | None = None, max_bytes: int | None = None) -> Response:
        d = self.scope.check(url)
        if not d:
            return self._note_block(url, d.reason)
        if self.aborted:
            return Response(url, error="aborted: server keeps throttling (429/503); try again later with a larger delay")
        limit = max_bytes or self.max_bytes
        for attempt in range(3):
            self.limiter.wait()
            with self._lock:
                self.requests += 1
            req = urllib.request.Request(url, headers={**self.headers, **(extra_headers or {})})
            try:
                with self._opener.open(req, timeout=self.timeout) as r:
                    return self._read(url, r, r.status, limit)
            except ScopeBlocked as e:
                return self._note_block(e.url, e.reason)
            except urllib.error.HTTPError as e:
                if e.code in (429, 503) and attempt < 2:
                    with self._lock:
                        self.throttled += 1
                    time.sleep(min(30.0, _retry_after(e.headers.get("Retry-After")) or (2 ** attempt * 2)))
                    continue
                if e.code in (429, 503):
                    with self._lock:
                        self.throttled += 1
                return Response(url, final_url=e.geturl() or url, status=e.code, headers=dict(e.headers.items()),
                                error="" if e.code == 404 else f"HTTP {e.code}")
            except (urllib.error.URLError, OSError, ValueError, ssl.SSLError) as e:
                if isinstance(getattr(e, "reason", None), ScopeBlocked):
                    b = e.reason  # type: ignore[union-attr]
                    return self._note_block(b.url, b.reason)
                if attempt < 2:
                    time.sleep(1 + attempt)
                    continue
                return Response(url, error=f"{type(e).__name__}: {getattr(e, 'reason', e)}")
        return Response(url, error="gave up after retries")

    def _read(self, url: str, r, status: int, limit: int) -> Response:
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        raw = r.read(limit + 1)
        enc = hdrs.get("content-encoding", "").lower()
        try:
            if enc == "gzip":
                body = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, limit + 1)
            elif enc == "deflate":
                try:
                    body = zlib.decompressobj().decompress(raw, limit + 1)
                except zlib.error:
                    body = zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, limit + 1)
            else:
                body = raw
        except (zlib.error, EOFError, gzip.BadGzipFile) as e:
            return Response(url, final_url=r.geturl(), status=status, headers=hdrs, error=f"bad {enc} body: {e}")
        if len(body) > limit:
            return Response(url, final_url=r.geturl(), status=status, headers=hdrs, too_large=True,
                            error=f"larger than {limit // 1024 // 1024} MB cap")
        with self._lock:
            self.bytes += len(body)
        return Response(url, final_url=r.geturl(), status=status, headers=hdrs, body=body)


def _retry_after(v: str | None) -> float:
    try:
        return float(v) if v else 0.0
    except ValueError:
        return 0.0
