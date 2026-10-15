"""Local dashboard (stdlib only).

Threat model: the database is full of attacker-controlled strings (they came from the target's JS) and
real secret values. So:
  * binds to loopback only (override is explicit and loud)
  * every /api call needs a random per-launch token (sent as a header, so a malicious web page cannot
    forge requests: custom headers force a CORS preflight that we never approve)
  * Host header is validated (defeats DNS-rebinding)
  * strict CSP; the frontend builds the DOM with textContent only, never innerHTML
  * secrets are masked in lists; full values only via an explicit per-finding reveal call
"""
from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .difftools import diff_texts
from .models import mask  # noqa: F401
from .report import build_report, finding_view
from .store import TRIAGE, Store

STATIC = Path(__file__).parent / "static"
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 64 * 1024


def make_server(store_path: str, host: str = "127.0.0.1", port: int = 8777, token: str | None = None,
                allow_remote: bool = False) -> tuple[ThreadingHTTPServer, str]:
    token = token or os.urandom(18).hex()
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not allow_remote:
        raise ValueError("refusing to bind to a non-loopback address (the DB contains secrets); pass allow_remote=True to override")
    store = Store(store_path)

    class H(BaseHTTPRequestHandler):
        server_version = "jsdrift"
        sys_version = ""

        def log_message(self, *a):  # quiet
            pass

        # ---- helpers
        def _hosts_ok(self) -> bool:
            h = (self.headers.get("Host") or "").lower()
            p = self.server.server_address[1]
            return h in {f"127.0.0.1:{p}", f"localhost:{p}", f"[::1]:{p}"} or (allow_remote and not loopback)

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _authed(self) -> bool:
            return hmac.compare_digest(self.headers.get("X-JSDrift-Token", ""), token)

        def _origin_ok(self) -> bool:
            o = self.headers.get("Origin")
            if not o:
                return True
            return urlsplit(o).netloc.lower() == (self.headers.get("Host") or "").lower()

        # ---- routing
        def do_GET(self):  # noqa: N802
            if not self._hosts_ok():
                return self._json({"error": "bad host header"}, 403)
            u = urlsplit(self.path)
            if u.path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if u.path in ("/", "/index.html", "/app.js", "/app.css"):
                name = "index.html" if u.path in ("/", "/index.html") else u.path[1:]
                f = STATIC / name
                if not f.is_file():
                    return self._json({"error": "static asset missing"}, 500)
                return self._send(200, f.read_bytes(), MIME[f.suffix])
            if not u.path.startswith("/api/"):
                return self._json({"error": "not found"}, 404)
            if not self._authed() or not self._origin_ok():
                return self._json({"error": "unauthorized"}, 401)
            q = {k: v[-1] for k, v in parse_qs(u.query).items()}
            try:
                return self._api_get(u.path, q)
            except (KeyError, ValueError) as e:
                return self._json({"error": str(e)}, 400)
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"{type(e).__name__}"}, 500)

        def do_POST(self):  # noqa: N802
            if not self._hosts_ok():
                return self._json({"error": "bad host header"}, 403)
            if not self._authed() or not self._origin_ok():
                return self._json({"error": "unauthorized"}, 401)
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                return self._json({"error": "content-type must be application/json"}, 415)
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._json({"error": "body too large"}, 413)
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
                path = urlsplit(self.path).path
                if path == "/api/triage":
                    tgt, fid, tri = str(data["target"]), int(data["id"]), str(data["triage"])
                    if tri not in TRIAGE:
                        raise ValueError("bad triage value")
                    ok = store.set_triage(tgt, fid, tri, str(data.get("note", ""))[:500])
                    return self._json({"ok": ok})
                return self._json({"error": "not found"}, 404)
            except (KeyError, ValueError, TypeError) as e:
                return self._json({"error": str(e)}, 400)

        # ---- API
        def _api_get(self, path: str, q: dict):
            def i(name, default=0):
                return int(q.get(name, default))

            if path == "/api/targets":
                out = []
                for t in store.targets():
                    lr = store.last_run(t)
                    out.append({"name": t, "counts": store.counts(t), "last_run": lr})
                return self._json(out)
            if path == "/api/findings":
                rows, total = store.query_findings(
                    q["target"], state=q.get("state") or None, kinds=[k for k in q.get("kind", "").split(",") if k] or None,
                    min_conf=i("min_conf"), min_sev=q.get("min_sev", "info"),
                    triage=[x for x in q.get("triage", "").split(",") if x] or None, q=q.get("q", ""),
                    source=q.get("source", ""), limit=min(i("limit", 100), 500), offset=i("offset"))
                return self._json({"total": total, "items": [finding_view(r) for r in rows]})
            if path == "/api/finding":
                f = store.finding(i("id"))
                if not f:
                    return self._json({"error": "not found"}, 404)
                return self._json(finding_view(f, reveal=q.get("reveal") == "1"))
            if path == "/api/runs":
                return self._json(store.runs(q["target"]))
            if path == "/api/report":
                return self._json(build_report(store, i("run"), min_conf=i("min_conf"), min_sev=q.get("min_sev", "info"),
                                               include_fp=q.get("include_fp") == "1"))
            if path == "/api/files":
                return self._json(store.files(q["target"]))
            if path == "/api/versions":
                return self._json(store.versions(i("file_id")))
            if path == "/api/filediff":
                a, b = store.version_text(i("from")), store.version_text(i("to"))
                if a is None or b is None:
                    return self._json({"error": "version content not stored"}, 404)
                return self._json({"lines": diff_texts(a, b)})
            return self._json({"error": "not found"}, 404)

    srv = ThreadingHTTPServer((host, port), H)
    return srv, token


def serve(store_path: str, host: str = "127.0.0.1", port: int = 8777, open_browser: bool = False) -> None:
    srv, token = make_server(store_path, host, port)
    url = f"http://127.0.0.1:{srv.server_address[1]}/#token={token}"
    print(f"jsdrift dashboard: {url}\n(token is regenerated on every launch; Ctrl-C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
