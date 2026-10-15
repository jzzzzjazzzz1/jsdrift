
"""Self-contained demo: a fake web app on 127.0.0.1 that "deploys" a new version between two scans.

Nothing leaves your machine. All credential-like examples below are synthetic.
Version 1 contains false-positive bait; version 2 introduces simulated attack-surface drift.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .secrets import _base62

H1, H2 = "5f3e2a1b", "9c8d7e6f"
ADMIN_H = "9f8e7d6c"


def _b64(d: dict) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(d, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )


def gh_token() -> str:
    """Synthetic GitHub token with a *valid* embedded CRC32, built at runtime (never a literal)."""
    core = "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cD1"
    return "gh" + "p_" + core + _base62(zlib.crc32(core.encode()) & 0xFFFFFFFF, 6)


def service_role_jwt() -> str:
    return (
        f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}."
        f"{_b64({'iss': 'supabase', 'role': 'service_role', 'exp': 4102444800})}."
        "ZGVtby1zaWduYXR1cmUtbm90LXJlYWw"
    )


def _seed(label: str, n: int) -> str:
    """Deterministic pseudo-random alphanumerics, so demo values are stable but never literals."""
    out, i = "", 0
    while len(out) < n:
        out += base64.b64encode(hashlib.sha256(f"{label}:{i}".encode()).digest()).decode().replace("=", "")
        i += 1
    return out[:n]


def aws_key_id(account: int = 123456789012) -> str:
    """Synthetic AWS access key ID whose base32 body decodes to `account` (passes the validator)."""
    raw = (account << 7).to_bytes(6, "big") + hashlib.sha256(b"demo-aws").digest()[:4]
    return "AK" + "IA" + base64.b32encode(raw).decode()


def aws_secret() -> str:
    return _seed("demo-aws-secret", 40).replace("+", "x").replace("/", "y")


def gitlab_pat() -> str:
    return "glp" + "at-" + _seed("demo-gitlab", 20).replace("+", "-").replace("/", "_")


def stripe_placeholder() -> str:
    return "sk_" + "live_" + "x" * 24      # shape of a live key, but an obvious placeholder


AWS_ID = aws_key_id()
AWS_SECRET = aws_secret()

_COMMON_T = r'''
var API="/api/v1",labels={password:"Password",forgot_password:"Forgot your password?",token:"authToken",title:"Reset password"};
var ph={apiKey:"YOUR_API_KEY_HERE",secret:"changeme",password:"xxxxxxxx",client_secret:"<client-secret>"};
var docs={aws:"__DOC_AWS__",jwt:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",pem:"-----BEGIN PRIVATE KEY-----"};
var misc={ns:"http://www.w3.org/1999/xhtml",mime:"application/json",fmt:"DD/MM/YYYY",img:"/static/img/logo.png",re:/^[\w.+-]+@[\w-]+\.[\w.-]+$/};
var cfg={stripe:"__STRIPE_PH__"};
function login(a,b){return fetch("/api/v1/auth/login",{method:"POST",body:JSON.stringify({email:a,password:b})})}
function order(id){return axios.get(`/api/v1/orders/${id}`)}
function search(q){return fetch("/api/v1/search?q="+encodeURIComponent(q)+"&page=1")}
'''

_DOC_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"      # AWS's published documentation key, split on purpose
_COMMON = _COMMON_T.replace("__DOC_AWS__", _DOC_AWS).replace("__STRIPE_PH__", stripe_placeholder())

V1_MAIN = "!function(){" + _COMMON + '''
function me(){return axios.get("/api/v1/users/me")}
window.app={login:login,me:me,order:order,search:search,labels:labels};
}();
'''

V2_MAIN = "!function(){" + _COMMON + f'''
function me(){{return axios.get("/api/v2/users/me")}}
function impersonate(id){{return fetch("/api/v2/admin/users/"+id+"/impersonate",{{method:"POST"}})}}
function exportCsv(u){{return axios.get("/api/v1/export?format=csv&redirect_url="+encodeURIComponent(u))}}
var awsCfg={{accessKeyId:"{AWS_ID}",secretAccessKey:"{AWS_SECRET}"}};
var ci={{token:"{gh_token()}"}};
var sb={{url:"https://xyzcompany.supabase.test",serviceKey:"{service_role_jwt()}"}};
var backups="https://demo-app-backups.s3.amazonaws.com/exports/";
var Admin=function(){{return import("/static/js/admin-panel.{ADMIN_H}.js")}};
window.app={{login:login,me:me,order:order,search:search,labels:labels,impersonate:impersonate,exportCsv:exportCsv,Admin:Admin}};
}}();
//# sourceMappingURL=main.{H2}.js.map
'''

VENDOR = '''/*! tiny-lib 1.2.3 */
(function(){var ns="http://www.w3.org/1999/xhtml",p="/node_modules/tiny-lib/",d="MM/DD/YYYY";
var o={password:"Password",token:"tokenType",secret:"secretKey"};})();
'''

ADMIN_CHUNK = '''(function(){
var q="mutation PurgeAccount($id: ID!) { purgeAccount(id: $id) { ok } }";
fetch("/api/v2/admin/audit-log?user_id=1&debug=true");
var host="https://staging-internal.demo-corp.test/v2";
})();
'''

SOURCEMAP = json.dumps({
    "version": 3,
    "file": "main.js",
    "sources": [
        "webpack:///./src/index.js",
        "webpack:///./src/features/billing/RefundPanel.tsx",
        "webpack:///./src/admin/ImpersonateUser.tsx",
        "webpack:///./node_modules/react/index.js",
    ],
    "sourcesContent": [
        "import './app';\n",
        'const STAGING_API = "https://staging-api.demo.test/graphql";\n'
        '// TODO: remove hardcoded token before release  const SVC = "' + gitlab_pat() + '";\n'
        "export const refund = (id) => fetch(`/api/v2/billing/refunds/${id}`, {method: 'POST'});\n",
        "export const go = id => fetch('/api/v2/admin/users/' + id + '/impersonate');\n",
        "module.exports = {};",
    ],
    "mappings": "",
})


def _index(v: int) -> str:
    h = H1 if v == 1 else H2
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>Demo</title>\n'
        '<script>window.__CONFIG__={"env":"prod","csrfToken":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"};</script>\n'
        '<script src="/static/js/vendor.4d3c2b1a.js"></script>\n'
        f'<script src="/static/js/main.{h}.js" defer></script>\n'
        '<script src="https://cdn.thirdparty.test/analytics.js"></script>\n'
        '</head><body><div id="root"></div></body></html>'
    )


class DemoApp:
    def __init__(self) -> None:
        self.version = 1
        self.fail: set[str] = set()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code: int, body: str, ctype: str = "text/html") -> None:
                b = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):  # noqa: N802
                p, v = self.path.split("?", 1)[0], outer.version
                js = "application/javascript"

                if any(p.startswith(x) for x in outer.fail):
                    return self._send(500, "boom")

                if p == "/":
                    return self._send(200, _index(v))

                if p == f"/static/js/main.{H1 if v == 1 else H2}.js":
                    return self._send(200, V1_MAIN if v == 1 else V2_MAIN, js)

                if p == "/static/js/vendor.4d3c2b1a.js":
                    return self._send(200, VENDOR, js)

                if v == 2 and p == f"/static/js/admin-panel.{ADMIN_H}.js":
                    return self._send(200, ADMIN_CHUNK, js)

                if v == 2 and p == f"/static/js/main.{H2}.js.map":
                    return self._send(200, SOURCEMAP, "application/json")

                if p.endswith(".map"):
                    return self._send(404, "not found")

                # SPA fallback: unknown paths return index.html with 200.
                return self._send(200, _index(v))

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever,
            daemon=True,
        )

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def start(self) -> str:
        self.thread.start()
        return self.base

    def deploy(self) -> None:
        self.version = 2

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()