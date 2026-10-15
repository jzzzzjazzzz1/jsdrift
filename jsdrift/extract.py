"""Attack-surface extraction from JavaScript source.

Finds endpoints, client routes, hosts, parameters (with vulnerability-class hints), GraphQL
operations, sourcemap references and secrets. Every candidate goes through noise filters and
gets a 0-99 confidence score; rejections can be listed with ``explain=True``.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from .models import Finding
from .secrets import Rejection, scan_units, scrub_context
from .tokenizer import Tok, tokenize
from .util import norm_host

# --------------------------------------------------------------------------- noise lists

DEFAULT_NOISE_HOSTS = {
    "w3.org", "www.w3.org", "schema.org", "json-schema.org", "purl.org", "ogp.me", "xmlpull.org",
    "reactjs.org", "react.dev", "fb.me", "reactjs.org", "mozilla.org", "developer.mozilla.org",
    "github.com", "raw.githubusercontent.com", "npmjs.com", "npmjs.org", "apache.org", "gnu.org",
    "example.com", "example.org", "example.net", "localhost", "fonts.googleapis.com", "fonts.gstatic.com",
    "cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net", "ajax.googleapis.com", "stackoverflow.com",
    "wikipedia.org", "medium.com", "bit.ly", "goo.gl", "tc39.es", "ecma-international.org", "nodejs.org",
    "webpack.js.org", "babeljs.io", "angular.io", "vuejs.org", "mths.be", "momentjs.com", "lodash.com",
    "jquery.com", "jquery.org", "openjsf.org", "creativecommons.org", "unicode.org", "iana.org",
}
TLDS = {
    "com", "net", "org", "io", "co", "dev", "app", "ai", "cloud", "tech", "xyz", "info", "biz", "me", "us",
    "uk", "de", "fr", "in", "np", "au", "ca", "jp", "cn", "ru", "br", "nl", "eu", "sh", "so", "ly", "gg",
    "tv", "cc", "ch", "se", "no", "es", "it", "pl", "kr", "sg", "hk", "id", "mx", "za", "nz", "ie", "fi",
    "internal", "local", "corp", "lan", "intra", "int", "online", "site", "store", "shop", "pro", "link",
    "network", "systems", "services", "digital", "email", "live", "page", "run", "zone", "one",
}
STATIC_EXT = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "css", "scss", "less", "woff", "woff2",
    "ttf", "otf", "eot", "map", "mp4", "mp3", "webm", "wav", "ogg", "pdf", "zip", "gz", "wasm", "md", "txt",
    "ts", "tsx", "jsx", "vue", "html", "htm", "min",
}
PATH_NOISE = re.compile(
    r"(?i)(?:^/(?:\*|#|\^|path/to|foo|bar|baz|example|test/test|usr|etc|var|home|users|tmp|opt|node_modules|"
    r"_next|_nuxt|__webpack|sockjs-node|webpack|static/(?:css|media|fonts|img|images|js)|assets/(?:img|images|fonts)|"
    r"images|img|fonts|locales?|i18n|lang|public)(?:/|$)|node_modules|\.\./|/\.\.)"
)
DATE_TOKENS = re.compile(r"^(?:[dmyDMY]{1,4}|[hH]{1,2}|mm|ss|SSS|a|A|[Zz]+)$")
STATIC_DIRS = re.compile(r"(?i)^/(?:static|assets|dist|build|public|media|vendor)/")
API_PREFIX = re.compile(
    r"(?i)^/(?:api|apis|rest|graphql|gql|v\d+(?:\.\d+)?|internal|private|admin\w*|manage\w*|console|oauth2?|auth\w*|sso|saml|"
    r"openid|\.well-known|actuator|swagger\w*|openapi|debug\w*|metrics|health\w*|export\w*|import\w*|upload\w*|"
    r"download\w*|webhooks?|callback|hooks?|ajax|services?|backend|bff|rpc|trpc|socket\.io|ws|wp-json|cgi-bin|"
    r"portal|backoffice|account\w*|user\w*|me|session\w*|login|logout|register|search|query|files?|graph)(?:/|$|\.)"
)
HIGH_PATH = re.compile(
    r"(?i)(?:^|/)(?:internal|private|admin\w*|backoffice|debug\w*|actuator|swagger\w*|impersonat\w*|sudo|backup\w*|"
    r"dump|\.git|\.env|console|staging|superuser|root|su|masquerade|shell|exec|eval)(?:/|$|\.|\?)"
)
RISKY_PATH = re.compile(
    r"(?i)(?:^|/)(?:manage\w*|metrics|export\w*|import\w*|test\w*|dev|graphql|oauth2?|callback|webhooks?|upload\w*|"
    r"token\w*|secrets?|config\w*|env|logs?|trace|sso|saml|invite\w*|reset\w*|password\w*|2fa|mfa|keys?|apikeys?|"
    r"billing|payments?|invoices?|roles?|permissions?|audit\w*|feature-?flags?|flags|openapi|docs|v[1-9]\d?/(?:users?|accounts?))"
    r"(?:/|$|\.|\?)"
)
CALL_CTX = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\$\.\w+|\.(?:get|post|put|patch|delete|head|request|getJSON|ajax|send|use))\s*\(\s*$|"""
    r"""\.open\(\s*["']([A-Z]+)["']\s*,\s*$""",
)
KEY_CTX = re.compile(
    r"""(?:\burl|\buri|\bhref|endpoint|baseURL|baseUrl|apiUrl|apiURL|API_URL|apiBase|\bapi|\baction|\bsrc)\s*[:=]\s*$""", re.I
)
ROUTE_CTX = re.compile(r"""(?:\bpath|\broute|\bto|\bhref)\s*[:=]\s*$|<Route\s+path=\s*$""", re.I)
METHOD_FROM_CALL = re.compile(r"\.(get|post|put|patch|delete|head)\s*\(\s*$", re.I)

# --------------------------------------------------------------------------- parameter hints

CLOUD_HOST = re.compile(r"(?i)(?:\.s3[.\-][\w.\-]*amazonaws\.com|^s3[.\-][\w.\-]*amazonaws\.com|storage\.googleapis\.com|"
                        r"\.blob\.core\.windows\.net|\.firebaseio\.com|\.digitaloceanspaces\.com|\.r2\.cloudflarestorage\.com)$")
PARAM_HINTS: dict[str, tuple[str, str, int]] = {}


def _hint(label: str, severity: str, *names: str) -> None:
    for n in names:
        PARAM_HINTS[re.sub(r"[_\-]", "", n.lower())] = (label, severity, 0)


_hint("open-redirect candidate", "medium", "redirect", "redirect_uri", "redirect_url", "redirecturl", "return", "returnurl",
      "return_to", "returnto", "next", "continue", "dest", "destination", "goto", "callback", "callback_url", "forward",
      "success_url", "failure_url", "back", "backurl", "relaystate")
_hint("SSRF candidate", "medium", "url", "uri", "link", "src", "source", "host", "domain", "proxy", "webhook", "feed",
      "image_url", "avatar_url", "imageurl", "fetch", "remote", "target", "endpoint", "site", "website", "import_url")
_hint("path traversal / LFI candidate", "medium", "file", "filename", "path", "filepath", "dir", "folder", "template",
      "page", "include", "doc", "document", "download", "load", "view", "resource", "lang", "locale")
_hint("IDOR candidate", "medium", "id", "user_id", "userid", "uid", "account_id", "org_id", "orgid", "tenant", "tenant_id",
      "customer_id", "order_id", "invoice_id", "project_id", "member", "owner", "profile_id", "workspace_id", "team_id")
_hint("authz / privilege candidate", "medium", "role", "roles", "admin", "is_admin", "isadmin", "permission", "permissions",
      "scope", "privilege", "group", "level", "impersonate", "sudo", "superuser", "access_level", "acl")
_hint("debug / hidden feature flag", "medium", "debug", "test", "dev", "trace", "verbose", "internal", "staging", "beta",
      "preview", "flag", "feature", "experiment", "mock", "sandbox", "admin_mode", "god_mode", "bypass")
_hint("injection candidate", "low", "q", "query", "search", "filter", "sort", "order", "orderby", "order_by", "sortby", "where",
      "fields", "select", "expand", "cmd", "exec", "command", "eval", "expression", "sql", "regex", "xpath", "script")
_hint("auth material in parameter", "medium", "token", "access_token", "api_key", "apikey", "key", "secret", "password", "pass",
      "session", "sessionid", "jwt", "otp", "code", "state", "nonce", "signature", "sig", "hmac")

PARAM_NOISE = {
    "type", "options", "labels", "datasets", "style", "classname", "children", "ref", "length", "name", "value", "values",
    "title", "text", "width", "height", "color", "size", "index", "items", "className", "props", "event", "target_",
    "x", "y", "z", "a", "b", "c", "e", "t", "n", "r", "i", "o", "s", "u", "$$typeof", "constructor", "prototype", "default",
    "message", "error", "status", "success", "data", "result", "response", "headers", "method", "body", "mode", "cache",
    "credentials", "signal", "content-type", "accept", "authorization",
}
PARAM_NAME = re.compile(r"^[A-Za-z_][\w\-.\[\]]{0,39}$")


def param_hint(name: str) -> tuple[str, str] | None:
    h = PARAM_HINTS.get(re.sub(r"[_\-]", "", name.lower()))
    return (h[0], h[1]) if h else None


# --------------------------------------------------------------------------- ignore rules

@dataclass
class Ignore:
    hosts: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    values: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._paths = [re.compile(p) for p in self.paths]

    def matches(self, f: Finding) -> bool:
        if f.value in self.values or f.rule in self.rules:
            return True
        if f.kind == "host" and any(f.value == h or f.value.endswith("." + h) for h in self.hosts):
            return True
        if f.kind == "param" and f.value in self.params:
            return True
        if f.kind in ("endpoint", "route") and any(p.search(f.value) for p in self._paths):
            return True
        return False


@dataclass
class ExtractResult:
    findings: list[Finding] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)
    js_refs: list[str] = field(default_factory=list)
    sourcemaps: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- normalisation

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def normalize_path(path: str) -> str:
    """Collapse dynamic segments so /users/123 and /users/${id} are one endpoint."""
    segs = []
    for s in path.split("/"):
        if not s:
            segs.append(s)
        elif "{expr}" in s or "${" in s:
            segs.append("{param}")
        elif s.isdigit() and len(s) >= 1:
            segs.append("{id}")
        elif _UUID.match(s):
            segs.append("{uuid}")
        elif re.fullmatch(r"[0-9a-fA-F]{16,}", s):
            segs.append("{hash}")
        else:
            segs.append(s)
    out = "/".join(segs)
    if len(out) > 1 and out.endswith("/"):
        out = out[:-1]
    return out


HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")
BARE_HOST = re.compile(r"^((?:[a-z0-9][a-z0-9\-]*\.)+[a-z]{2,24})(?::(\d{2,5}))?$")
URL_RE = re.compile(r"^(?:(https?|wss?):)?//", re.I)
PATH_ALLOWED = re.compile(r"^/[A-Za-z0-9_\-.~%!$&'()*+,;=:@/{}\[\]?#]*$")
JS_REF = re.compile(r"^[\w\-./{}~%@:]+\.m?js(?:\?[\w=&.\-]*)?$")


class Extractor:
    def __init__(self, noise_hosts=(), extra_tlds=(), ignore: Ignore | None = None, explain: bool = False):
        self.noise = DEFAULT_NOISE_HOSTS | {h.lower() for h in noise_hosts}
        self.tlds = TLDS | {t.lower() for t in extra_tlds}
        self.ignore = ignore or Ignore()
        self.explain = explain

    # ---- public entry
    def run(self, src: str, source: str = "", vendor: bool = False) -> ExtractResult:
        res = ExtractResult()
        acc: dict[tuple[str, str], Finding] = {}
        tokens = list(tokenize(src))
        # endpoints are matched on *joined* literals ("/api/u/"+id+"/edit" -> /api/u/{expr}/edit);
        # secrets are scanned on the original tokens below.
        for tok in join_concatenations(src, tokens):
            if tok.kind in ("str", "tpl"):
                self._string(tok, src, vendor, acc, res)
            elif tok.kind == "comment":
                self._comment(tok, res, acc)
        self._code_params(src, vendor, acc)
        units = [(t.value, t.start, t.end, t.kind) for t in tokens
                 if t.kind in ("str", "tpl", "comment") and len(t.value) >= 8]
        sec, rej = scan_units(units, src, vendor, self.explain)
        for f in sec:
            self._add(acc, f)
        res.rejected += rej
        for ref in resolve_webpack_chunks(src):
            res.js_refs.append(ref)
        res.js_refs = list(dict.fromkeys(res.js_refs))
        res.findings = []
        secret_values = [f.value for f in acc.values() if f.kind == "secret"]
        for f in acc.values():
            f.context = scrub_context(f.context, secret_values)
            f.source = source
            if self.ignore.matches(f):
                self._rej(res, f.kind, f.value, "matched an ignore rule in your config")
            else:
                res.findings.append(f)
        return res

    # ---- helpers
    def _rej(self, res: ExtractResult, kind: str, value: str, reason: str) -> None:
        if self.explain:
            res.rejected.append(Rejection(kind, value[:120], reason))

    @staticmethod
    def _add(acc: dict, f: Finding) -> None:
        key = (f.kind, f.value)
        old = acc.get(key)
        if old is None or f.confidence > old.confidence:
            if old is not None:
                f.meta.setdefault("seen_count", old.meta.get("seen_count", 1) + 1)
            acc[key] = f
        else:
            old.meta["seen_count"] = old.meta.get("seen_count", 1) + 1

    def _comment(self, tok: Tok, res: ExtractResult, acc: dict) -> None:
        m = re.match(r"\s*[#@]\s*sourceMappingURL=(\S+)", tok.value)
        if m:
            url = m.group(1)
            if url.startswith("data:"):
                f = Finding("sourcemap", "inline-sourcemap", 90, "medium", "sourcemap",
                            hint="Inline sourcemap embeds original source", context="//# sourceMappingURL=data:…")
                self._add(acc, f)
            else:
                res.sourcemaps.append(url)
                f = Finding("sourcemap", url, 90, "low", "sourcemap", hint="Sourcemap exposed (original source may be recoverable)",
                            context=f"//# sourceMappingURL={url}")
                f.why.append("sourceMappingURL comment present")
                self._add(acc, f)

    # ---- string literal handling
    def _string(self, tok: Tok, src: str, vendor: bool, acc: dict, res: ExtractResult) -> None:
        v = tok.value.strip()
        if len(v) < 2 or len(v) > 2048:
            return
        ctx = src[max(0, tok.start - 70): tok.start]
        after = src[tok.end: tok.end + 3].lstrip()
        concat = after.startswith("+")

        self._graphql(v, vendor, acc)  # graphql ops can live in any string/template

        if (JS_REF.match(v) and not v.startswith(("http:", "https:")) and (v[0] != "." or v.startswith(("./", "../")))) \
                or (URL_RE.match(v) and re.search(r"\.m?js(\?|$)", v)):
            res.js_refs.append(v)
            return

        if URL_RE.match(v):
            self._url(v, ctx, concat, vendor, acc, res)
            return
        if v.startswith("/") and not v.startswith("//"):
            self._path(v, ctx, concat, vendor, acc, res)
            return
        m = re.match(r"^[?&]([A-Za-z_][\w\-.\[\]]{0,39})=", v)
        if m:
            self._param_from_query(v.lstrip("?&"), "", vendor, acc, base=55)
            return
        if "/" in v and CALL_CTX.search(ctx) and re.match(r"^(?:\.\.?/)?[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-.{}]+)+$", v):
            self._path("/" + v.lstrip("./"), ctx, concat, vendor, acc, res, relative=True)
            return
        bh = BARE_HOST.match(v.lower())
        if bh:
            self._bare_host(bh.group(1), bh.group(2), ctx, vendor, acc, res)

    def _graphql(self, v: str, vendor: bool, acc: dict) -> None:
        if "{" not in v:
            return
        for m in re.finditer(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*[({]", v):
            kind, name = m.group(1), m.group(2)
            f = Finding("graphql", f"{kind} {name}", 75, "medium" if kind == "mutation" else "low", "graphql_operation",
                        hint="GraphQL " + kind, context=re.sub(r"\s+", " ", v[:160]))
            f.why.append("operation definition inside a string/template literal")
            if vendor:
                f.bump(-20, "vendor file")
            self._add(acc, f)

    def _host_ok(self, host: str, res: ExtractResult, raw: str) -> bool:
        if not host or "{" in host or "$" in host:
            return False
        if any(host == n or host.endswith("." + n) for n in self.noise):
            self._rej(res, "host", host, "well-known documentation/CDN/namespace host")
            return False
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        if not HOST_RE.match(host):
            self._rej(res, "host", host, "not a valid hostname")
            return False
        return True

    def _url(self, v: str, ctx: str, concat: bool, vendor: bool, acc: dict, res: ExtractResult) -> None:
        try:
            p = urlsplit(v if not v.startswith("//") else "https:" + v)
            host = norm_host(p.hostname)
        except ValueError:
            return
        dynamic_host = "{" in (p.netloc or "")
        if not dynamic_host and not self._host_ok(host, res, v):
            return
        hostval = host + (f":{p.port}" if p.port and p.port not in (80, 443) else "") if not dynamic_host else ""
        if hostval:
            f = Finding("host", hostval, 70, "low", "host_in_url", hint="Host referenced in JS", context=_ctx(ctx, v))
            f.why.append("host appears in an absolute URL")
            if CLOUD_HOST.search(hostval):
                f.hint = "Cloud storage/DB host: check public access and dangling-bucket takeover (in scope only)"
                f.bump(8, "cloud storage / database host")
            if vendor:
                f.bump(-20, "vendor file")
            self._add(acc, f)
        path = p.path or ""
        if path in ("", "/") and not p.query:
            return
        if path in ("", "/"):
            self._param_from_query(p.query, "", vendor, acc, base=60)
            return
        norm = normalize_path(path + ("/" if concat and path.endswith("/") else ""))
        if concat and path.endswith("/"):
            norm = normalize_path(path + "{expr}")
        if not self._path_ok(norm, res):
            return
        value = (hostval + norm) if hostval else norm
        scheme = (p.scheme or "").lower()
        f = self._endpoint_finding(value, norm, ctx, vendor, "endpoint")
        f.meta["absolute"] = True
        f.meta["host"] = hostval
        if scheme in ("ws", "wss"):
            f.meta["websocket"] = True
            f.hint = "WebSocket endpoint"
        self._add(acc, f)
        if p.query:
            self._param_from_query(p.query, norm, vendor, acc, base=60)

    def _path(self, v: str, ctx: str, concat: bool, vendor: bool, acc: dict, res: ExtractResult, relative: bool = False) -> None:
        if not PATH_ALLOWED.match(v):
            self._rej(res, "endpoint", v, "contains characters not valid in a URL path")
            return
        path, _, rest = v.partition("?")
        path = path.split("#", 1)[0]
        if concat and path.endswith("/"):
            path += "{expr}"
        norm = normalize_path(path)
        if not self._path_ok(norm, res):
            return
        kind = "route" if ROUTE_CTX.search(ctx) and not CALL_CTX.search(ctx) else "endpoint"
        f = self._endpoint_finding(norm, norm, ctx, vendor, kind)
        if relative:
            f.bump(-8, "relative path guessed from call context")
        if rest:
            f.meta["query"] = rest[:120]
            self._param_from_query(rest, norm, vendor, acc, base=60)
        self._add(acc, f)

    def _path_ok(self, norm: str, res: ExtractResult) -> bool:
        if norm in ("/", ""):
            return False
        if len(norm) > 200:
            self._rej(res, "endpoint", norm, "too long")
            return False
        if PATH_NOISE.search(norm):
            self._rej(res, "endpoint", norm, "matches known noise (library/static/system path)")
            return False
        last = norm.rsplit("/", 1)[-1]
        ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
        if ext in STATIC_EXT:
            self._rej(res, "endpoint", norm, f"static asset (.{ext})")
            return False
        if ext in ("js", "mjs"):
            self._rej(res, "endpoint", norm, "JavaScript file (tracked as a file, not an endpoint)")
            return False
        segs = [s for s in norm.split("/") if s]
        if segs and all(DATE_TOKENS.match(s) for s in segs):
            self._rej(res, "endpoint", norm, "looks like a date/time format string")
            return False
        if not re.search(r"[A-Za-z]{2}", norm):
            self._rej(res, "endpoint", norm, "no meaningful letters")
            return False
        if re.fullmatch(r"/(?:\{param\}|\{id\})(?:/.*)?", norm) and len(segs) == 1:
            self._rej(res, "endpoint", norm, "bare dynamic segment")
            return False
        return True

    def _endpoint_finding(self, value: str, norm: str, ctx: str, vendor: bool, kind: str) -> Finding:
        f = Finding(kind, value, 45, "low", "endpoint_literal", hint="API endpoint" if kind == "endpoint" else "Client-side route",
                    context=_ctx(ctx, value))
        m = CALL_CTX.search(ctx)
        if kind == "endpoint":
            if m:
                f.bump(20, "argument of an HTTP call (fetch/axios/XHR)")
                verb = METHOD_FROM_CALL.search(ctx)
                if verb:
                    f.meta["method"] = verb.group(1).upper()
                elif m.group(1):
                    f.meta["method"] = m.group(1)
            elif KEY_CTX.search(ctx):
                f.bump(12, "assigned to a url/endpoint-style key")
        else:
            f.severity = "info"
            f.confidence = 40
        if API_PREFIX.search(norm):
            f.bump(15, "API-style path prefix")
        segs = [s for s in norm.split("/") if s]
        if len(segs) >= 2:
            f.bump(8, "multi-segment path")
        if "{param}" in norm or "{id}" in norm or "{uuid}" in norm:
            f.bump(8, "parameterised REST resource")
        if len(segs) == 1 and not API_PREFIX.search(norm) and not m:
            f.bump(-12, "single generic segment with no call context")
        if STATIC_DIRS.search(norm):
            f.bump(-25, "lives under a static-asset directory")
        if vendor:
            f.bump(-20, "found in vendor/library file")
        if kind == "endpoint":
            if HIGH_PATH.search(norm):
                f.severity = "high" if f.confidence >= 60 else "medium"
                f.hint = "Privileged/internal-looking endpoint"
                f.bump(8, "privileged keyword in path (admin/internal/debug/...)")
            elif RISKY_PATH.search(norm):
                f.severity = "medium"
                f.hint = "Sensitive-function endpoint"
        f.confidence = max(0, min(95, f.confidence))
        return f

    def _bare_host(self, host: str, port: str | None, ctx: str, vendor: bool, acc: dict, res: ExtractResult) -> None:
        tld = host.rsplit(".", 1)[-1]
        if tld not in self.tlds:
            return
        if tld in STATIC_EXT or tld in ("js", "json"):
            return
        if not self._host_ok(host, res, host):
            return
        hv = host + (f":{port}" if port else "")
        f = Finding("host", hv, 55, "low", "host_bare", hint="Hostname literal in JS", context=_ctx(ctx, hv))
        f.why.append("bare hostname literal")
        if re.search(r"(?i)(host|domain|server|origin|base|api|endpoint|url|ws)\w*\s*[:=]\s*$", ctx):
            f.bump(12, "assigned to a host/url-style key")
        if vendor:
            f.bump(-20, "vendor file")
        self._add(acc, f)

    # ---- parameters
    def _param_from_query(self, query: str, endpoint: str, vendor: bool, acc: dict, base: int) -> None:
        for name, _ in parse_qsl(query, keep_blank_values=True):
            self._param(name, endpoint, vendor, acc, base, "query-string parameter in URL literal")

    def _param(self, name: str, endpoint: str, vendor: bool, acc: dict, base: int, why: str) -> None:
        if "{" in name or not PARAM_NAME.match(name):
            return
        if name.lower() in PARAM_NOISE and not param_hint(name):
            return
        h = param_hint(name)
        f = Finding("param", name, base, h[1] if h else "info", "param_literal", hint=h[0] if h else "Parameter")
        f.why.append(why)
        if h:
            f.bump(8, f"name suggests {h[0]}")
        if vendor:
            f.bump(-20, "vendor file")
        if endpoint:
            f.meta["endpoint"] = endpoint
        self._add(acc, f)

    _OBJ_START = re.compile(r"\b(params|query|variables|payload|searchParams|data|body)\s*:\s*(?:JSON\.stringify\()?\{")
    _SP_GET = re.compile(r"""\b(?:searchParams|URLSearchParams\([^)]{0,80}\)|params|query)\.(?:get|has|getAll)\(\s*["']([^"']{1,40})["']""")
    _FD_APPEND = re.compile(r"""\.(?:append|set)\(\s*["']([A-Za-z_][\w\-.\[\]]{0,39})["']\s*,""")
    _KEY = re.compile(r"""(?:^|[,{])\s*(?:([A-Za-z_$][\w$]*)|"([^"\n]{1,40})"|'([^'\n]{1,40})')\s*:""")

    def _code_params(self, src: str, vendor: bool, acc: dict) -> None:
        for m in self._SP_GET.finditer(src):
            self._param(m.group(1), "", vendor, acc, 62, "read via URLSearchParams/params.get()")
        for m in self._FD_APPEND.finditer(src):
            name = m.group(1)
            if param_hint(name):  # generic receivers are too noisy; only keep interesting names
                self._param(name, "", vendor, acc, 48, "FormData/URLSearchParams append/set")
        for m in self._OBJ_START.finditer(src):
            label = m.group(1)
            body = _balanced(src, m.end() - 1, limit=1500)
            if not body:
                continue
            base = 40 if label in ("data", "body", "payload") else 58
            seen = 0
            for km in self._KEY.finditer(_depth1(body)):
                name = km.group(1) or km.group(2) or km.group(3)
                seen += 1
                if seen > 40:
                    break
                self._param(name, "", vendor, acc, base, f"key inside a '{label}: {{…}}' object")


_CHAIN_GAP = re.compile(r"^\s*\+\s*(?:[\w$.]+(?:\[[^\]\n]{0,30}\])?(?:\([^()\n]{0,40}\))?\s*\+\s*)?$")


def join_concatenations(src: str, tokens: list[Tok]) -> list[Tok]:
    """Merge ``"a" + expr + "b"`` chains into one synthetic literal ``a{expr}b``."""
    out: list[Tok] = []
    cur: Tok | None = None
    for tok in tokens:
        if tok.kind in ("str", "tpl"):
            if cur is not None:
                gap = src[cur.end:tok.start]
                if len(gap) <= 80 and _CHAIN_GAP.match(gap):
                    mid = "{expr}" if re.search(r"[\w$]", gap) else ""
                    cur = Tok("tpl" if "tpl" in (cur.kind, tok.kind) else "str", cur.value + mid + tok.value,
                              cur.start, tok.end)
                    continue
                out.append(cur)
            cur = tok
        else:
            if cur is not None:
                out.append(cur)
                cur = None
            out.append(tok)
    if cur is not None:
        out.append(cur)
    return out


def _ctx(ctx: str, value: str) -> str:
    return re.sub(r"\s+", " ", (ctx[-50:] + value))[:160]


def _balanced(src: str, i: int, limit: int) -> str | None:
    """Return text of the {...} block starting at src[i] == '{', or None."""
    depth, j, end = 0, i, min(len(src), i + limit)
    while j < end:
        c = src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1:j]
        elif c in "\"'":
            k = j + 1
            while k < end and src[k] != c:
                k += 2 if src[k] == "\\" else 1
            j = k
        j += 1
    return None


def _depth1(body: str) -> str:
    """Blank out nested {...}/[...]/(...) so only top-level keys of an object literal remain."""
    out, depth, i = [], 0, 0
    while i < len(body):
        c = body[i]
        if c in "\"'":
            k = i + 1
            while k < len(body) and body[k] != c:
                k += 2 if body[k] == "\\" else 1
            if depth == 0:
                out.append(body[i:k + 1])
            i = k + 1
            continue
        if c in "{[(":
            depth += 1
            if depth == 1:
                out.append(" ")
        elif c in "}])":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(c)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------- webpack chunk resolution

_WP_U = re.compile(r"\.u\s*=\s*")
_WP_P = re.compile(r"""\.p\s*=\s*["']([^"']*)["']""")
_OBJ = re.compile(r"\{([^{}]*)\}")
_PAIR = re.compile(r"""(?:"([^"]+)"|'([^']+)'|(\w+))\s*:\s*(?:"([^"]*)"|'([^']*)')""")
_SEG = re.compile(r"""\"([^\"]*)\"|'([^']*)'|(OBJ\d+)|\b([A-Za-z_$][\w$]*)\b""")


def resolve_webpack_chunks(src: str, limit: int = 400) -> list[str]:
    """Best-effort resolution of webpack's runtime chunk-URL function (``__webpack_require__.u``)."""
    refs: list[str] = []
    pm = _WP_P.search(src)
    public = pm.group(1) if pm else ""
    for m in _WP_U.finditer(src):
        seg = src[m.end(): m.end() + 6000]
        cut = seg.find(";")
        if cut != -1:
            seg = seg[:cut]
        seg = re.sub(r"^(?:\(?\w+\)?\s*=>|function\s*\(\s*\w+\s*\)\s*\{\s*return)\s*", "", seg).rstrip("} ,")
        objs = []

        def stash(mo: re.Match) -> str:
            objs.append({(a or b or c): (d if d is not None else e) for a, b, c, d, e in _PAIR.findall(mo.group(1))})
            return f"OBJ{len(objs) - 1}"

        flat = re.sub(r"(OBJ\d+)\s*\[\s*\w+\s*\]", r"\1", _OBJ.sub(stash, seg))  # drop the "[e]" index, keep the lookup
        if not objs or not objs[-1]:
            continue
        hashes = objs[-1]
        parts = [(a or b, o, i) for a, b, o, i in _SEG.findall(flat)]
        for cid in list(hashes)[:limit]:
            url, ok = "", True
            for lit, obj, ident in parts:
                if obj:
                    mp = objs[int(obj[3:])]
                    if mp is hashes:
                        if cid not in mp:
                            ok = False
                            break
                        url += mp[cid]
                    else:
                        url += mp.get(cid, cid)
                elif ident:
                    url += cid
                else:
                    url += lit
            if ok and url.endswith(".js") and "undefined" not in url:
                refs.append(public + url if not url.startswith(("/", "http")) else url)
    return refs
