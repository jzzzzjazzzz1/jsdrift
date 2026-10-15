"""Discovery: seed pages -> script tags -> lazy chunks -> sourcemaps -> original sources.

Everything fetched goes through the scope-guarded Fetcher. Files are identified by
``identity_key`` (hash-normalised URL) so a re-deploy that only renames ``main.3f9a.js`` to
``main.81bc.js`` is one file with a new version, not "one removed + one added".
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

from .config import TargetConfig
from .extract import HIGH_PATH, RISKY_PATH, ExtractResult, Extractor
from .fetcher import Fetcher, Response
from .models import Finding
from .util import identity_key

MAX_MAP_BYTES = 40 * 1024 * 1024
MAX_MAP_TEXT_TOTAL = 20 * 1024 * 1024
SPECULATIVE_BUDGET = 60


@dataclass
class SrcFile:
    key: str
    url: str
    kind: str                      # js | inline | map | map-source
    sha: str
    size: int
    parent: str = ""
    text: str | None = None
    analysis: ExtractResult | None = None
    carried: bool = False          # unchanged since last scan: findings carried forward, not re-analysed
    refs: list[str] = field(default_factory=list)
    maps: list[str] = field(default_factory=list)
    vendor: bool = False
    store: bool = True


@dataclass
class CrawlResult:
    files: dict[str, SrcFile] = field(default_factory=dict)
    pages: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    blocked: dict[str, str] = field(default_factory=dict)
    third_party: dict[str, str] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    limited: bool = False
    aborted: str = ""

    @property
    def complete(self) -> bool:
        """True only if nothing went wrong, so 'not seen' can safely be read as 'gone'."""
        return not self.failed and not self.limited and not self.aborted


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.inline: list[tuple[str, str]] = []
        self.base: str | None = None
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "base" and a.get("href") and self.base is None:
            self.base = a["href"]
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
                self._cur = None
            else:
                self._cur = {"type": a.get("type", "").lower(), "buf": []}
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "modulepreload" in rel or ("preload" in rel and a.get("as") == "script") or \
                    ("prefetch" in rel and a.get("as") == "script"):
                self.scripts.append(a["href"])

    def handle_data(self, data):
        if self._cur is not None:
            self._cur["buf"].append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._cur is not None:
            self.inline.append((self._cur["type"], "".join(self._cur["buf"])))
            self._cur = None


_SKIP_INLINE_TYPES = ("text/template", "text/x-template", "text/html", "text/ng-template", "application/ld+json",
                      "speculationrules", "text/x-handlebars-template")


def _sha(s: str | bytes) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace") if isinstance(s, str) else s).hexdigest()


def resolve_ref(ref: str, file_url: str, page_url: str) -> list[tuple[str, bool]]:
    """Turn a JS-literal reference into candidate URLs. Bool = speculative (a guess; 404 is expected)."""
    ref = ref.strip()
    if not ref or "{" in ref or "undefined" in ref or len(ref) > 300:
        return []
    if ref.startswith(("http://", "https://")):
        return [(ref, False)]
    fp = urlsplit(file_url)
    if ref.startswith("//"):
        return [(f"{fp.scheme}:{ref}", False)]
    if ref.startswith(("/", "./", "../")):
        return [(urljoin(file_url, ref), False)]
    out: list[tuple[str, bool]] = []
    m = re.search(r"/static/", fp.path)
    if ref.startswith("static/") and m:  # Next.js / CRA: ref is relative to the dir *above* /static/
        out.append((f"{fp.scheme}://{fp.netloc}{fp.path[:m.start() + 1]}{ref}", True))
    out.append((urljoin(file_url, ref), True))
    if page_url:
        out.append((urljoin(page_url, ref), True))
    return list(dict.fromkeys(out))


def clean_source_path(p: str) -> str:
    p = re.sub(r"^(?:webpack(?:-internal)?://[^/]*/|webpack:///|file:///|ng:///|vite://)", "", p)
    p = p.split("?", 1)[0]
    while p.startswith(("./", "../")):
        p = p.split("/", 1)[1]
    return p.lstrip("/")


class Crawler:
    def __init__(self, target: TargetConfig, fetcher: Fetcher, extractor: Extractor,
                 cache: Callable[[str], dict | None] | None = None, log: Callable[[str], None] = lambda s: None):
        self.t, self.f, self.x = target, fetcher, extractor
        self.cache = cache or (lambda key: None)
        self.log = log
        self.vendor_re = target.vendor_re()
        self.res = CrawlResult()
        self._seen_urls: set[str] = set()
        self._spec_used = 0

    # ------------------------------------------------------------------ main loop
    def run(self) -> CrawlResult:
        queue: deque = deque()
        for s in self.t.seeds:
            queue.append((s, 0, "", "page", False))
        for u in self.t.extra_js:
            queue.append((u, 1, "", "js", False))
        with ThreadPoolExecutor(max_workers=max(1, self.t.threads)) as pool:
            while queue:
                batch = []
                while queue:
                    item = queue.popleft()
                    url = item[0].split("#", 1)[0]
                    if url in self._seen_urls:
                        continue
                    if item[4]:
                        if self._spec_used >= SPECULATIVE_BUDGET:
                            continue
                        self._spec_used += 1
                    self._seen_urls.add(url)
                    d = self.t.scope.check(url)
                    if not d:
                        (self.res.third_party if item[3] == "js" else self.res.blocked)[url] = d.reason
                        continue
                    batch.append((url, *item[1:]))
                if not batch:
                    break
                if self.f.aborted:
                    self.res.aborted = "server throttling (429/503)"
                    break
                responses = list(pool.map(lambda it: self.f.get(it[0]), batch))
                for item, resp in zip(batch, responses):
                    self._handle(item, resp, queue)
                    if len([f for f in self.res.files.values() if f.kind in ("js", "inline")]) >= self.t.max_files:
                        self.res.limited = True
                        queue.clear()
                        break
        self.res.blocked.update(self.f.blocked)
        if self.f.aborted and not self.res.aborted:
            self.res.aborted = "server throttling (429/503)"
        return self.res

    # ------------------------------------------------------------------ per-response handling
    def _handle(self, item, resp: Response, queue: deque) -> None:
        url, depth, referrer, hint, speculative = item
        if resp.blocked:
            self.res.blocked[url] = resp.error
            return
        if resp.too_large:
            self.res.skipped.append((url, resp.error))
            self.res.failed.append((url, resp.error))
            return
        if resp.status == 404 or (resp.status == 0 and not resp.error):
            if not speculative and hint == "js":
                self.res.skipped.append((url, "404 Not Found"))
            elif not speculative:
                self.res.failed.append((url, "404 Not Found"))
            return
        if not resp.ok:
            if not speculative:
                self.res.failed.append((url, resp.error or f"HTTP {resp.status}"))
            return
        base = resp.final_url or url
        text = resp.text
        ct = resp.headers.get("content-type", "").lower()
        looks_html = text.lstrip()[:300].lower().startswith(("<!doctype", "<html", "<head", "<body", "<script", "<?xml"))
        is_js = hint == "js" or urlsplit(base).path.lower().endswith((".js", ".mjs")) or "javascript" in ct or "ecmascript" in ct
        if is_js and looks_html and "javascript" not in ct:
            # SPA servers answer unknown paths with index.html (200). That is not a script.
            self.res.skipped.append((url, "HTML returned instead of JavaScript (not a real script)"))
            return
        if looks_html or (hint == "page" and not is_js):
            self._handle_page(base, text, depth, queue)
        elif is_js or "json" in ct:
            self._handle_js(base, text, depth, referrer, queue, resp)

    def _handle_page(self, page_url: str, html: str, depth: int, queue: deque) -> None:
        self.res.pages.append(page_url)
        p = _Page()
        try:
            p.feed(html)
            p.close()
        except Exception as e:  # noqa: BLE001 - broken HTML must not kill the scan
            self.log(f"  html parse warning for {page_url}: {e}")
        base = urljoin(page_url, p.base) if p.base else page_url
        for src in p.scripts:
            queue.append((urljoin(base, src), depth + 1, page_url, "js", False))
        idx = 0
        for typ, body in p.inline:
            if typ == "importmap":
                try:
                    for v in (json.loads(body).get("imports") or {}).values():
                        if isinstance(v, str):
                            queue.append((urljoin(base, v), depth + 1, page_url, "js", False))
                except (ValueError, AttributeError):
                    pass
                continue
            if typ.startswith(_SKIP_INLINE_TYPES) or len(body.strip()) < 20:
                continue
            idx += 1
            key = identity_key(page_url) + f"#inline-{idx}"
            self._register_js(key, f"{page_url}#inline-{idx}", "inline", body, "", depth, page_url, queue)

    def _handle_js(self, url: str, text: str, depth: int, referrer: str, queue: deque, resp: Response) -> None:
        key = self._unique_key(identity_key(url), url)
        sm_header = resp.headers.get("sourcemap") or resp.headers.get("x-sourcemap")
        self._register_js(key, url, "js", text, sm_header or "", depth, referrer, queue)

    def _unique_key(self, key: str, url: str) -> str:
        n, k = 1, key
        while k in self.res.files and self.res.files[k].url != url:
            n += 1
            k = f"{key}~{n}"
        return k

    # ------------------------------------------------------------------ registering + analysing a JS file
    def _register_js(self, key: str, url: str, kind: str, text: str, sm_header: str, depth: int,
                     referrer: str, queue: deque) -> None:
        if key in self.res.files:
            return
        sha = _sha(text)
        vendor = bool(self.vendor_re.search(urlsplit(url).path)) if kind == "js" else False
        sf = SrcFile(key, url, kind, sha, len(text.encode("utf-8", "replace")), text=text, vendor=vendor)
        self.res.files[key] = sf
        cached = self.cache(key)
        if cached and cached.get("sha") == sha and (not cached.get("maps") or cached.get("children")):
            sf.carried = True
            sf.refs, sf.maps = list(cached.get("refs", [])), list(cached.get("maps", []))
            for ck in cached.get("children", []):
                self.res.files.setdefault(ck, SrcFile(ck, "", "map-source", "", 0, parent=key, carried=True, store=False))
        else:
            sf.analysis = self.x.run(text, source=key, vendor=vendor)
            sf.refs = list(sf.analysis.js_refs)
            sf.maps = list(sf.analysis.sourcemaps)
            if sm_header and sm_header not in sf.maps:
                sf.maps.append(sm_header)
            # sourcemap findings are re-created below, *verified* (a comment pointing at a 404 is not a finding)
            sf.analysis.findings = [f for f in sf.analysis.findings
                                    if not (f.kind == "sourcemap" and f.value != "inline-sourcemap")]
            if self.t.sourcemaps:
                for ref in sf.maps[:2]:
                    self._load_map(sf, ref)
                if kind == "js" and not sf.maps:
                    inline = re.search(r"sourceMappingURL=(data:application/json[^\s\"']+)", text[-400_000:])
                    if inline:
                        self._load_map(sf, inline.group(1))
        # follow references found inside this file
        if depth < self.t.max_depth and kind in ("js", "inline"):
            for ref in sf.refs:
                for cand, spec in resolve_ref(ref, url.split("#", 1)[0], referrer):
                    queue.append((cand, depth + 1, url, "js", spec))

    # ------------------------------------------------------------------ sourcemaps
    def _load_map(self, parent: SrcFile, ref: str) -> None:
        if ref.startswith("data:"):
            m = re.match(r"data:[^,]*;base64,(.+)", ref, re.S)
            if not m:
                return
            try:
                raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
            except ValueError:
                return
            map_url = parent.url.split("#", 1)[0] + "#inline-map"
        else:
            map_url = urljoin(parent.url.split("#", 1)[0], ref)
            if not self.t.scope.check(map_url):
                self.res.third_party[map_url] = "sourcemap host out of scope"
                return
            r = self.f.get(map_url, max_bytes=MAX_MAP_BYTES)
            if r.blocked:
                self.res.blocked[map_url] = r.error
                return
            if r.too_large:
                self.res.skipped.append((map_url, r.error))
                return
            if not r.ok:
                if r.status not in (401, 403, 404, 410):  # 404/403 = not exposed (boring); anything else = unknown
                    self.res.failed.append((map_url, r.error or f"HTTP {r.status}"))
                return
            raw = r.body
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return
        if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
            return
        sources: list = data["sources"]
        contents: list = data.get("sourcesContent") or []
        mkey = identity_key(map_url) if not ref.startswith("data:") else parent.key + "#inline-map"
        n_content = sum(1 for c in contents if isinstance(c, str))
        mf = SrcFile(mkey, map_url, "map", _sha(raw), len(raw), parent=parent.key, store=False)
        mres = ExtractResult()
        f = Finding("sourcemap", mkey, 95, "medium" if n_content else "low", "sourcemap_exposed",
                    hint=f"Sourcemap is publicly fetchable: {len(sources)} source files listed, "
                         f"{n_content} with embedded original code",
                    context=f"sourceMappingURL -> {map_url}", source=mkey)
        f.why.append("map URL returned 200 and parsed as a v3 sourcemap")
        f.meta.update({"sources": len(sources), "with_content": n_content, "map_url": map_url})
        mres.findings.append(f)
        total, taken = 0, 0
        for i, src in enumerate(sources):
            if not isinstance(src, str):
                continue
            path = clean_source_path(src)
            if not path or path.startswith(("webpack/", "(webpack)", "external ")) or "/webpack/bootstrap" in path:
                continue
            if "node_modules" in path and not self.t.map_node_modules:
                continue
            if taken >= self.t.max_map_sources:
                break
            sev, hint, conf = "info", "Original source file listed in sourcemap", 65
            if HIGH_PATH.search("/" + path):
                sev, hint, conf = "medium", "Privileged-looking source module (admin/internal/debug/...)", 75
            elif RISKY_PATH.search("/" + path):
                sev, hint, conf = "low", "Sensitive-function source module", 70
            sf = Finding("sourcefile", path, conf, sev, "sourcemap_source", hint=hint, source=mkey)
            sf.why.append("path listed in an exposed sourcemap")
            mres.findings.append(sf)
            taken += 1
            code = contents[i] if i < len(contents) else None
            if isinstance(code, str) and code.strip() and total + len(code) <= MAX_MAP_TEXT_TOTAL:
                total += len(code)
                skey = f"{mkey}::{path}"
                child = SrcFile(skey, f"{map_url}::{path}", "map-source", _sha(code), len(code.encode("utf-8", "replace")),
                                parent=mkey, text=code)
                cached = self.cache(skey)
                if cached and cached.get("sha") == child.sha:
                    child.carried = True
                else:
                    child.analysis = self.x.run(code, source=skey, vendor=False)
                self.res.files[skey] = child
        mf.analysis = mres
        self.res.files[mkey] = mf
