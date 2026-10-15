"""Scan orchestration and the drift/diff logic.

Core idea: a finding is identified by a content fingerprint (not by the file it came from), and it
is linked to the logical files that contain it. After every scan:

    new       = fingerprint never seen for this target
    reappeared= was removed earlier, present again
    removed   = active finding that no longer has *any* file containing it

Files that failed to download keep their previous links, so a flaky CDN can never produce fake
"removed" or "new" noise. Files whose content hash did not change are not re-analysed at all.
"""
from __future__ import annotations

import json
import zlib
from dataclasses import dataclass, field
from typing import Callable

from . import ANALYZER_VERSION
from .config import TargetConfig
from .crawler import CrawlResult, Crawler
from .extract import Extractor
from .fetcher import Fetcher
from .models import Finding
from .store import Store, utcnow

MAX_STORED_VERSION = 25 * 1024 * 1024


class ScanError(RuntimeError):
    pass


@dataclass
class ScanResult:
    target: str
    run_id: int
    baseline: bool
    status: str
    stats: dict = field(default_factory=dict)
    crawl: CrawlResult | None = None


def make_extractor(t: TargetConfig, explain: bool = False) -> Extractor:
    return Extractor(noise_hosts=t.noise_hosts, ignore=t.ignore, explain=explain)


def scan_target(store: Store, t: TargetConfig, log: Callable[[str], None] = print,
                fetcher: Fetcher | None = None) -> ScanResult:
    run_id, baseline = store.start_run(t.name)
    log(f"[{t.name}] run #{run_id} {'(baseline: first scan, nothing is reported as new)' if baseline else ''}")
    f = fetcher or Fetcher(t.scope, headers=t.headers, user_agent=t.user_agent, delay=t.delay, timeout=t.timeout,
                           max_bytes=int(t.max_file_mb * 1024 * 1024), proxy=t.proxy, verify_tls=t.verify_tls,
                           trust_env=t.trust_env)
    try:
        crawl = Crawler(t, f, make_extractor(t), cache=lambda k: store.cache_lookup(t.name, k, ANALYZER_VERSION), log=log).run()
    except Exception as e:  # noqa: BLE001
        store.finish_run(run_id, "failed", {"error": f"{type(e).__name__}: {e}"})
        raise
    # A seed that the scope guard rejected is a configuration mistake: fail loudly, never silently "succeed".
    seed_blocked = [s for s in t.seeds if s.split("#")[0] in crawl.blocked]
    n_js = sum(1 for x in crawl.files.values() if x.kind in ("js", "inline"))
    if seed_blocked and not crawl.pages:
        store.finish_run(run_id, "failed", {"error": "all seed URLs rejected by scope", "blocked": crawl.blocked})
        raise ScanError("seed URL rejected by scope guard: " + "; ".join(f"{u} ({crawl.blocked[u]})" for u in seed_blocked))
    if not crawl.pages and n_js == 0:
        err = "; ".join(f"{u}: {e}" for u, e in crawl.failed[:3]) or "no pages or scripts could be fetched"
        store.finish_run(run_id, "failed", {"error": err})
        raise ScanError(f"nothing could be fetched for '{t.name}': {err}")
    stats = reconcile(store, t, run_id, crawl)
    stats["requests"], stats["bytes"] = f.requests, f.bytes
    stats["crawl"] = {
        "pages": crawl.pages, "complete": crawl.complete, "aborted": crawl.aborted, "limited": crawl.limited,
        "failed": crawl.failed[:30], "skipped": crawl.skipped[:30],
        "blocked": dict(list(crawl.blocked.items())[:30]), "third_party": list(crawl.third_party)[:60],
        "n_third_party": len(crawl.third_party), "n_blocked": len(crawl.blocked),
    }
    status = "ok" if crawl.complete else "partial"
    store.finish_run(run_id, status, stats)
    return ScanResult(t.name, run_id, baseline, status, stats, crawl)


# ---------------------------------------------------------------------------------------------- reconcile

def _best(findings: list[Finding]) -> dict[str, Finding]:
    out: dict[str, Finding] = {}
    for f in findings:
        old = out.get(f.fingerprint)
        if old is None or f.confidence > old.confidence:
            out[f.fingerprint] = f
    return out


def reconcile(store: Store, t: TargetConfig, run_id: int, crawl: CrawlResult) -> dict:
    c = store.conn
    now = utcnow()
    stats = {"files": {"total": 0, "analyzed": 0, "carried": 0, "added": 0, "changed": 0, "removed": 0},
             "findings": {"added": 0, "reappeared": 0, "removed": 0}}

    def ev(typ: str, finding_id: int | None = None, fkey: str | None = None, detail: dict | None = None) -> None:
        c.execute("INSERT INTO events(run_id,target,type,finding_id,fkey,detail,ts) VALUES (?,?,?,?,?,?,?)",
                  (run_id, t.name, typ, finding_id, fkey, json.dumps(detail or {}), now))

    with c:
        carried_keys: list[str] = []
        for sf in crawl.files.values():
            stats["files"]["total"] += 1
            row = c.execute("SELECT * FROM files WHERE target=? AND fkey=?", (t.name, sf.key)).fetchone()
            if sf.carried:
                if row is not None:
                    c.execute("UPDATE files SET last_run=?, state='active' WHERE id=?", (run_id, row["id"]))
                    carried_keys.append(sf.key)
                    stats["files"]["carried"] += 1
                continue
            if sf.analysis is None:
                continue
            stats["files"]["analyzed"] += 1
            new = _best(sf.analysis.findings)
            visible = sf.kind == "js"
            if row is None:
                cur = c.execute(
                    "INSERT INTO files(target,fkey,url,kind,parent,sha,size,first_run,last_run,changed_run,analyzer,refs,maps) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (t.name, sf.key, sf.url, sf.kind, sf.parent, sf.sha, sf.size, run_id, run_id, run_id, ANALYZER_VERSION,
                     json.dumps(sf.refs), json.dumps(sf.maps)))
                file_id, old_fps, changed = cur.lastrowid, set(), True
                if visible:
                    stats["files"]["added"] += 1
                    ev("file_added", fkey=sf.key, detail={"url": sf.url, "size": sf.size, "kind": sf.kind})
            else:
                file_id = row["id"]
                old_fps = {r[0] for r in c.execute(
                    "SELECT f.fp FROM findings f JOIN finding_sources s ON s.finding_id=f.id WHERE s.target=? AND s.fkey=?",
                    (t.name, sf.key))}
                changed = row["sha"] != sf.sha
                c.execute("UPDATE files SET url=?, kind=?, parent=?, sha=?, size=?, state='active', last_run=?, "
                          "changed_run=CASE WHEN ? THEN ? ELSE changed_run END, analyzer=?, refs=?, maps=? WHERE id=?",
                          (sf.url, sf.kind, sf.parent, sf.sha, sf.size, run_id, int(changed), run_id, ANALYZER_VERSION,
                           json.dumps(sf.refs), json.dumps(sf.maps), file_id))
                if row["state"] == "gone" and visible:
                    stats["files"]["added"] += 1
                    ev("file_added", fkey=sf.key, detail={"url": sf.url, "size": sf.size, "kind": sf.kind, "reappeared": True})
            if changed and t.store_content and sf.store and sf.text is not None and len(sf.text) <= MAX_STORED_VERSION:
                c.execute("INSERT OR IGNORE INTO versions(file_id,run_id,sha,size,url,content) VALUES (?,?,?,?,?,?)",
                          (file_id, run_id, sf.sha, sf.size, sf.url, zlib.compress(sf.text.encode("utf-8", "replace"), 6)))
            c.execute("DELETE FROM finding_sources WHERE target=? AND fkey=?", (t.name, sf.key))
            for fp, f in new.items():
                fr = c.execute("SELECT id, state, confidence FROM findings WHERE target=? AND fp=?", (t.name, fp)).fetchone()
                if fr is None:
                    cur = c.execute(
                        "INSERT INTO findings(target,fp,kind,value,rule,severity,confidence,hint,context,meta,why,first_run,"
                        "last_run,first_source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (t.name, fp, f.kind, f.value, f.rule, f.severity, f.confidence, f.hint, f.context,
                         json.dumps(f.meta, default=str), json.dumps(f.why), run_id, run_id, sf.key))
                    fid = cur.lastrowid
                    stats["findings"]["added"] += 1
                    ev("finding_added", fid, sf.key)
                else:
                    fid = fr["id"]
                    c.execute("UPDATE findings SET last_run=? WHERE id=?", (run_id, fid))
                    if f.confidence > fr["confidence"]:
                        c.execute("UPDATE findings SET confidence=?, severity=?, hint=?, context=?, meta=?, why=? WHERE id=?",
                                  (f.confidence, f.severity, f.hint, f.context, json.dumps(f.meta, default=str),
                                   json.dumps(f.why), fid))
                    if fr["state"] == "removed":
                        c.execute("UPDATE findings SET state='active' WHERE id=?", (fid,))
                        stats["findings"]["reappeared"] += 1
                        ev("finding_reappeared", fid, sf.key)
                c.execute("INSERT OR IGNORE INTO finding_sources(finding_id,target,fkey) VALUES (?,?,?)", (fid, t.name, sf.key))
            if row is not None and changed and visible:
                stats["files"]["changed"] += 1
                ev("file_changed", fkey=sf.key, detail={
                    "old_sha": row["sha"][:12], "new_sha": sf.sha[:12], "old_size": row["size"], "new_size": sf.size,
                    "findings_added": len(set(new) - old_fps), "findings_removed": len(old_fps - set(new))})

        # findings from unchanged files are still "seen this run"
        for k in carried_keys:
            c.execute("UPDATE findings SET last_run=? WHERE id IN (SELECT finding_id FROM finding_sources WHERE target=? AND fkey=?)",
                      (run_id, t.name, k))

        # files that were not encountered: gone - but only if the crawl was complete enough to trust that
        if crawl.complete:
            seen = set(crawl.files)
            for row in c.execute("SELECT * FROM files WHERE target=? AND state='active'", (t.name,)).fetchall():
                if row["fkey"] in seen:
                    continue
                c.execute("UPDATE files SET state='gone' WHERE id=?", (row["id"],))
                c.execute("DELETE FROM finding_sources WHERE target=? AND fkey=?", (t.name, row["fkey"]))
                if row["kind"] == "js":
                    stats["files"]["removed"] += 1
                    ev("file_removed", fkey=row["fkey"], detail={"url": row["url"], "kind": row["kind"]})

        # findings with no remaining file -> removed
        for r in c.execute("SELECT f.id FROM findings f WHERE f.target=? AND f.state='active' AND NOT EXISTS "
                           "(SELECT 1 FROM finding_sources s WHERE s.finding_id=f.id)", (t.name,)).fetchall():
            c.execute("UPDATE findings SET state='removed' WHERE id=?", (r["id"],))
            stats["findings"]["removed"] += 1
            ev("finding_removed", r["id"])
    # free memory held by downloaded sources
    for sf in crawl.files.values():
        sf.text = None
    return stats
