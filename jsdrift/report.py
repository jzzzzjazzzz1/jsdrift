"""Turn a run's events into a prioritised report (text / markdown / JSON)."""
from __future__ import annotations

import json
from collections import Counter

from .models import SEV_RANK, mask
from .store import Store

_BUCKET = {"finding_added": "new", "finding_reappeared": "reappeared", "finding_removed": "removed"}
SEV_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}
_COLOR = {"critical": "\x1b[1;37;41m", "high": "\x1b[1;31m", "medium": "\x1b[33m", "low": "\x1b[36m", "info": "\x1b[2m"}
_RESET = "\x1b[0m"


def finding_view(f: dict, reveal: bool = False) -> dict:
    d = {k: f[k] for k in ("id", "fp", "kind", "rule", "severity", "confidence", "hint", "context", "why", "meta",
                           "sources", "triage", "state", "first_run", "last_run", "note")}
    d["value"] = f["value"] if (reveal or f["kind"] != "secret") else mask(f["value"])
    return d


def build_report(store: Store, run_id: int, min_conf: int = 0, min_sev: str = "info", reveal: bool = False,
                 include_fp: bool = False) -> dict:
    run = store.run(run_id)
    if run is None:
        raise KeyError(f"run {run_id} not found")
    floor = SEV_RANK.get(min_sev, 0)
    buckets: dict[str, list] = {"new": [], "reappeared": [], "removed": []}
    files: dict[str, list] = {"added": [], "changed": [], "removed": []}
    hidden: Counter = Counter()
    for e in store.events(run_id):
        if e["type"] in _BUCKET:
            f = store.finding(e["finding_id"])
            if f is None:
                continue
            if f["triage"] == "false_positive" and not include_fp:
                hidden["false_positive"] += 1
                continue
            if f["confidence"] < min_conf or SEV_RANK.get(f["severity"], 0) < floor:
                hidden["below_threshold"] += 1
                continue
            v = finding_view(f, reveal)
            v["found_in"] = e["fkey"] or (f["sources"][0] if f["sources"] else f["first_source"])
            buckets[_BUCKET[e["type"]]].append(v)
        elif e["type"].startswith("file_"):
            files[e["type"][5:]].append({"file": e["fkey"], **e["detail"]})
    for lst in buckets.values():
        lst.sort(key=lambda v: (-SEV_RANK.get(v["severity"], 0), -v["confidence"], v["kind"], v["value"]))
    return {
        "target": run["target"],
        "run": {k: run[k] for k in ("id", "started", "finished", "status", "baseline")},
        "stats": run["stats"],
        "thresholds": {"min_confidence": min_conf, "min_severity": min_sev},
        "hidden": dict(hidden), **buckets, "files": files,
        "totals": store.counts(run["target"]),
    }


def alert_items(rep: dict) -> list[dict]:
    """What is worth pinging a human about: new + reappeared, above thresholds, never on a baseline run."""
    if rep["run"]["baseline"]:
        return []
    return rep["new"] + rep["reappeared"]


# ---------------------------------------------------------------------------------------------- text

def _c(s: str, sev: str, color: bool) -> str:
    return f"{_COLOR[sev]}{s}{_RESET}" if color else s


def render_text(rep: dict, color: bool = False, verbose: bool = False, limit: int = 40) -> str:
    run, st = rep["run"], rep["stats"]
    L: list[str] = []
    L.append(f"jsdrift | {rep['target']} | run #{run['id']} | {run['status']}"
             + (" | BASELINE (first scan: everything is new, nothing is alerted)" if run["baseline"] else ""))
    fs, fi = st.get("files", {}), st.get("findings", {})
    L.append(f"files: {fs.get('total', 0)} seen, {fs.get('analyzed', 0)} analysed, {fs.get('carried', 0)} unchanged | "
             f"+{fs.get('added', 0)} new, ~{fs.get('changed', 0)} changed, -{fs.get('removed', 0)} gone | "
             f"requests: {st.get('requests', 0)}")
    cr = st.get("crawl", {})
    if cr.get("n_third_party") or cr.get("n_blocked"):
        L.append(f"scope guard: skipped {cr.get('n_third_party', 0)} out-of-scope script URLs, "
                 f"blocked {cr.get('n_blocked', 0)} other requests (none were sent)")
    if not cr.get("complete", True):
        why = cr.get("aborted") or ("file limit reached" if cr.get("limited") else f"{len(cr.get('failed', []))} fetch failure(s)")
        L.append(f"WARNING partial scan ({why}): removals are not reported, previous findings kept")
        for u, e in cr.get("failed", [])[:5]:
            L.append(f"    ! {u}: {e}")
    L.append("")
    shown = False
    for title, key in (("NEW", "new"), ("REAPPEARED", "reappeared"), ("REMOVED", "removed")):
        items = rep[key]
        if not items:
            continue
        shown = True
        L.append(f"== {title} ({len(items)}) ==")
        for v in items[:limit]:
            tag = _c(f"[{SEV_TAG[v['severity']]}]", v["severity"], color)
            L.append(f"{tag} {v['kind']:<9} {v['value']}")
            L.append(f"       conf {v['confidence']} | {v['rule']} | in {_short(v['found_in'])}"
                     + (f" | {v['hint']}" if v["hint"] else ""))
            if verbose:
                for w in v["why"]:
                    L.append(f"         - {w}")
                if v["context"]:
                    L.append(f"         ctx: {v['context']}")
        if len(items) > limit:
            L.append(f"   ... and {len(items) - limit} more (use `jsdrift findings` or the dashboard)")
        L.append("")
    fl = rep["files"]
    for title, key in (("NEW JS FILES", "added"), ("CHANGED JS FILES", "changed"), ("JS FILES GONE", "removed")):
        if fl[key]:
            shown = True
            L.append(f"== {title} ({len(fl[key])}) ==")
            for x in fl[key][:limit]:
                extra = ""
                if key == "changed":
                    extra = f"  (+{x['findings_added']}/-{x['findings_removed']} findings, {x['old_size']}->{x['new_size']} bytes)"
                L.append(f"   {_short(x['file'])}{extra}")
            L.append("")
    if not shown:
        L.append("No drift: nothing new above the thresholds.")
    h = rep["hidden"]
    if h:
        L.append(f"(hidden: {h.get('below_threshold', 0)} below confidence/severity thresholds "
                 f"[{rep['thresholds']['min_confidence']}/{rep['thresholds']['min_severity']}], "
                 f"{h.get('false_positive', 0)} triaged as false positive)")
    return "\n".join(L)


def _short(key: str, n: int = 90) -> str:
    return key if len(key) <= n else "…" + key[-(n - 1):]


# ---------------------------------------------------------------------------------------------- markdown

def render_markdown(rep: dict) -> str:
    run = rep["run"]
    out = [f"# jsdrift report: {rep['target']}", "",
           f"- run **#{run['id']}**, status `{run['status']}`, started {run['started']}",
           f"- baseline run: {'yes (first scan)' if run['baseline'] else 'no'}",
           f"- thresholds: confidence >= {rep['thresholds']['min_confidence']}, severity >= {rep['thresholds']['min_severity']}", ""]
    for title, key in (("New findings", "new"), ("Reappeared", "reappeared"), ("Removed", "removed")):
        items = rep[key]
        out.append(f"## {title} ({len(items)})")
        out.append("")
        if not items:
            out += ["_none_", ""]
            continue
        for v in items:
            val = v["value"].replace("`", "'")
            out.append(f"### [{v['severity'].upper()}] `{v['kind']}` `{val}`")
            out.append(f"- confidence **{v['confidence']}**, rule `{v['rule']}`, triage `{v['triage']}`, fingerprint `{v['fp']}`")
            out.append(f"- found in `{v['found_in']}`")
            if v["hint"]:
                out.append(f"- {v['hint']}")
            for w in v["why"]:
                out.append(f"  - {w}")
            if v["meta"].get("note"):
                out.append(f"- note: {v['meta']['note']}")
            if v["context"]:
                out.append(f"- context: `{v['context'].replace('`', chr(39))}`")
            out.append("")
    for title, key in (("New JS files", "added"), ("Changed JS files", "changed"), ("JS files gone", "removed")):
        if rep["files"][key]:
            out += [f"## {title}", ""] + [f"- `{x['file']}`" for x in rep["files"][key]] + [""]
    return "\n".join(out)


def render_json(rep: dict) -> str:
    return json.dumps(rep, indent=2, default=str)
