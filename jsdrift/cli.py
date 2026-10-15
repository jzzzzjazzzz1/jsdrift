"""Command line interface."""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

from . import __version__
from .config import EXAMPLE_CONFIG, Config, ConfigError, TargetConfig, load_config, quick_target
from .difftools import diff_texts
from .engine import ScanError, make_extractor, scan_target
from .models import SEV_RANK, mask
from .notify import send_alerts
from .report import SEV_TAG, alert_items, build_report, render_json, render_markdown, render_text
from .store import TRIAGE, Store

BANNER = "jsdrift: only scan assets you are authorised to test (bug bounty scope / written permission)."


def _color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _load(a, need_targets: bool = True) -> Config | None:
    path = a.config
    if Path(path).exists():
        return load_config(path)
    if need_targets:
        return None
    return None


def _db(a, cfg: Config | None) -> str:
    return a.db or (cfg.db if cfg else "jsdrift.db")


def _store(a) -> tuple[Store, Config | None]:
    cfg = _load(a, need_targets=False)
    path = _db(a, cfg)
    if not Path(path).exists():
        raise ConfigError(f"database not found: {path} (run a scan first, or pass --db)")
    return Store(path), cfg


# ---------------------------------------------------------------------------------------------- commands

def cmd_init(a) -> int:
    p = Path(a.path)
    if p.exists() and not a.force:
        print(f"{p} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    p.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    print(f"wrote {p}: edit seeds and scope, then run `jsdrift scan`")
    return 0


def _targets_from_args(a) -> tuple[Config, list[TargetConfig]]:
    if a.url:
        t = quick_target(a.url, a.scope or None, a.exclude or None, delay=a.delay, threads=a.threads,
                         **({"headers": dict(h.split(":", 1) for h in a.header)} if a.header else {}),
                         **({"proxy": a.proxy} if a.proxy else {}), verify_tls=not a.insecure)
        if not a.scope:
            print(f"note: no --scope given, so scope is limited to exactly '{t.scope.in_scope[0]}'", file=sys.stderr)
        cfg = Config(db=a.db or "jsdrift.db")
        return cfg, [t]
    cfg = load_config(a.config)
    if a.db:
        cfg.db = a.db
    names = a.targets or list(cfg.targets)
    unknown = [n for n in names if n not in cfg.targets]
    if unknown:
        raise ConfigError(f"unknown target(s): {', '.join(unknown)} (have: {', '.join(cfg.targets)})")
    return cfg, [cfg.targets[n] for n in names]


def _scan_once(a, cfg: Config, targets: list[TargetConfig], store: Store) -> int:
    rc = 0
    for t in targets:
        try:
            res = scan_target(store, t, log=lambda s: print(s, file=sys.stderr))
        except ScanError as e:
            print(f"[{t.name}] ERROR: {e}", file=sys.stderr)
            rc = max(rc, 1)
            continue
        rep = build_report(store, res.run_id, min_conf=t.min_alert_confidence, min_sev=t.min_alert_severity,
                           reveal=a.reveal or t.reveal_secrets)
        fmt = a.format
        out = render_json(rep) if fmt == "json" else render_markdown(rep) if fmt == "md" else \
            render_text(rep, color=_color() and not a.output, verbose=a.verbose)
        if a.output:
            Path(a.output).write_text(out, encoding="utf-8")
            print(f"[{t.name}] report written to {a.output}", file=sys.stderr)
        else:
            print(out)
        if cfg.notify and not a.no_notify:
            # alerts always mask secrets unless the target explicitly opts in
            arep = rep if not (a.reveal or t.reveal_secrets) else build_report(
                store, res.run_id, min_conf=t.min_alert_confidence, min_sev=t.min_alert_severity)
            for err in send_alerts(cfg.notify, arep):
                print(f"[{t.name}] notify failed: {err}", file=sys.stderr)
        if a.exit_code and alert_items(rep):
            rc = max(rc, 2)
    return rc


def cmd_scan(a) -> int:
    print(BANNER, file=sys.stderr)
    cfg, targets = _targets_from_args(a)
    store = Store(cfg.db)
    return _scan_once(a, cfg, targets, store)


def cmd_watch(a) -> int:
    print(BANNER, file=sys.stderr)
    cfg, targets = _targets_from_args(a)
    store = Store(cfg.db)
    print(f"watching {', '.join(t.name for t in targets)} every ~{a.interval}s (Ctrl-C to stop)", file=sys.stderr)
    try:
        while True:
            try:
                _scan_once(a, cfg, targets, store)
            except Exception as e:  # noqa: BLE001 - a bad cycle must not kill the watcher
                print(f"cycle failed: {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(a.interval * (1 + random.uniform(-a.jitter, a.jitter)))
    except KeyboardInterrupt:
        return 0


def cmd_analyze(a) -> int:
    """Offline: analyse local JS files. Use --explain to see *why* candidates were rejected (FP tuning)."""
    from .extract import Extractor
    ex = Extractor(explain=a.explain)
    rc = 0
    for path in a.files:
        try:
            src = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"{path}: {e}", file=sys.stderr)
            rc = 1
            continue
        res = ex.run(src, source=path, vendor=a.vendor)
        items = sorted((f for f in res.findings if f.confidence >= a.min_confidence),
                       key=lambda f: (-SEV_RANK[f.severity], -f.confidence, f.kind))
        if a.json:
            print(json.dumps([{"kind": f.kind, "value": f.value if a.reveal else f.display, "severity": f.severity,
                               "confidence": f.confidence, "rule": f.rule, "why": f.why, "meta": f.meta} for f in items], indent=2))
            continue
        print(f"== {path}: {len(items)} findings (confidence >= {a.min_confidence}), {len(res.js_refs)} script refs, "
              f"{len(res.sourcemaps)} sourcemap refs")
        for f in items:
            v = f.value if a.reveal else f.display
            print(f"[{SEV_TAG[f.severity]}] {f.kind:<9} conf {f.confidence:<3} {v}   ({f.rule})")
            if a.explain or a.verbose:
                for w in f.why:
                    print(f"      - {w}")
        if a.explain:
            print(f"-- {len(res.rejected)} candidates rejected:")
            for r in res.rejected:
                print(f"   x {r.kind:<9} {r.value}  <- {r.reason}")
    return rc


def cmd_findings(a) -> int:
    store, _ = _store(a)
    rows, total = store.query_findings(
        a.target, state=None if a.state == "any" else a.state, kinds=a.kind or None, min_conf=a.min_confidence,
        min_sev=a.min_severity, triage=None if a.all else ["new", "confirmed", "reported"], q=a.q or "", limit=a.limit)
    print(f"{total} findings ({len(rows)} shown)")
    for f in rows:
        v = f["value"] if a.reveal or f["kind"] != "secret" else mask(f["value"])
        print(f"{f['fp']}  [{SEV_TAG[f['severity']]}] {f['kind']:<9} conf {f['confidence']:<3} {v}  ({f['rule']}, {f['triage']})")
        if a.verbose:
            print(f"      in: {', '.join(f['sources'][:3])}")
    return 0


def cmd_report(a) -> int:
    store, cfg = _store(a)
    run = store.run(a.run) if a.run else store.last_run(a.target)
    if not run:
        print("no runs found", file=sys.stderr)
        return 1
    t = cfg.targets.get(a.target) if cfg else None
    rep = build_report(store, run["id"], min_conf=a.min_confidence if a.min_confidence is not None else (t.min_alert_confidence if t else 60),
                       min_sev=a.min_severity or (t.min_alert_severity if t else "low"), reveal=a.reveal)
    out = render_json(rep) if a.format == "json" else render_markdown(rep) if a.format == "md" else \
        render_text(rep, color=_color() and not a.output, verbose=a.verbose)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        print(f"written to {a.output}")
    else:
        print(out)
    return 0


def cmd_triage(a) -> int:
    store, _ = _store(a)
    f = store.finding_by_fp(a.target, a.fingerprint)
    if not f:
        print("no unique finding matches that fingerprint prefix (see `jsdrift findings`)", file=sys.stderr)
        return 1
    store.set_triage(a.target, f["id"], a.status, a.note or "")
    print(f"{f['fp']} ({f['kind']} {mask(f['value']) if f['kind'] == 'secret' else f['value']}) -> {a.status}")
    return 0


def cmd_runs(a) -> int:
    store, _ = _store(a)
    for r in store.runs(a.target):
        s = r["stats"]
        fi, fs = s.get("findings", {}), s.get("files", {})
        print(f"#{r['id']:<4} {r['started']}  {r['status']:<8} {'baseline ' if r['baseline'] else ''}"
              f"files={fs.get('total', '?')} +{fi.get('added', 0)}/-{fi.get('removed', 0)} findings  req={s.get('requests', '?')}")
    return 0


def cmd_diff_file(a) -> int:
    store, _ = _store(a)
    rows = store.find_file(a.target, a.needle)
    exact = [r for r in rows if r["fkey"] == a.needle or r["fkey"].endswith("/" + a.needle)]
    top = [r for r in rows if r["kind"] in ("js", "inline")]
    rows = exact or top or rows
    if not rows:
        print("no tracked file matches", file=sys.stderr)
        return 1
    if len(rows) > 1:
        print("several files match, be more specific:", file=sys.stderr)
        for r in rows[:15]:
            print("  " + r["fkey"], file=sys.stderr)
        return 1
    vs = [v for v in store.versions(rows[0]["id"]) if v["has_content"]]
    if len(vs) < 2:
        print(f"{rows[0]['fkey']}: only {len(vs)} stored version(s), nothing to diff yet")
        return 0
    by_run = {v["run_id"]: v for v in vs}
    va = by_run.get(a.from_run) if a.from_run else vs[-2]
    vb = by_run.get(a.to_run) if a.to_run else vs[-1]
    if not va or not vb:
        print("requested run has no stored version of this file; available runs: " + ", ".join(str(v["run_id"]) for v in vs))
        return 1
    lines = diff_texts(store.version_text(va["id"]) or "", store.version_text(vb["id"]) or "",
                       label_a=f"run#{va['run_id']}", label_b=f"run#{vb['run_id']}")
    c = _color()
    for ln in lines:
        if c and ln[:1] == "+" and not ln.startswith("+++"):
            ln = f"\x1b[32m{ln}\x1b[0m"
        elif c and ln[:1] == "-" and not ln.startswith("---"):
            ln = f"\x1b[31m{ln}\x1b[0m"
        print(ln)
    return 0


def cmd_scope_check(a) -> int:
    cfg = load_config(a.config)
    t = cfg.targets.get(a.target)
    if not t:
        print(f"unknown target {a.target}", file=sys.stderr)
        return 1
    bad = 0
    for u in a.urls:
        d = t.scope.check(u)
        print(f"{'ALLOWED' if d else 'BLOCKED'}  {u}  ({d.reason})")
        bad += not d
    return 1 if bad else 0


def cmd_serve(a) -> int:
    from .web import serve
    cfg = _load(a, need_targets=False)
    path = _db(a, cfg)
    if not Path(path).exists():
        print(f"database not found: {path}", file=sys.stderr)
        return 1
    serve(path, a.host, a.port, a.open)
    return 0


def cmd_demo(a) -> int:
    from .demo import DemoApp
    tmp = Path(a.dir) if a.dir else Path(tempfile.mkdtemp(prefix="jsdrift-demo-"))
    tmp.mkdir(parents=True, exist_ok=True)
    db = tmp / "demo.db"
    app = DemoApp()
    base = app.start()
    t = quick_target(base + "/", ["127.0.0.1"], allow_http=True, allow_private_ips=True, trust_env=False, delay=0.0)
    store = Store(db)
    quiet = lambda s: None  # noqa: E731
    try:
        print(f"demo app running at {base} (local only). Scope = 127.0.0.1\n")
        print("### SCAN 1: baseline of version 1 (full of false-positive bait)\n")
        r1 = scan_target(store, t, log=quiet)
        print(render_text(build_report(store, r1.run_id, min_conf=60), color=_color()))
        from .demo import V1_MAIN as v1
        ex = make_extractor(t, explain=True).run(v1, "main.js")
        print(f"\nFalse positives the filters rejected in v1 ({len(ex.rejected)}), a naive scanner would have reported these:")
        for r in ex.rejected[:14]:
            print(f"   x {r.kind:<9} {r.value[:48]:<48} <- {r.reason}")
        print("\n### Deploying version 2 (every filename hash changes) ...\n")
        app.deploy()
        r2 = scan_target(store, t, log=quiet)
        print(render_text(build_report(store, r2.run_id, min_conf=60), color=_color(), verbose=True))
    finally:
        app.stop()
    print(f"\nDatabase: {db}\nExplore it:  jsdrift serve --db {db}\nFile diff:   jsdrift diff-file {t.name} main --db {db}")
    if a.serve:
        from .web import serve
        serve(str(db), "127.0.0.1", a.port, False)
    return 0


# ---------------------------------------------------------------------------------------------- parser

def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", default="jsdrift.toml", help="config file (default: jsdrift.toml)")
    p.add_argument("--db", help="SQLite database (default: from config, else ./jsdrift.db)")


def _scanargs(p: argparse.ArgumentParser) -> None:
    _common(p)
    p.add_argument("targets", nargs="*", help="target names from the config (default: all)")
    p.add_argument("--url", help="ad-hoc scan of one URL instead of using a config file")
    p.add_argument("--scope", action="append", help="in-scope host pattern for --url mode (repeatable, e.g. '*.example.com')")
    p.add_argument("--exclude", action="append", help="out-of-scope host pattern for --url mode (repeatable)")
    p.add_argument("--header", action="append", help="extra request header 'Name: value' (--url mode)")
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 for Burp (--url mode)")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (--url mode)")
    p.add_argument("--delay", type=float, default=0.5, help="seconds between requests (--url mode)")
    p.add_argument("--threads", type=int, default=4, help="parallel downloads (--url mode)")
    p.add_argument("--format", choices=["text", "json", "md"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--reveal", action="store_true", help="show full secret values (default: masked)")
    p.add_argument("-v", "--verbose", action="store_true", help="show why each finding got its confidence")
    p.add_argument("--no-notify", action="store_true", help="do not send webhook alerts")
    p.add_argument("--exit-code", action="store_true", help="exit 2 when there are new alertable findings (for CI/cron)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jsdrift", description="Watch JavaScript for new endpoints, parameters and secrets, "
                                "with false-positive filtering and a hard scope guard.")
    p.add_argument("--version", action="version", version=f"jsdrift {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="write an example jsdrift.toml")
    s.add_argument("path", nargs="?", default="jsdrift.toml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("scan", help="scan targets once, store a snapshot and report drift since the last scan")
    _scanargs(s)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("watch", help="scan repeatedly (use cron/systemd instead if you prefer)")
    _scanargs(s)
    s.add_argument("--interval", type=float, default=3600, help="seconds between scans (default 3600)")
    s.add_argument("--jitter", type=float, default=0.15, help="random +/- fraction of the interval")
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("analyze", help="offline: analyse local JS files; --explain shows rejected false positives")
    s.add_argument("files", nargs="+", help="JS files, or - for stdin")
    s.add_argument("--explain", action="store_true")
    s.add_argument("--min-confidence", type=int, default=0)
    s.add_argument("--vendor", action="store_true", help="treat as third-party library code (down-weights findings)")
    s.add_argument("--reveal", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("findings", help="list stored findings")
    _common(s)
    s.add_argument("target")
    s.add_argument("--kind", action="append", choices=["secret", "endpoint", "route", "param", "host", "graphql", "sourcemap", "sourcefile"])
    s.add_argument("--min-confidence", type=int, default=60)
    s.add_argument("--min-severity", default="info", choices=list(SEV_RANK))
    s.add_argument("--state", default="active", choices=["active", "removed", "any"])
    s.add_argument("--all", action="store_true", help="include findings triaged as false positive")
    s.add_argument("-q", help="substring search")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--reveal", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_findings)

    s = sub.add_parser("report", help="re-render the report of a stored run")
    _common(s)
    s.add_argument("target")
    s.add_argument("--run", type=int)
    s.add_argument("--format", choices=["text", "json", "md"], default="text")
    s.add_argument("--min-confidence", type=int)
    s.add_argument("--min-severity", choices=list(SEV_RANK))
    s.add_argument("-o", "--output")
    s.add_argument("--reveal", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("triage", help="mark a finding: confirmed | reported | false_positive | new")
    _common(s)
    s.add_argument("target")
    s.add_argument("fingerprint", help="fingerprint (or unique prefix) from `jsdrift findings`")
    s.add_argument("status", choices=list(TRIAGE))
    s.add_argument("--note")
    s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("runs", help="list scan history")
    _common(s)
    s.add_argument("target")
    s.set_defaults(fn=cmd_runs)

    s = sub.add_parser("diff-file", help="line diff between two stored versions of one JS file")
    _common(s)
    s.add_argument("target")
    s.add_argument("needle", help="part of the file key or URL")
    s.add_argument("--from-run", type=int)
    s.add_argument("--to-run", type=int)
    s.set_defaults(fn=cmd_diff_file)

    s = sub.add_parser("scope-check", help="dry-run URLs against a target's scope rules (nothing is fetched)")
    s.add_argument("-c", "--config", default="jsdrift.toml")
    s.add_argument("target")
    s.add_argument("urls", nargs="+")
    s.set_defaults(fn=cmd_scope_check)

    s = sub.add_parser("serve", help="local web dashboard")
    _common(s)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8777)
    s.add_argument("--open", action="store_true", help="open the browser")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("demo", help="safe end-to-end demo against a local fake app (no internet needed)")
    s.add_argument("--dir", help="where to keep the demo database")
    s.add_argument("--serve", action="store_true", help="open the dashboard on the demo data afterwards")
    s.add_argument("--port", type=int, default=8777)
    s.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, ScanError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
