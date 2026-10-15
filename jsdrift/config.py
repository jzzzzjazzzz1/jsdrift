"""Configuration loading (TOML) and per-target settings."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .extract import Ignore
from .scope import Scope, ScopeConfigError
from .util import norm_host

DEFAULT_UA = "jsdrift/1.0 (authorized security research)"

# Files that are mostly third-party library code. Findings in them are not dropped,
# only down-weighted (so a leaked key in vendor.js is still reported, but noise is not).
DEFAULT_VENDOR = (
    r"(?i)(?:^|[/._~-])(?:vendors?|jquery[\w.\-]*|lodash|moment|polyfills?|framework|react(?:-dom)?|angular|vue|"
    r"bootstrap|d3|three|chart|socket\.io|gtag|gtm|analytics|fbevents|hotjar|intercom|sentry)(?:[.\-_~/]|$)"
)


class ConfigError(ValueError):
    pass


@dataclass
class TargetConfig:
    name: str
    seeds: list[str]
    scope: Scope
    extra_js: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    ignore: Ignore = field(default_factory=Ignore)
    noise_hosts: list[str] = field(default_factory=list)
    vendor_pattern: str = DEFAULT_VENDOR
    user_agent: str = DEFAULT_UA
    delay: float = 0.5            # minimum seconds between requests (global, per scan)
    threads: int = 4
    timeout: float = 20.0
    max_file_mb: float = 8.0
    max_files: int = 300
    max_depth: int = 3
    sourcemaps: bool = True       # fetch exposed .map files and analyse original sources
    map_node_modules: bool = False
    max_map_sources: int = 400
    proxy: str = ""
    verify_tls: bool = True
    trust_env: bool = True        # honour HTTP(S)_PROXY from the environment
    store_content: bool = True    # keep compressed copies of each JS version (needed for diff-file)
    min_alert_confidence: int = 60
    min_alert_severity: str = "low"
    reveal_secrets: bool = False  # alerts show masked secrets unless this is set

    def vendor_re(self) -> re.Pattern:
        return re.compile(self.vendor_pattern)


@dataclass
class Config:
    db: str = "jsdrift.db"
    targets: dict[str, TargetConfig] = field(default_factory=dict)
    notify: dict[str, str] = field(default_factory=dict)
    path: str = ""


_TARGET_SCALARS = {
    "user_agent": str, "delay": float, "threads": int, "timeout": float, "max_file_mb": float, "max_files": int,
    "max_depth": int, "sourcemaps": bool, "map_node_modules": bool, "max_map_sources": int, "proxy": str,
    "verify_tls": bool, "trust_env": bool, "store_content": bool, "min_alert_confidence": int,
    "min_alert_severity": str, "reveal_secrets": bool, "vendor_pattern": str,
}


def _build_target(name: str, raw: dict, defaults: dict) -> TargetConfig:
    merged = {**defaults, **raw}
    seeds = list(merged.get("seeds", []))
    if not seeds:
        raise ConfigError(f"target '{name}': 'seeds' must list at least one URL")
    for s in seeds + list(merged.get("extra_js", [])):
        if urlsplit(s).scheme not in ("http", "https"):
            raise ConfigError(f"target '{name}': '{s}' is not an http(s) URL")
    sc = dict(merged.get("scope", {}))
    if "in_scope" in merged:  # allow flat keys too
        sc.setdefault("in_scope", merged["in_scope"])
    if "out_of_scope" in merged:
        sc.setdefault("out_of_scope", merged["out_of_scope"])
    for k in ("allow_http", "allow_private_ips"):
        if k in merged:
            sc.setdefault(k, merged[k])
    if not sc.get("in_scope"):
        raise ConfigError(
            f"target '{name}': define in_scope (e.g. in_scope = [\"*.example.com\", \"example.com\"]). "
            "JSDrift refuses to run without an explicit scope."
        )
    try:
        scope = Scope.from_dict(sc)
    except ScopeConfigError as e:
        raise ConfigError(f"target '{name}': {e}") from e
    ign = merged.get("ignore", {})
    kw = {}
    for key, typ in _TARGET_SCALARS.items():
        if key in merged:
            try:
                kw[key] = typ(merged[key])
            except (TypeError, ValueError) as e:
                raise ConfigError(f"target '{name}': bad value for {key}: {e}") from e
    return TargetConfig(
        name=name, seeds=seeds, scope=scope, extra_js=list(merged.get("extra_js", [])),
        headers={str(k): str(v) for k, v in dict(merged.get("headers", {})).items()},
        ignore=Ignore(hosts=[norm_host(h) for h in ign.get("hosts", [])], paths=list(ign.get("paths", [])),
                      values=list(ign.get("values", [])), params=list(ign.get("params", [])),
                      rules=list(ign.get("rules", []))),
        noise_hosts=list(merged.get("noise_hosts", [])), **kw,
    )


def load_config(path: str | os.PathLike) -> Config:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p} (create one with `jsdrift init`)")
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{p}: invalid TOML: {e}") from e
    defaults = dict(raw.get("defaults", {}))
    cfg = Config(db=str(raw.get("db", defaults.pop("db", "jsdrift.db"))), path=str(p))
    # DB path is relative to the config file so the tool works from any cwd
    if not os.path.isabs(cfg.db):
        cfg.db = str((p.parent / cfg.db).resolve())
    defaults.pop("db", None)
    cfg.notify = {k: str(v) for k, v in dict(raw.get("notify", {})).items()}
    for env, key in (("JSDRIFT_DISCORD_WEBHOOK", "discord"), ("JSDRIFT_SLACK_WEBHOOK", "slack"),
                     ("JSDRIFT_WEBHOOK", "generic")):
        if os.environ.get(env):
            cfg.notify[key] = os.environ[env]
    for name, t in dict(raw.get("targets", {})).items():
        cfg.targets[name] = _build_target(name, dict(t), defaults)
    if not cfg.targets:
        raise ConfigError(f"{p}: no [targets.<name>] sections found")
    return cfg


def quick_target(url: str, scope: list[str] | None, out_of_scope: list[str] | None = None, **opts) -> TargetConfig:
    """Build an ad-hoc target from the command line. Scope defaults to the seed host *only*."""
    host = norm_host(urlsplit(url).hostname)
    if not host:
        raise ConfigError(f"cannot parse host from '{url}'")
    raw = {"seeds": [url], "scope": {"in_scope": scope or [host], "out_of_scope": out_of_scope or []}, **opts}
    return _build_target(host, raw, {})


EXAMPLE_CONFIG = '''\
# jsdrift.toml - run `jsdrift scan` (all targets) or `jsdrift scan acme`
# ONLY monitor assets you are authorised to test (bug bounty scope / written permission).
db = "jsdrift.db"

[defaults]
delay = 0.5            # seconds between requests (be polite; raise it for fragile targets)
threads = 4
max_depth = 3          # how deep to follow chunk/lazy-load references
min_alert_confidence = 60   # alerts only include findings with confidence >= this (everything is still stored)
min_alert_severity = "low"  # info | low | medium | high | critical
# headers = { "X-Bug-Bounty" = "your-handle" }   # many programs ask you to identify your traffic

[notify]               # optional; env vars JSDRIFT_DISCORD_WEBHOOK / JSDRIFT_SLACK_WEBHOOK / JSDRIFT_WEBHOOK also work
# discord = "https://discord.com/api/webhooks/..."
# slack   = "https://hooks.slack.com/services/..."
# generic = "https://example.com/hook"       # receives the full JSON report

[targets.acme]
seeds = ["https://app.acme.com/", "https://www.acme.com/"]
# extra_js = ["https://app.acme.com/static/js/legacy-admin.js"]   # files not linked from any page

[targets.acme.scope]
in_scope = ["app.acme.com", "www.acme.com", "*.api.acme.com"]       # every request AND redirect is checked
out_of_scope = ["blog.acme.com", "*.corp.acme.com"]                 # always wins over in_scope
# allow_http = false
# allow_private_ips = false   # keep false: stops a hostile page steering the tool into internal networks

[targets.acme.ignore]          # tune false positives permanently (or use `jsdrift triage ... fp`)
# hosts  = ["cdn.example-analytics.com"]
# paths  = ["^/cdn-cgi/", "^/__"]                 # regexes against endpoint paths
# values = ["pk_test_abc123"]                      # exact values
# params = ["utm_source"]
# rules  = ["generic_assignment"]                  # switch a whole rule off for this target
'''
