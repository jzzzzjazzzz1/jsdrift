"""Webhook alerts (Discord / Slack / generic JSON).

Alert text contains attacker-controlled strings (they come from the target's JavaScript), so it is
sanitised: no @mentions/pings, no Slack control sequences, no markdown breakout. Secrets are masked.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .report import SEV_TAG, alert_items

_ICON = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U0001F535", "info": "⚪"}


def _clean(s: str) -> str:
    return (s.replace("@", "@​").replace("`", "'").replace("<", "‹").replace(">", "›")
             .replace("&", "+").replace("\n", " "))[:200]


def format_alert(rep: dict, max_items: int = 12) -> str | None:
    items = alert_items(rep)
    fl = rep["files"]
    if not items and not fl["added"] and not any(x["findings_added"] for x in fl["changed"]):
        return None
    lines = [f"**jsdrift: {_clean(rep['target'])}**, run #{rep['run']['id']}: "
             f"{len(rep['new'])} new, {len(rep['reappeared'])} reappeared, {len(fl['added'])} new JS files"]
    for v in items[:max_items]:
        where = v["found_in"].rsplit("/", 1)[-1]
        lines.append(f"{_ICON[v['severity']]} **{SEV_TAG[v['severity']].strip()}** {v['kind']} `{_clean(v['value'])}` "
                     f"(conf {v['confidence']}, {_clean(v['rule'])}) in `{_clean(where)}`")
    if len(items) > max_items:
        lines.append(f"...and {len(items) - max_items} more. Open the dashboard / `jsdrift report`.")
    for x in fl["added"][:5]:
        lines.append(f"\U0001F4C4 new JS file `{_clean(x['file'].rsplit('/', 1)[-1])}`")
    return "\n".join(lines)


def _post(url: str, payload: dict, timeout: float = 10.0) -> str | None:
    if urlsplit(url).scheme != "https":
        return "webhook URL must be https"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "jsdrift"})
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return None
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"{type(e).__name__}: {e}"


def send_alerts(notify_cfg: dict[str, str], rep: dict) -> list[str]:
    """Returns a list of human-readable problems (empty = all sent or nothing to send)."""
    text = format_alert(rep)
    if text is None:
        return []
    errs = []
    if notify_cfg.get("discord"):
        e = _post(notify_cfg["discord"], {"content": text[:1900], "username": "jsdrift", "allowed_mentions": {"parse": []}})
        errs += [f"discord: {e}"] if e else []
    if notify_cfg.get("slack"):
        e = _post(notify_cfg["slack"], {"text": text[:2900].replace("**", "*")})
        errs += [f"slack: {e}"] if e else []
    if notify_cfg.get("generic"):
        e = _post(notify_cfg["generic"], rep)
        errs += [f"generic webhook: {e}"] if e else []
    return errs
