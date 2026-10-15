"""Small shared helpers: entropy, host normalisation, and stable file identity."""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urlsplit


def entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def char_classes(s: str) -> int:
    """How many of {lower, upper, digit, symbol} appear in s."""
    return sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))


def norm_host(host: str | None) -> str:
    h = (host or "").strip().rstrip(".").lower()
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


_VERSION_QS = {
    "v", "ver", "version", "t", "ts", "_", "cb", "cachebust", "cache", "hash", "h",
    "rev", "build", "bust", "nocache", "timestamp", "r", "_v",
}


def _hashy(tok: str, minlen: int) -> bool:
    """Does this path token look like a build/content hash rather than a word?"""
    if len(tok) < minlen or not re.fullmatch(r"[A-Za-z0-9_\-]+", tok):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", tok):
        return len(tok) >= 8 or bool(re.search(r"\d", tok))
    has_digit = bool(re.search(r"\d", tok))
    has_alpha = bool(re.search(r"[A-Za-z]", tok))
    if has_digit and has_alpha:
        if re.fullmatch(r"[A-Za-z]+\d{1,4}", tok) or re.fullmatch(r"\d+[A-Za-z]{1,3}", tok):
            return False
        return True
    return False


def _vite_hash(tok: str) -> bool:
    """Vite/Rollup default: 8 chars of [A-Za-z0-9_-], usually mixed case."""
    return len(tok) == 8 and bool(re.fullmatch(r"[A-Za-z0-9_\-]{8}", tok)) and bool(re.search(r"[a-z]", tok)) and bool(re.search(r"[A-Z]", tok))


def _strip_hash_suffix(t: str) -> str:
    """``index-DiwrgTda`` -> ``index-[hash]``; ``chunk-vendors`` stays as is."""
    i = max(t.rfind("-"), t.rfind("_"))
    if i > 0:
        suf = t[i + 1:]
        if _hashy(suf, 6) or _vite_hash(suf):
            return t[:i] + "-[hash]"
    return t


def identity_key(url: str) -> str:
    """Stable identity for a JS file across deploys.

    ``/static/app.3f9a2b1c.js?v=123`` and ``/static/app.9d81c7e0.js?v=124`` are the same
    logical file, so a new content-hash in the filename is a *new version*, not a new file.
    This is the single biggest source of noise in naive JS monitors.
    """
    p = urlsplit(url)
    host = norm_host(p.hostname) + (f":{p.port}" if p.port else "")
    segs = p.path.split("/")
    out: list[str] = []
    for i, seg in enumerate(segs):
        if not seg:
            out.append(seg)
            continue
        if i == len(segs) - 1:
            toks = seg.split(".")
            new: list[str] = []
            for j, t in enumerate(toks):
                if j == len(toks) - 1 and len(toks) > 1:
                    new.append(t)  # extension
                elif j == 0:
                    if len(toks) > 1 and "-" not in t and "_" not in t and _hashy(t, 8):
                        new.append("[hash]")
                    else:
                        new.append(_strip_hash_suffix(t))
                elif _hashy(t, 8):
                    new.append("[hash]")
                else:
                    new.append(t)
            seg = ".".join(new)
        elif _hashy(seg, 12):
            seg = "[build]"
        out.append(seg)
    qs = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k.lower() not in _VERSION_QS)
    return host + "/".join(out) + (("?" + urlencode(qs)) if qs else "")
