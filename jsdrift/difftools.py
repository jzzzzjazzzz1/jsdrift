"""Readable diffs of minified bundles."""
from __future__ import annotations

import difflib

from .tokenizer import prettify

BIG = 12_000  # lines; above this difflib's quadratic worst case is too slow, so use a set-based diff


def diff_texts(old: str, new: str, context: int = 2, max_lines: int = 4000, label_a: str = "old", label_b: str = "new") -> list[str]:
    a, b = prettify(old).splitlines(), prettify(new).splitlines()
    if len(a) > BIG or len(b) > BIG:
        sa, sb = set(a), set(b)
        out = [f"--- {label_a}", f"+++ {label_b}", "@@ large file: unordered line diff @@"]
        out += [f"-{x}" for x in a if x not in sb][:max_lines // 2]
        out += [f"+{x}" for x in b if x not in sa][:max_lines // 2]
        return out
    out = list(difflib.unified_diff(a, b, label_a, label_b, n=context, lineterm=""))
    if len(out) > max_lines:
        out = out[:max_lines] + [f"... diff truncated at {max_lines} lines"]
    return out
