"""A fast, forgiving JavaScript lexer.

We do not need a full parser. We need string literals (to find endpoints and secrets),
comments (to find sourcemaps and leaked notes) and a way to *not* be fooled by regex
literals, division, template strings or minified one-line bundles.
"""
from __future__ import annotations

import re
from typing import Iterator, NamedTuple


class Tok(NamedTuple):
    kind: str   # 'str' | 'tpl' | 'comment' | 'regex'
    value: str
    start: int
    end: int


_NEXT = re.compile(r"""["'`/]""")
_DQ = re.compile(r'"((?:[^"\\\n]|\\.)*)"', re.S)
_SQ = re.compile(r"'((?:[^'\\\n]|\\.)*)'", re.S)
_REGEX = re.compile(r"/((?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)/[a-z]*")
_TPL_SPECIAL = re.compile(r"[\\`$]")
_WORD_BEFORE = re.compile(r"([A-Za-z_$][\w$]*)\s*$")
_REGEX_KEYWORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
    "case", "do", "else", "yield", "await",
}

_ESC = re.compile(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|\r?\n|.)", re.S)
_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v"}


def unescape_js(s: str) -> str:
    if "\\" not in s:
        return s

    def rep(m: re.Match) -> str:
        g = m.group(1)
        try:
            if g[0] == "u" and len(g) > 1:
                return chr(int(g[2:-1] if g[1] == "{" else g[1:], 16))
            if g[0] == "x" and len(g) > 1:
                return chr(int(g[1:], 16))
            if g.isdigit():
                return chr(int(g, 8))
        except (ValueError, OverflowError):
            return m.group(0)
        if g in ("\n", "\r\n"):
            return ""
        return _SIMPLE.get(g, g)

    return _ESC.sub(rep, s)


def _regex_allowed(src: str, pos: int) -> bool:
    """Is a '/' at pos the start of a regex literal (vs. a division operator)?"""
    i = pos - 1
    while i >= 0 and src[i] in " \t\r\n":
        i -= 1
    if i < 0:
        return True
    c = src[i]
    if c in ")]}":
        return False
    if c in "\"'`":
        return False
    if c.isalnum() or c in "_$":
        m = _WORD_BEFORE.search(src, max(0, i - 20), i + 1)
        return bool(m and m.group(1) in _REGEX_KEYWORDS)
    return True


def _scan_template(src: str, j: int) -> tuple[str, int] | None:
    """Scan a template literal starting at the backtick at j. ``${...}`` becomes ``{expr}``."""
    i, n = j + 1, len(src)
    out: list[str] = []
    while i < n:
        m = _TPL_SPECIAL.search(src, i)
        if not m:
            return None
        out.append(src[i:m.start()])
        i = m.start()
        c = src[i]
        if c == "\\":
            out.append(src[i:i + 2])
            i += 2
        elif c == "`":
            return unescape_js("".join(out)), i + 1
        elif src.startswith("${", i):
            depth, k = 1, i + 2
            while k < n and depth:
                ch = src[k]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                elif ch in "\"'":
                    mm = (_DQ if ch == '"' else _SQ).match(src, k)
                    if mm:
                        k = mm.end()
                        continue
                elif ch == "`":
                    r = _scan_template(src, k)
                    if r:
                        k = r[1]
                        continue
                k += 1
            if depth:
                return None
            out.append("{expr}")
            i = k
        else:  # lone '$'
            out.append("$")
            i += 1
    return None


def tokenize(src: str) -> Iterator[Tok]:
    i, n = 0, len(src)
    while i < n:
        m = _NEXT.search(src, i)
        if not m:
            return
        j = m.start()
        c = src[j]
        if c == "/":
            nxt = src[j + 1:j + 2]
            if nxt == "/":
                e = src.find("\n", j)
                e = n if e == -1 else e
                yield Tok("comment", src[j + 2:e], j, e)
                i = e
                continue
            if nxt == "*":
                e = src.find("*/", j + 2)
                e = n if e == -1 else e + 2
                yield Tok("comment", src[j + 2:max(j + 2, e - 2)], j, e)
                i = e
                continue
            if _regex_allowed(src, j):
                mr = _REGEX.match(src, j)
                if mr:
                    yield Tok("regex", mr.group(1), j, mr.end())
                    i = mr.end()
                    continue
            i = j + 1
            continue
        if c == '"' or c == "'":
            ms = (_DQ if c == '"' else _SQ).match(src, j)
            if ms:
                yield Tok("str", unescape_js(ms.group(1)), j, ms.end())
                i = ms.end()
            else:
                i = j + 1
            continue
        r = _scan_template(src, j)
        if r:
            yield Tok("tpl", r[0], j, r[1])
            i = r[1]
        else:
            i = j + 1


def prettify(src: str) -> str:
    """Cheap beautifier so that diffs of minified bundles are line-oriented and readable."""
    out: list[str] = []
    pos = 0
    for t in tokenize(src):
        gap = src[pos:t.start]
        out.append(_break(gap))
        raw = src[t.start:t.end]
        out.append(raw if t.kind != "comment" else raw + ("\n" if not raw.endswith("\n") else ""))
        pos = t.end
    out.append(_break(src[pos:]))
    text = "".join(out)
    return re.sub(r"\n{2,}", "\n", text)


def _break(code: str) -> str:
    return code.replace(";", ";\n").replace("{", "{\n").replace("}", "\n}\n")
