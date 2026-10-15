"""SQLite persistence. One file, WAL mode, owner-only permissions (it contains full secret values)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import zlib
from datetime import datetime, timezone
from pathlib import Path

from .models import SEV_RANK

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, started TEXT NOT NULL, finished TEXT,
  baseline INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'running', stats TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, fkey TEXT NOT NULL, url TEXT NOT NULL, kind TEXT NOT NULL,
  parent TEXT NOT NULL DEFAULT '', sha TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'active',
  first_run INTEGER NOT NULL, last_run INTEGER NOT NULL, changed_run INTEGER NOT NULL, analyzer TEXT NOT NULL DEFAULT '',
  refs TEXT NOT NULL DEFAULT '[]', maps TEXT NOT NULL DEFAULT '[]', UNIQUE(target, fkey));
CREATE TABLE IF NOT EXISTS versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, run_id INTEGER NOT NULL, sha TEXT NOT NULL,
  size INTEGER NOT NULL, url TEXT NOT NULL, content BLOB, UNIQUE(file_id, sha));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, fp TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  rule TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL, confidence INTEGER NOT NULL, hint TEXT NOT NULL DEFAULT '',
  context TEXT NOT NULL DEFAULT '', meta TEXT NOT NULL DEFAULT '{}', why TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'active', triage TEXT NOT NULL DEFAULT 'new', note TEXT NOT NULL DEFAULT '',
  first_run INTEGER NOT NULL, last_run INTEGER NOT NULL, first_source TEXT NOT NULL DEFAULT '', UNIQUE(target, fp));
CREATE TABLE IF NOT EXISTS finding_sources(
  finding_id INTEGER NOT NULL, target TEXT NOT NULL, fkey TEXT NOT NULL, UNIQUE(finding_id, fkey));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, target TEXT NOT NULL, type TEXT NOT NULL,
  finding_id INTEGER, fkey TEXT, detail TEXT NOT NULL DEFAULT '{}', ts TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_fs_file ON finding_sources(target, fkey);
CREATE INDEX IF NOT EXISTS ix_find_t ON findings(target, state, triage);
CREATE INDEX IF NOT EXISTS ix_ev_run ON events(run_id);
CREATE INDEX IF NOT EXISTS ix_files_t ON files(target, state);
"""

TRIAGE = ("new", "confirmed", "reported", "false_positive")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | os.PathLike):
        self.path = str(path)
        self._local = threading.local()
        new = not Path(self.path).exists()
        with self.conn:
            self.conn.executescript(SCHEMA)
        if new:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            self._local.c = c
        return c

    def close(self) -> None:
        c = getattr(self._local, "c", None)
        if c is not None:
            c.close()
            self._local.c = None

    # ------------------------------------------------------------------ runs
    def start_run(self, target: str) -> tuple[int, bool]:
        c = self.conn
        prev = c.execute("SELECT COUNT(*) FROM runs WHERE target=? AND status IN ('ok','partial')", (target,)).fetchone()[0]
        with c:
            cur = c.execute("INSERT INTO runs(target, started, baseline) VALUES (?,?,?)", (target, utcnow(), int(prev == 0)))
        return cur.lastrowid, prev == 0

    def finish_run(self, run_id: int, status: str, stats: dict) -> None:
        with self.conn as c:
            c.execute("UPDATE runs SET finished=?, status=?, stats=? WHERE id=?", (utcnow(), status, json.dumps(stats), run_id))

    def runs(self, target: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM runs WHERE target=? ORDER BY id DESC LIMIT ?", (target, limit)).fetchall()
        return [self._run(r) for r in rows]

    def run(self, run_id: int) -> dict | None:
        r = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._run(r) if r else None

    def last_run(self, target: str, before: int | None = None) -> dict | None:
        q = "SELECT * FROM runs WHERE target=? AND status IN ('ok','partial')"
        args: list = [target]
        if before:
            q += " AND id<?"
            args.append(before)
        r = self.conn.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
        return self._run(r) if r else None

    @staticmethod
    def _run(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["stats"] = json.loads(d["stats"] or "{}")
        d["baseline"] = bool(d["baseline"])
        return d

    def targets(self) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT DISTINCT target FROM runs ORDER BY target")]

    # ------------------------------------------------------------------ files
    def cache_lookup(self, target: str, fkey: str, analyzer: str) -> dict | None:
        """What we know about a file from the last scan (lets the crawler skip unchanged files)."""
        r = self.conn.execute("SELECT * FROM files WHERE target=? AND fkey=? AND state='active'", (target, fkey)).fetchone()
        if not r or r["analyzer"] != analyzer:
            return None
        children, frontier = [], [fkey]
        while frontier:
            rows = self.conn.execute(
                f"SELECT fkey FROM files WHERE target=? AND state='active' AND parent IN ({','.join('?' * len(frontier))})",
                [target, *frontier]).fetchall()
            frontier = [x[0] for x in rows if x[0] not in children]
            children += frontier
        return {"sha": r["sha"], "refs": json.loads(r["refs"]), "maps": json.loads(r["maps"]), "children": children}

    def files(self, target: str, state: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM files WHERE target=?", [target]
        if state:
            q += " AND state=?"
            args.append(state)
        rows = self.conn.execute(q + " ORDER BY changed_run DESC, fkey", args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["n_findings"] = self.conn.execute("SELECT COUNT(*) FROM finding_sources WHERE target=? AND fkey=?",
                                                (target, r["fkey"])).fetchone()[0]
            d["n_versions"] = self.conn.execute("SELECT COUNT(*) FROM versions WHERE file_id=?", (r["id"],)).fetchone()[0]
            d.pop("refs", None), d.pop("maps", None)
            out.append(d)
        return out

    def find_file(self, target: str, needle: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM files WHERE target=? AND (fkey=? OR fkey LIKE ? OR url LIKE ?) ORDER BY fkey",
                                 (target, needle, f"%{needle}%", f"%{needle}%")).fetchall()

    def versions(self, file_id: int) -> list[dict]:
        rows = self.conn.execute("SELECT id, run_id, sha, size, url, content IS NOT NULL AS has_content FROM versions "
                                 "WHERE file_id=? ORDER BY id", (file_id,)).fetchall()
        return [dict(r) for r in rows]

    def version_text(self, version_id: int) -> str | None:
        r = self.conn.execute("SELECT content FROM versions WHERE id=?", (version_id,)).fetchone()
        return zlib.decompress(r[0]).decode("utf-8", "replace") if r and r[0] else None

    # ------------------------------------------------------------------ findings
    def finding(self, finding_id: int) -> dict | None:
        r = self.conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return self._finding(r) if r else None

    def finding_by_fp(self, target: str, fp: str) -> dict | None:
        rows = self.conn.execute("SELECT * FROM findings WHERE target=? AND fp LIKE ?", (target, fp + "%")).fetchall()
        return self._finding(rows[0]) if len(rows) == 1 else None

    def _finding(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["meta"] = json.loads(d["meta"] or "{}")
        d["why"] = json.loads(d["why"] or "[]")
        d["sources"] = [x[0] for x in self.conn.execute(
            "SELECT fkey FROM finding_sources WHERE finding_id=? ORDER BY fkey", (r["id"],))]
        return d

    def query_findings(self, target: str, state: str | None = "active", kinds: list[str] | None = None,
                       min_conf: int = 0, min_sev: str = "info", triage: list[str] | None = None, q: str = "",
                       source: str = "", limit: int = 200, offset: int = 0) -> tuple[list[dict], int]:
        where, args = ["target=?"], [target]
        if state:
            where.append("state=?")
            args.append(state)
        if kinds:
            where.append(f"kind IN ({','.join('?' * len(kinds))})")
            args += kinds
        if min_conf:
            where.append("confidence>=?")
            args.append(min_conf)
        if triage:
            where.append(f"triage IN ({','.join('?' * len(triage))})")
            args += triage
        if q:
            where.append("(value LIKE ? OR hint LIKE ? OR rule LIKE ? OR context LIKE ?)")
            args += [f"%{q}%"] * 4
        if source:
            where.append("id IN (SELECT finding_id FROM finding_sources WHERE fkey LIKE ?)")
            args.append(f"%{source}%")
        floor = SEV_RANK.get(min_sev, 0)
        sev_ok = [s for s, i in SEV_RANK.items() if i >= floor]
        where.append(f"severity IN ({','.join('?' * len(sev_ok))})")
        args += sev_ok
        sql = " AND ".join(where)
        total = self.conn.execute(f"SELECT COUNT(*) FROM findings WHERE {sql}", args).fetchone()[0]
        order = ("CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for s, i in SEV_RANK.items()) + " END DESC, confidence DESC, id DESC")
        rows = self.conn.execute(f"SELECT * FROM findings WHERE {sql} ORDER BY {order} LIMIT ? OFFSET ?",
                                 [*args, limit, offset]).fetchall()
        return [self._finding(r) for r in rows], total

    def set_triage(self, target: str, finding_id: int, triage: str, note: str = "") -> bool:
        if triage not in TRIAGE:
            raise ValueError(f"triage must be one of {TRIAGE}")
        with self.conn as c:
            cur = c.execute("UPDATE findings SET triage=?, note=CASE WHEN ?='' THEN note ELSE ? END WHERE id=? AND target=?",
                            (triage, note, note, finding_id, target))
        return cur.rowcount == 1

    def counts(self, target: str) -> dict:
        c = self.conn
        out = {"active": 0, "by_severity": {}, "by_kind": {}, "triage": {}}
        for r in c.execute("SELECT severity, kind, triage, COUNT(*) n FROM findings WHERE target=? AND state='active' "
                           "GROUP BY severity, kind, triage", (target,)):
            out["active"] += r["n"]
            out["by_severity"][r["severity"]] = out["by_severity"].get(r["severity"], 0) + r["n"]
            out["by_kind"][r["kind"]] = out["by_kind"].get(r["kind"], 0) + r["n"]
            out["triage"][r["triage"]] = out["triage"].get(r["triage"], 0) + r["n"]
        out["files"] = c.execute("SELECT COUNT(*) FROM files WHERE target=? AND state='active' AND kind IN ('js','inline')",
                                 (target,)).fetchone()[0]
        return out

    # ------------------------------------------------------------------ events
    def events(self, run_id: int) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"] or "{}")
            out.append(d)
        return out
