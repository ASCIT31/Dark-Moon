#!/usr/bin/env python3
"""Darkmoon Terminal Explorer, local data adapter (Community edition, GPL-3.0).

Read-only. Reads the local Darkmoon JSON store and prints, on stdout, the same JSON shapes as the Pro API
routes the TUI uses, so one renderer serves both editions. No daemon, no cache file, no write, no network,
no model call.

Safety
- Every path is resolved inside the data root (or the reports root); ids are checked against the store's id
  grammar; a symlink that leaves the root is refused.
- Evidence is masked with the Darkmoon redaction engine (``evidence_redaction``). If that engine cannot be
  loaded, evidence is withheld (fail closed): ``{"withheld": true}`` replaces it and nothing raw is printed.
- Attack paths: the MCP server's read model (``api.attack_paths_local``) is used when it is installed; otherwise only
  the agents' ``enabled_by`` declarations are listed, as ``agent-declared`` hypotheses. Nothing is inferred here.

Usage: darkmoon_explore.py [--data DIR] [--reports DIR] [--mcp DIR] <command> [args]
  projects | campaigns | campaign ID | finding ID | vulnerabilities [--project ID] [--campaign ID]
  | report CAMPAIGN_ID | paths CAMPAIGN_ID
Exit codes: 0 ok, 2 not found / refused, 1 error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
SEVERITIES = ("critical", "high", "medium", "low", "info")


class NotFound(Exception):
    pass


def default_data_dir() -> Path:
    env = os.environ.get("DARKMOON_DATA_DIR", "").strip()
    if env:
        return Path(env)
    pro = Path("/opt/darkmoon/mcp/server/data")
    return pro if pro.is_dir() else Path.home() / ".local" / "share" / "opencode"


class Store:
    def __init__(self, data: Path, reports: Path):
        self.root = data.resolve()
        self.reports = reports.resolve()

    def _inside(self, base: Path, rel: str) -> Path:
        p = (base / rel).resolve()
        if p != base and base not in p.parents:
            raise NotFound("path outside the data root")
        return p

    def _json(self, base: Path, rel: str, default):
        p = self._inside(base, rel)
        if not p.is_file():
            return default
        with p.open(encoding="utf-8") as f:
            return json.load(f)

    def _json_or(self, base: Path, rel: str, default):
        """Listings: one unreadable, malformed or escaping file is skipped, it never empties the whole view."""
        try:
            return self._json(base, rel, default)
        except (NotFound, OSError, ValueError):
            return default

    def projects(self) -> list:
        d = self._json(self.root, "projects.json", [])
        return d if isinstance(d, list) else list(d.values()) if isinstance(d, dict) else []

    def targets(self) -> list:
        d = self._json(self.root, "targets.json", [])
        return d if isinstance(d, list) else list(d.values()) if isinstance(d, dict) else []

    def campaigns(self) -> list:
        base = self._inside(self.root, "campaigns")
        if not base.is_dir():
            return []
        out = []
        for p in sorted(base.glob("*.json")):
            if not ID_RE.match(p.stem):
                continue
            c = self._json_or(base, p.name, None)
            if isinstance(c, dict):
                out.append(c)
        return out

    def campaign(self, cid: str) -> dict:
        check_id(cid)
        c = self._json(self.root, f"campaigns/{cid}.json", None)
        if not isinstance(c, dict):
            raise NotFound(cid)
        return c

    def vulns(self, cid: str) -> list:
        check_id(cid)
        d = self._json(self.root, f"vulnerabilities/{cid}.json", [])
        return d if isinstance(d, list) else d.get("vulnerabilities", []) if isinstance(d, dict) else []

    def all_vulns(self) -> list:
        base = self._inside(self.root, "vulnerabilities")
        if not base.is_dir():
            return []
        out = []
        for p in sorted(base.glob("*.json")):
            if ID_RE.match(p.stem):
                try:
                    vs = self.vulns(p.stem)
                except (NotFound, OSError, ValueError):
                    continue
                for v in vs:
                    if isinstance(v, dict):
                        out.append({**v, "campaign_id": v.get("campaign_id") or p.stem})
        return out

    def report(self, report_path: str) -> str:
        name = Path(str(report_path or "")).name
        if not name or not name.endswith(".md"):
            raise NotFound("no report")
        for base in (self.reports, self._inside(self.root, "reports")):
            p = self._inside(base, name)
            if p.is_file():
                return p.read_text(encoding="utf-8", errors="replace")
        raise NotFound("report file missing")


def check_id(s: str) -> None:
    if not ID_RE.match(s or ""):
        raise NotFound("invalid id")


# ---------------------------------------------------------------- redaction (fail closed)

def load_redaction(mcp_root: Path | None):
    for root in [mcp_root, Path(__file__).resolve().parent / "_vendor"]:
        if root and root.is_dir() and str(root) not in sys.path:
            sys.path.insert(0, str(root))
    for name in ("api.evidence_redaction", "evidence_redaction"):
        try:
            mod = __import__(name, fromlist=["redact_finding"])
            if callable(getattr(mod, "redact_finding", None)) and callable(getattr(mod, "redact_text", None)):
                return mod
        except Exception:  # noqa: BLE001 — any failure means: no redaction available
            continue
    return None


EVIDENCE_KEYS = ("evidence", "raw_request", "raw_response", "logs", "commands", "payloads", "extracted_data", "screenshots")


def safe_finding(v: dict, red, list_view: bool) -> dict:
    if red is not None:
        try:
            return red.redact_finding(v, list_view=list_view)
        except Exception:  # noqa: BLE001
            pass
    out = {k: v[k] for k in v if k not in EVIDENCE_KEYS}
    out["evidence"] = {"withheld": True}
    return out


def safe_text(s: str, red) -> str | None:
    if red is None:
        return None
    try:
        text, _ = red.redact_text(s)
        return text
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- commands

def severity_counts(vs: list) -> dict:
    c = Counter(str(v.get("severity", "info")).lower() for v in vs)
    stats = {s: c.get(s, 0) for s in SEVERITIES}
    stats["total_findings"] = len(vs)
    stats["exploited"] = sum(1 for v in vs if str(v.get("status", "")).lower() == "exploited")
    return stats


def worst(vs: list) -> str | None:
    for s in SEVERITIES:
        if any(str(v.get("severity", "")).lower() == s for v in vs):
            return s
    return None


def cmd_projects(st: Store, red) -> dict:
    targets = {t.get("id"): t for t in st.targets() if isinstance(t, dict)}
    camps = [c for c in st.campaigns() if not c.get("is_subagent")]
    vulns = st.all_vulns()
    out = []
    for p in st.projects():
        if not isinstance(p, dict):
            continue
        pc = [c for c in camps if c.get("project_id") == p.get("id")]
        ids = {c.get("id") for c in pc}
        pv = [v for v in vulns if v.get("campaign_id") in ids or v.get("project_id") == p.get("id")]
        out.append({**p, "target": targets.get(p.get("target_id")) or p.get("target"), "campaigns_count": len(pc),
                    "vulnerabilities_count": len(pv), "latest_risk": worst(pv)})
    return {"data": out, "total": len(out)}


def cmd_campaigns(st: Store, red) -> dict:
    out = []
    for c in st.campaigns():
        if c.get("is_subagent"):
            continue
        vs = st.vulns(c["id"]) if ID_RE.match(str(c.get("id", ""))) else []
        out.append({**{k: v for k, v in c.items() if k not in ("vulnerabilities", "executive_summary")},
                    "stats": severity_counts(vs)})
    return {"data": out, "total": len(out)}


def safe_obj(o, red):
    """Every string of a record through the redaction; without the engine, free-text fields are withheld."""
    if red is not None:
        try:
            return red.redact_obj(o)
        except Exception:  # noqa: BLE001
            pass
    if isinstance(o, dict):
        return {k: ("[withheld]" if k in FREE_TEXT_KEYS else safe_obj(v, None)) for k, v in o.items()}
    if isinstance(o, list):
        return [safe_obj(v, None) for v in o]
    return o


FREE_TEXT_KEYS = ("executive_summary", "prompt", "description", "remediation", "note", "why", "plain", "raw")


def cmd_campaign(st: Store, red, cid: str) -> dict:
    c = safe_obj(st.campaign(cid), red)
    vs = [safe_finding(v, red, True) for v in st.vulns(cid) if isinstance(v, dict)]
    return {"data": {**c, "stats": severity_counts(vs), "vulnerabilities": vs}}


def cmd_finding(st: Store, red, vid: str) -> dict:
    check_id(vid)
    for v in st.all_vulns():
        if v.get("id") == vid:
            return {"data": safe_finding(v, red, False)}
    raise NotFound(vid)


def cmd_vulnerabilities(st: Store, red, project: str | None, campaign: str | None) -> dict:
    vs = st.vulns(campaign) if campaign else st.all_vulns()
    if project:
        ids = {c.get("id") for c in st.campaigns() if c.get("project_id") == project}
        vs = [v for v in vs if v.get("project_id") == project or v.get("campaign_id") in ids]
    vs = [safe_finding(v, red, True) for v in vs if isinstance(v, dict)]
    by_sev = Counter(str(v.get("severity", "info")).lower() for v in vs)
    by_status = Counter(str(v.get("status", "")).lower() for v in vs)
    return {"data": vs, "total": len(vs), "stats": {"by_severity": dict(by_sev), "by_status": dict(by_status)}}


def cmd_report(st: Store, red, cid: str) -> dict:
    c = st.campaign(cid)
    raw = st.report(c.get("report_path") or "")
    text = safe_text(raw, red)
    if text is None:
        text = "> **Report withheld.** The redaction engine is not available, so the report is not shown in the terminal.\n"
    return {"campaign_id": cid, "format": "markdown", "content": text}


def cmd_paths(st: Store, red, cid: str) -> dict:
    st.campaign(cid)
    try:  # the attack-path read model of the MCP server (local store, no web server), when it is installed
        from api.attack_paths_local import attack_paths_doc  # type: ignore

        doc = attack_paths_doc(cid, "all", True, finding_filter=lambda v: safe_obj(v, red))
        if doc is not None:
            return safe_obj(doc, red)
    except Exception:  # noqa: BLE001 — fall back to the declarations, never to an invented path
        pass
    vs = {v.get("id"): v for v in st.vulns(cid) if isinstance(v, dict)}
    paths = []
    for v in vs.values():
        for src in v.get("enabled_by") or []:
            sid = src if isinstance(src, str) else (src or {}).get("id") or (src or {}).get("finding_id")
            if not sid or sid not in vs:
                continue
            a, b = vs[sid], v
            paths.append({
                "id": f"decl_{sid}_{v.get('id')}", "title": f"{a.get('title', sid)} → {b.get('title', v.get('id'))}",
                "provenance": "agent-declared", "hypothesis": True, "certainty": "unconfirmed",
                "criticality": b.get("severity"), "status": "open", "finding_ids": [sid, v.get("id")],
                "note": "Declared by the agent, not verified: the local edition has no corroboration engine.",
                "steps": [
                    {"n": 1, "node_label": a.get("title", sid), "finding_id": sid, "proof": a.get("status"), "kind": "declared"},
                    {"n": 2, "node_label": b.get("title", v.get("id")), "finding_id": v.get("id"), "proof": b.get("status"), "kind": "declared"},
                ],
            })
    return safe_obj({"schema_version": "darkmoon-attack-paths/v1", "campaign_id": cid, "paths": paths,
            "summary": {"paths_total": len(paths), "proven_paths": 0, "declared_paths": len(paths), "inferred_paths": 0}}, red)


# C0 controls (but tab/newline), DEL, C1 controls (8-bit CSI/OSC/DCS...) and bidi overrides: a stored title or
# report can never drive the terminal the explorer renders in.
_CONTROLS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def no_controls(o):
    if isinstance(o, str):
        return _CONTROLS.sub("", o)
    if isinstance(o, dict):
        return {no_controls(k): no_controls(v) for k, v in o.items()}
    if isinstance(o, list):
        return [no_controls(v) for v in o]
    return o


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--data", type=Path, default=None)
    ap.add_argument("--reports", type=Path, default=None)
    ap.add_argument("--mcp", type=Path, default=None)
    ap.add_argument("cmd")
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--project")
    ap.add_argument("--campaign")
    a = ap.parse_args(argv)
    data = a.data or default_data_dir()
    reports = a.reports or Path(os.environ.get("DARKMOON_REPORTS_DIR", "").strip() or data / "reports")
    mcp = a.mcp or (Path("/opt/darkmoon/mcp/server") if Path("/opt/darkmoon/mcp/server/api").is_dir() else None)
    if mcp and mcp.is_dir():
        os.environ.setdefault("DARKMOON_DATA_DIR", str(data))
    st = Store(data, reports)
    red = load_redaction(mcp)
    try:
        if a.cmd == "projects":
            out = cmd_projects(st, red)
        elif a.cmd == "campaigns":
            out = cmd_campaigns(st, red)
        elif a.cmd == "campaign":
            out = cmd_campaign(st, red, a.arg or "")
        elif a.cmd == "finding":
            out = cmd_finding(st, red, a.arg or "")
        elif a.cmd == "vulnerabilities":
            out = cmd_vulnerabilities(st, red, a.project, a.campaign)
        elif a.cmd == "report":
            out = cmd_report(st, red, a.arg or "")
        elif a.cmd == "paths":
            out = cmd_paths(st, red, a.arg or "")
        else:
            print(f"unknown command: {a.cmd}", file=sys.stderr)
            return 1
    except NotFound as e:
        print(f"not found: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 — never print data in an error
        print(f"adapter error: {type(e).__name__}", file=sys.stderr)
        return 1
    json.dump(no_controls(out), sys.stdout, ensure_ascii=False, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
