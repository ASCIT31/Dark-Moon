"""
Scope index — automatic indexing of bug-bounty programmes per platform.

Fetches programme listings (and, per programme, the in/out-of-scope assets)
from HackerOne, Bugcrowd, Intigriti and YesWeHack, normalises them into one
record shape, and persists the index under darkmoon-settings/scope_index/ so
the engine (which bind-mounts that directory) and the Web UI agree on scope.

Platform reality (verified live 2026-11-04):
  - YesWeHack:  public REST API, no auth. api.yeswehack.com/programs (paged),
                per-program detail carries `scopes` + `out_of_scope`.
  - HackerOne:  api.hackerone.com/v1/hackers/programs with HTTP Basic auth
                (api token). Unauthenticated GraphQL is Cloudflare-blocked.
  - Intigriti:  api.intigriti.com requires a personal access token
                (app.intigriti.com/researcher/profile/authorization).
  - Bugcrowd:   api.bugcrowd.com requires Basic auth (email + password).

Credentials come from .opencode.env (same file the Settings page writes),
so users configure them once in Settings → Environment:
  HACKERONE_API_TOKEN=...
  INTIGRITI_API_TOKEN=...
  BUGCROWD_EMAIL=... / BUGCROWD_PASSWORD=...
  YESWEHACK_API_TOKEN=...        (optional; works without)

No platform returns the programme's automation/rate policy text through these
endpoints, so the indexer never invents one: programmes launch with the engine
default policy until the operator fills it from the brief.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack")

ASSET_TYPE_WEB = ("URL", "WILDCARD", "WEB", "DOMAIN", "API", "APK", "IP", "CIDR")

_USER_AGENT = "Mozilla/5.0 (DarkMoon scope indexer; local engine)"


# ---------------------------------------------------------------------------
# HTTP helpers (urllib only — no new dependencies in the UI image)
# ---------------------------------------------------------------------------

def _http_json(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """GET/POST a JSON API. Returns {'ok', 'status', 'json'|'text'|'error'}.

    Never raises: platform failures (auth, Cloudflare, schema drift) are
    returned as data so the UI can show per-platform errors without a 500.
    """
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": f"HTTP {exc.code} from {url.split('?')[0]}"}
    except Exception as exc:  # network down, TLS, DNS...
        return {"ok": False, "status": None, "error": f"{type(exc).__name__}: {exc}"}

    try:
        return {"ok": True, "status": status, "json": json.loads(raw)}
    except json.JSONDecodeError:
        return {"ok": False, "status": status, "error": "response is not JSON", "text": raw[:500]}


def _basic_auth(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


# ---------------------------------------------------------------------------
# Credentials (from .opencode.env, written by the Settings page)
# ---------------------------------------------------------------------------

_ENV_KEYS = {
    "hackerone": ("HACKERONE_API_TOKEN",),
    "intigriti": ("INTIGRITI_API_TOKEN",),
    "bugcrowd": ("BUGCROWD_EMAIL", "BUGCROWD_PASSWORD"),
    "yeswehack": ("YESWEHACK_API_TOKEN",),  # optional
}


def _load_env(env_file: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip().strip("'\"")
    except OSError:
        pass
    for k, v in os.environ.items():
        out.setdefault(k, v)
    return out


def _platform_credentials(platform: str, env_file: Path) -> Dict[str, str]:
    env = _load_env(env_file)
    return {k: env[k] for k in _ENV_KEYS.get(platform, ()) if env.get(k)}


def _missing_creds(platform: str) -> List[str]:
    # YesWeHack works without auth — its token entry stays in _ENV_KEYS (the
    # fetcher uses it when present) but it must not be reported as required.
    optional = {"yeswehack": ("YESWEHACK_API_TOKEN",)}.get(platform, ())
    return [k for k in _ENV_KEYS.get(platform, ()) if k not in optional]


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def _norm_program(
    platform: str,
    handle: str,
    name: str,
    url: str,
    bounty_min: Optional[int],
    bounty_max: Optional[int],
    in_scope: List[Dict[str, Any]],
    out_scope: List[Dict[str, Any]],
    rules: str = "",
) -> Dict[str, Any]:
    """One unified programme record. Scope entries: {asset, type, note}."""
    return {
        "platform": platform,
        "handle": handle,
        "name": name,
        "url": url,
        "bounty_min": bounty_min,
        "bounty_max": bounty_max,
        "in_scope": in_scope,
        "out_scope": out_scope,
        "rules": rules,
        "indexed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _norm_asset(asset: str, atype: str, note: str = "") -> Dict[str, Any]:
    return {"asset": str(asset or "").strip(), "type": str(atype or "").strip(), "note": str(note or "").strip()}


# ---------------------------------------------------------------------------
# YesWeHack — public REST, no auth
# ---------------------------------------------------------------------------

def _yeswehack_programs(env: Dict[str, str]) -> Dict[str, Any]:
    headers = {}
    if env.get("YESWEHACK_API_TOKEN"):
        headers["Authorization"] = f"Bearer {env['YESWEHACK_API_TOKEN']}"
    programs: List[Dict[str, Any]] = []
    page = 1
    while True:
        r = _http_json(f"https://api.yeswehack.com/programs?page={page}&limit=50", headers=headers)
        if not r.get("ok") or not isinstance(r.get("json"), dict):
            return {"ok": False, "platform": "yeswehack", "error": r.get("error") or "unexpected payload", "programs": programs}
        data = r["json"]
        items = data.get("items") or []
        for p in items:
            if not isinstance(p, dict) or not p.get("slug"):
                continue
            programs.append(
                _norm_program(
                    "yeswehack",
                    p["slug"],
                    p.get("title") or p["slug"],
                    f"https://yeswehack.com/programs/{p['slug']}",
                    p.get("bounty_reward_min"),
                    p.get("bounty_reward_max"),
                    in_scope=[],
                    out_scope=[],
                )
            )
        if page >= int(data.get("pagination", {}).get("nb_pages") or 1):
            break
        page += 1
        if page > 30:  # hard cap: a pagination that never ends must not hang the indexer
            break
    return {"ok": True, "platform": "yeswehack", "programs": programs}


def _yeswehack_program_detail(handle: str, env: Dict[str, str]) -> Dict[str, Any]:
    headers = {}
    if env.get("YESWEHACK_API_TOKEN"):
        headers["Authorization"] = f"Bearer {env['YESWEHACK_API_TOKEN']}"
    r = _http_json(f"https://api.yeswehack.com/programs/{handle}", headers=headers)
    if not r.get("ok") or not isinstance(r.get("json"), dict):
        return {"ok": False, "error": r.get("error") or "unexpected payload"}
    d = r["json"]
    in_scope = [
        _norm_asset(s.get("scope"), s.get("scope_type_name") or s.get("scope_type"), s.get("report_count") or "")
        for s in (d.get("scopes") or [])
        if isinstance(s, dict) and s.get("scope")
    ]
    out_scope = [_norm_asset(x, "out-of-scope") for x in (d.get("out_of_scope") or []) if isinstance(x, str) and x.strip()]
    return {
        "ok": True,
        "program": _norm_program(
            "yeswehack",
            d.get("slug") or handle,
            d.get("title") or handle,
            f"https://yeswehack.com/programs/{handle}",
            d.get("bounty_reward_min"),
            d.get("bounty_reward_max"),
            in_scope,
            out_scope,
        ),
    }


# ---------------------------------------------------------------------------
# HackerOne — REST API, HTTP Basic auth with an API token
# ---------------------------------------------------------------------------

def _hackerone_programs(env: Dict[str, str]) -> Dict[str, Any]:
    token = env.get("HACKERONE_API_TOKEN") or ""
    if not token:
        return {"ok": False, "platform": "hackerone", "error": "HACKERONE_API_TOKEN missing — set it in Settings → Environment", "programs": []}
    identifier = env.get("HACKERONE_IDENTIFIER") or token.split(":")[0] if ":" in token else token
    headers = {"Authorization": _basic_auth(identifier, token)}
    programs: List[Dict[str, Any]] = []
    page = 1
    while True:
        r = _http_json(f"https://api.hackerone.com/v1/hackers/programs?page[number]={page}&page[size]=50", headers=headers)
        if not r.get("ok") or not isinstance(r.get("json"), dict):
            return {"ok": False, "platform": "hackerone", "error": r.get("error") or "unexpected payload", "programs": programs}
        data = r["json"].get("data") or []
        if not data:
            break
        for item in data:
            attrs = item.get("attributes") or {}
            handle = attrs.get("handle") or ""
            if not handle:
                continue
            programs.append(
                _norm_program(
                    "hackerone",
                    handle,
                    attrs.get("name") or handle,
                    f"https://hackerone.com/{handle}",
                    attrs.get("bounty_min") if attrs.get("bounty_min") is not None else None,
                    attrs.get("bounty_max") if attrs.get("bounty_max") is not None else None,
                    [],
                    [],
                )
            )
        if len(data) < 50 or page > 20:
            break
        page += 1
    return {"ok": True, "platform": "hackerone", "programs": programs}


def _hackerone_program_detail(handle: str, env: Dict[str, str]) -> Dict[str, Any]:
    token = env.get("HACKERONE_API_TOKEN") or ""
    if not token:
        return {"ok": False, "error": "HACKERONE_API_TOKEN missing — set it in Settings → Environment"}
    identifier = token.split(":")[0] if ":" in token else token
    headers = {"Authorization": _basic_auth(identifier, token)}
    r = _http_json(f"https://api.hackerone.com/v1/hackers/programs/{handle}", headers=headers)
    if not r.get("ok") or not isinstance(r.get("json"), dict):
        return {"ok": False, "error": r.get("error") or "unexpected payload"}
    attrs = r["json"].get("attributes") or {}
    rel = (r["json"].get("relationships") or {}).get("structured_scopes") or {}
    in_scope, out_scope = [], []
    for s in rel.get("data") or []:
        sa = s.get("attributes") or {}
        asset = _norm_asset(sa.get("asset_identifier"), sa.get("asset_type"), sa.get("instruction") or "")
        if sa.get("eligible_for_bounty") or sa.get("eligible_for_submission"):
            in_scope.append(asset)
        else:
            out_scope.append(asset)
    return {
        "ok": True,
        "program": _norm_program(
            "hackerone",
            attrs.get("handle") or handle,
            attrs.get("name") or handle,
            f"https://hackerone.com/{handle}",
            attrs.get("bounty_min"),
            attrs.get("bounty_max"),
            in_scope,
            out_scope,
        ),
    }


# ---------------------------------------------------------------------------
# Intigriti — REST API, personal access token
# ---------------------------------------------------------------------------

def _intigriti_programs(env: Dict[str, str]) -> Dict[str, Any]:
    token = env.get("INTIGRITI_API_TOKEN") or ""
    if not token:
        return {"ok": False, "platform": "intigriti", "error": "INTIGRITI_API_TOKEN missing — create one at app.intigriti.com/researcher/profile/authorization", "programs": []}
    headers = {"Authorization": f"Bearer {token}"}
    programs: List[Dict[str, Any]] = []
    page = 0
    while True:
        r = _http_json(f"https://api.intigriti.com/external/researcher/v1/marketplace/projects?maxRecords=50&pageNumber={page}", headers=headers)
        if not r.get("ok") or not isinstance(r.get("json"), list):
            return {"ok": False, "platform": "intigriti", "error": r.get("error") or "unexpected payload", "programs": programs}
        if not r["json"]:
            break
        for p in r["json"]:
            handle = p.get("id") or p.get("handle") or ""
            if not handle:
                continue
            bounty = p.get("minReward") or {}
            programs.append(
                _norm_program(
                    "intigriti",
                    handle,
                    p.get("name") or handle,
                    f"https://app.intigriti.com/programs/{handle}",
                    bounty.get("value") if isinstance(bounty, dict) else None,
                    (p.get("maxReward") or {}).get("value") if isinstance(p.get("maxReward"), dict) else None,
                    [],
                    [],
                )
            )
        page += 1
        if page > 20:
            break
    return {"ok": True, "platform": "intigriti", "programs": programs}


def _intigriti_program_detail(handle: str, env: Dict[str, str]) -> Dict[str, Any]:
    token = env.get("INTIGRITI_API_TOKEN") or ""
    if not token:
        return {"ok": False, "error": "INTIGRITI_API_TOKEN missing"}
    headers = {"Authorization": f"Bearer {token}"}
    r = _http_json(f"https://api.intigriti.com/external/researcher/v1/marketplace/projects/{handle}", headers=headers)
    if not r.get("ok") or not isinstance(r.get("json"), dict):
        return {"ok": False, "error": r.get("error") or "unexpected payload"}
    d = r["json"]
    in_scope, out_scope = [], []
    for engagement in d.get("types") or []:
        if not isinstance(engagement, dict):
            continue
        for domain in engagement.get("domains") or []:
            if not isinstance(domain, dict) or not domain.get("url"):
                continue
            asset = _norm_asset(domain["url"], engagement.get("typeName") or "web", domain.get("instruction") or "")
            if domain.get("inScope", True):
                in_scope.append(asset)
            else:
                out_scope.append(asset)
    return {
        "ok": True,
        "program": _norm_program(
            "intigriti",
            d.get("id") or handle,
            d.get("name") or handle,
            f"https://app.intigriti.com/programs/{handle}",
            (d.get("minReward") or {}).get("value") if isinstance(d.get("minReward"), dict) else None,
            (d.get("maxReward") or {}).get("value") if isinstance(d.get("maxReward"), dict) else None,
            in_scope,
            out_scope,
        ),
    }


# ---------------------------------------------------------------------------
# Bugcrowd — REST API, Basic auth (email + password)
# ---------------------------------------------------------------------------

def _bugcrowd_session(env: Dict[str, str]) -> Dict[str, Any]:
    email, password = env.get("BUGCROWD_EMAIL") or "", env.get("BUGCROWD_PASSWORD") or ""
    if not email or not password:
        return {"ok": False, "error": "BUGCROWD_EMAIL / BUGCROWD_PASSWORD missing — set them in Settings → Environment"}
    r = _http_json(
        "https://api.bugcrowd.com/login",
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        body=json.dumps({"email": email, "password": password}).encode("utf-8"),
    )
    if not r.get("ok") or not isinstance(r.get("json"), dict):
        return {"ok": False, "error": r.get("error") or "login failed"}
    token = r["json"].get("token") or r["json"].get("session") or ""
    if not token:
        return {"ok": False, "error": "login response carried no token"}
    return {"ok": True, "token": token}


def _bugcrowd_programs(env: Dict[str, str]) -> Dict[str, Any]:
    sess = _bugcrowd_session(env)
    if not sess.get("ok"):
        return {"ok": False, "platform": "bugcrowd", "error": sess.get("error"), "programs": []}
    headers = {"Authorization": f"Bearer {sess['token']}"}
    programs: List[Dict[str, Any]] = []
    page = 1
    while True:
        r = _http_json(f"https://api.bugcrowd.com/programs?page={page}", headers=headers)
        if not r.get("ok") or not isinstance(r.get("json"), dict):
            return {"ok": False, "platform": "bugcrowd", "error": r.get("error") or "unexpected payload", "programs": programs}
        items = r["json"].get("programs") or r["json"].get("data") or []
        if not items:
            break
        for p in items:
            handle = p.get("program_handle") or p.get("handle") or ""
            if not handle:
                continue
            programs.append(
                _norm_program(
                    "bugcrowd",
                    handle,
                    p.get("name") or handle,
                    f"https://bugcrowd.com/{handle}",
                    p.get("min_payout") or p.get("bounty_min"),
                    p.get("max_payout") or p.get("bounty_max"),
                    [],
                    [],
                )
            )
        page += 1
        if page > 20:
            break
    return {"ok": True, "platform": "bugcrowd", "programs": programs}


def _bugcrowd_program_detail(handle: str, env: Dict[str, str]) -> Dict[str, Any]:
    sess = _bugcrowd_session(env)
    if not sess.get("ok"):
        return {"ok": False, "error": sess.get("error")}
    headers = {"Authorization": f"Bearer {sess['token']}"}
    r = _http_json(f"https://api.bugcrowd.com/programs/{handle}/targets", headers=headers)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error")}
    data = r["json"] if isinstance(r["json"], list) else (r["json"].get("targets") or [])
    in_scope, out_scope = [], []
    for t in data:
        if not isinstance(t, dict):
            continue
        name = t.get("name") or t.get("target") or ""
        if not name:
            continue
        note = t.get("instructions") or ""
        asset = _norm_asset(name, t.get("target_type") or "web", note)
        if (t.get("in_scope") is False) or t.get("target_type") == "out-of-scope":
            out_scope.append(asset)
        else:
            in_scope.append(asset)
    return {
        "ok": True,
        "program": _norm_program("bugcrowd", handle, handle, f"https://bugcrowd.com/{handle}", None, None, in_scope, out_scope),
    }


# ---------------------------------------------------------------------------
# Registry + orchestrator
# ---------------------------------------------------------------------------

_LISTERS: Dict[str, Callable[[Dict[str, str]], Dict[str, Any]]] = {
    "hackerone": _hackerone_programs,
    "bugcrowd": _bugcrowd_programs,
    "intigriti": _intigriti_programs,
    "yeswehack": _yeswehack_programs,
}

_DETAILS: Dict[str, Callable[[str, Dict[str, str]], Dict[str, Any]]] = {
    "hackerone": _hackerone_program_detail,
    "bugcrowd": _bugcrowd_program_detail,
    "intigriti": _intigriti_program_detail,
    "yeswehack": _yeswehack_program_detail,
}


def list_platform_programs(platform: str, env_file: Path) -> Dict[str, Any]:
    """Fetch the programme listing for one platform."""
    fn = _LISTERS.get(platform)
    if not fn:
        return {"ok": False, "platform": platform, "error": f"unknown platform '{platform}'", "programs": []}
    return fn(_platform_credentials(platform, env_file))


def fetch_program_detail(platform: str, handle: str, env_file: Path) -> Dict[str, Any]:
    """Fetch one programme's scope detail."""
    fn = _DETAILS.get(platform)
    if not fn:
        return {"ok": False, "error": f"unknown platform '{platform}'"}
    return fn(handle, _platform_credentials(platform, env_file))


def _scope_index_dir(data_dir: Path) -> Path:
    d = data_dir / "scope_index"
    (d / "programs").mkdir(parents=True, exist_ok=True)
    return d


def _program_key(platform: str, handle: str) -> str:
    return f"{platform}:{re.sub(r'[^a-zA-Z0-9_.-]', '_', handle)}"


def store_program(data_dir: Path, program: Dict[str, Any]) -> Path:
    """Persist one programme record (scope included) and refresh the index."""
    d = _scope_index_dir(data_dir)
    fname = f"{program['platform']}_{program['handle']}.json"
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", fname)
    path = d / "programs" / safe
    path.write_text(json.dumps(program, ensure_ascii=False, indent=1), encoding="utf-8")
    _rebuild_index(d)
    return path


def _rebuild_index(d: Path) -> None:
    entries = []
    for f in sorted((d / "programs").glob("*.json")):
        try:
            p = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        entries.append(
            {
                "platform": p.get("platform"),
                "handle": p.get("handle"),
                "name": p.get("name"),
                "url": p.get("url"),
                "bounty_min": p.get("bounty_min"),
                "bounty_max": p.get("bounty_max"),
                "in_scope_count": len(p.get("in_scope") or []),
                "indexed_at": p.get("indexed_at"),
            }
        )
    (d / "index.json").write_text(
        json.dumps({"updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "programs": entries}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )


def load_index(data_dir: Path) -> Dict[str, Any]:
    d = _scope_index_dir(data_dir)
    try:
        return json.loads((d / "index.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"updated_at": None, "programs": []}


def load_program(data_dir: Path, platform: str, handle: str) -> Optional[Dict[str, Any]]:
    d = _scope_index_dir(data_dir)
    f = d / "programs" / f"{platform}_{handle}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def refresh_platforms(platforms: List[str], env_file: Path, data_dir: Path, detail_limit: int = 25) -> Dict[str, Any]:
    """Index the listing for each requested platform IN PARALLEL, then pull the
    scope detail for the first `detail_limit` programmes of each.

    YesWeHack is free; the others stay silent (empty) until their credentials
    are set, and that fact is reported per platform instead of raising.
    """
    results: Dict[str, Any] = {}
    per_platform: Dict[str, List[Dict[str, Any]]] = {}

    def run_one(platform: str) -> Dict[str, Any]:
        return list_platform_programs(platform, env_file)

    with ThreadPoolExecutor(max_workers=len(platforms) or 1) as pool:
        futures = {pool.submit(run_one, p): p for p in platforms if p in PLATFORMS}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                results[p] = fut.result()
            except Exception as exc:  # defensive: one platform must not kill the batch
                results[p] = {"ok": False, "platform": p, "error": f"{type(exc).__name__}: {exc}", "programs": []}

    for platform, res in results.items():
        programs = res.get("programs") or []
        per_platform[platform] = programs
        if res.get("ok"):
            with ThreadPoolExecutor(max_workers=6) as pool:
                detail_futures = {pool.submit(fetch_program_detail, platform, p["handle"], env_file): p for p in programs[:detail_limit]}
                for fut in as_completed(detail_futures):
                    p = detail_futures[fut]
                    try:
                        det = fut.result()
                    except Exception:
                        det = None
                    if det and det.get("ok") and det.get("program"):
                        store_program(data_dir, det["program"])
                        p.update(
                            {
                                "in_scope_count": len(det["program"]["in_scope"]),
                                "out_scope_count": len(det["program"]["out_scope"]),
                            }
                        )
            for p in programs:
                if "in_scope_count" not in p:
                    existing = load_program(data_dir, platform, p["handle"])
                    if existing:
                        p.update({"in_scope_count": len(existing["in_scope"]), "out_scope_count": len(existing["out_scope"])})

    indexed = {p: len(v) for p, v in per_platform.items()}
    return {
        "ok": True,
        "indexed": indexed,
        "errors": {p: r.get("error") for p, r in results.items() if not r.get("ok")},
    }


def needs_credentials(platform: str) -> List[str]:
    return _missing_creds(platform)
