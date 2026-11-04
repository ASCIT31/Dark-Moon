"""
CVE Lookup Workflow — automatic, applicable CVE discovery.

Fingerprint a product (whatweb / cmseek / nuclei tags / version banners),
then ask the NVD for every CVE ever published against it — recent first,
all-time as fallback — and hand the agent a machine-readable shortlist it can
immediately validate with targeted nuclei templates.

Added 2026-11-03 after the ALSCO / Secure Gateway campaign audit: the engine
had NO automated CVE-discovery step at all, so version-banner matches relied
on the model remembering CVE numbers — the exact failure mode that produced
the wrong-rule-id citation in the same campaign (see
docs/workflow-errors-register.md E3).

No API key required: this uses the public NVD REST API 2.0
(https://services.nvd.nist.gov/req.json), tolerant of its polite rate limit
(5 requests / 30 s without a key — one workflow call issues ONE request).
"""

import json
import shlex
from typing import Dict, Any, List, Optional
from src.tools.workflows.base import BaseWorkflow


class CveLookupWorkflow(BaseWorkflow):
    """
    Automatic CVE discovery for a fingerprinted product/version.

    Use cases:
    - After fingerprinting: whatweb/cmseek/nuclei identify "Royal CMS 2.1"
      -> search_cves("royal cms", "2.1") returns every applicable CVE.
    - Historical reach: recent_years=0 searches ALL published CVEs, not just
      recent ones — an old product on an unpatched box is often the whole bug.
    - Precision: get_cve("CVE-2024-1234") for the full record of one advisory.
    """

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def search_cves(
        self,
        product: str,
        version: str = "",
        max_results: int = 15,
        recent_years: int = 5,
        min_severity: str = "",
        timeout: int = 40,
    ) -> Dict[str, Any]:
        """
        Search published CVEs for a product (NVD 2.0 keyword search).

        Workflow:
        1. Build a keyword query (`product`, plus `version` when given)
        2. One NVD request — recent window when recent_years > 0,
           all-time when recent_years == 0
        3. Parse + rank (CVSS desc), filter by min_severity when given

        Args:
            product: Product name as fingerprinted (e.g. "royal cms", "apache struts")
            version: Optional version, narrows the match ("2.1", "7.4")
            max_results: Cap on returned CVEs (default 15, max 30)
            recent_years: Window in years from today (default 5).
                          0 = search ALL published CVEs, no date filter.
            min_severity: Optional floor ("low", "medium", "high", "critical").
                          Empty = no floor.
            timeout: Total budget in seconds (default 40)

        Returns:
            {query, window, count, cves: [{id, published, cvss, severity,
            description, references, applicable_to}] }
        """
        product = (product or "").strip()
        if not product:
            return {"error": "product is required (e.g. 'royal cms')"}

        keyword = f"{product} {version}".strip() if version else product
        max_results = max(1, min(int(max_results), 30))

        steps: Dict[str, Any] = {}
        setup_timeout = 5

        # -- Build the NVD query ------------------------------------------------
        # Keyword search is quoted so multi-word products match as a phrase.
        q = shlex.quote(keyword)
        params = [f"keywordSearch={q}", f"resultsPerPage={max_results}"]

        if recent_years and int(recent_years) > 0:
            from datetime import datetime, timedelta, timezone

            end = datetime.now(timezone.utc)
            start = end - timedelta(days=365 * int(recent_years))
            fmt = "%Y-%m-%dT%H:%M:%S.000"
            params.append(f"pubStartDate={start.strftime(fmt)}")
            params.append(f"pubEndDate={end.strftime(fmt)}")
            window = f"last {int(recent_years)}y"
        else:
            window = "all-time"

        url = f"{self.NVD_API}?{'&'.join(params)}"
        quoted_url = shlex.quote(url)

        # -- One NVD request, from inside the toolbox container ------------------
        # (Same egress as every other tool; the container has outbound net.)
        cve_output = f"/tmp/nvd_response_{abs(hash(product)) % 99999}.json"
        success, raw, output = self.execute_step(
            step_name=f"NVD keyword search ({keyword}, {window})",
            command=f"curl -s --max-time {max(timeout - setup_timeout, 10)} {quoted_url} -o {cve_output} && cat {cve_output}",
            timeout=timeout,
            parse_json=False,
        )

        cves: List[Dict[str, Any]] = []
        parse_error = ""
        if success and raw:
            data = raw if isinstance(raw, dict) else None
            if data is None:
                try:
                    data = json.loads(raw) if isinstance(raw, str) else None
                except (ValueError, TypeError):
                    data = None
            if isinstance(data, dict):
                cves = self._parse_nvd(data, version)
            else:
                parse_error = "NVD returned a non-JSON body (rate limited?)"
        elif not success:
            parse_error = f"NVD request failed: {(output or '')[:200]}"

        if min_severity:
            cves = [c for c in cves
                    if self._sev_rank(c.get("severity", "")) <= self._sev_rank(min_severity)]

        steps["nvd_search"] = {
            "success": success,
            "url": url,
            "count": len(cves),
        }

        return {
            "query": {"product": product, "version": version, "keyword": keyword},
            "window": window,
            "count": len(cves),
            "cves": cves,
            "parse_error": parse_error,
            "steps": steps,
            "note": (
                "Rank: CVSS descending. Validate the top entries with targeted "
                "nuclei -tags/-t on the exact template id, or manually when a "
                "template does not exist yet (E3 of docs/workflow-errors-register.md)."
            ),
        }

    def get_cve(self, cve_id: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Fetch one CVE record in full, by id.

        Args:
            cve_id: e.g. "CVE-2024-1234" (case-insensitive, dashes tolerated)
            timeout: Total budget in seconds (default 30)

        Returns:
            The parsed, normalised CVE record (id, cvss, severity, description,
            references, affected CPEs), or an error envelope.
        """
        raw_id = (cve_id or "").strip().upper().replace(" ", "")
        if not raw_id.startswith("CVE-"):
            return {"error": "cve_id must look like CVE-YYYY-NNNN"}

        url = f"{self.NVD_API}?cveId={shlex.quote(raw_id)}"
        quoted_url = shlex.quote(url)

        success, raw, output = self.execute_step(
            step_name=f"NVD single-CVE fetch ({raw_id})",
            command=f"curl -s --max-time {max(timeout - 5, 10)} {quoted_url}",
            timeout=timeout,
            parse_json=False,
        )

        if not (success and raw):
            return {"error": f"NVD request failed: {(output or '')[:200]}"}

        data = raw if isinstance(raw, dict) else None
        if data is None:
            try:
                data = json.loads(raw) if isinstance(raw, str) else None
            except (ValueError, TypeError):
                data = None
        if not isinstance(data, dict):
            return {"error": "NVD returned a non-JSON body (rate limited?)"}

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return {"error": f"{raw_id} not found in the NVD (not published / "
                              "reserved / rejected)"}

        parsed = self._parse_nvd({"vulnerabilities": vulns}, "")
        return parsed[0] if parsed else {"error": f"{raw_id} could not be parsed"}

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _sev_rank(name: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "": 4}
        return order.get(str(name).strip().lower(), 4)

    def _parse_nvd(self, data: Dict[str, Any], version: str) -> List[Dict[str, Any]]:
        """Normalise NVD 2.0 records into the shortlist the agent consumes."""
        out: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cid = cve.get("id", "")

            desc = ""
            for d in cve.get("descriptions") or []:
                if str(d.get("lang", "")).lower().startswith("en"):
                    desc = str(d.get("value", ""))
                    break

            score, severity = 0.0, ""
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for m in metrics.get(key) or []:
                    cd = m.get("cvssData") or {}
                    score = float(cd.get("baseScore") or 0.0)
                    severity = str(cd.get("baseSeverity") or m.get("baseSeverity") or "")
                    break
                if score:
                    break

            refs = [
                str(r.get("url"))
                for r in (cve.get("references") or [])[:4]
                if r.get("url")
            ]

            # Applicability hint: which CPEs did NVD map, does the version
            # appear anywhere in the record?
            cpes: List[str] = []
            for cfg in cve.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for m in node.get("cpeMatch") or []:
                        for cpe in (m.get("criteria") or "").split("OR"):
                            cpe = cpe.strip()
                            if cpe and cpe not in cpes:
                                cpes.append(cpe)
            version_hit = bool(version) and version.lower() in f"{desc} {' '.join(cpes)}".lower()

            out.append({
                "id": cid,
                "published": cve.get("published", ""),
                "cvss": round(score, 1),
                "severity": severity.lower(),
                "description": desc[:400],
                "references": refs,
                "cpes": cpes[:6],
                "version_hint_match": version_hit,
            })

        out.sort(key=lambda c: (-c["cvss"], c["id"]))
        return out