"""Tests for the Community data adapter (stdlib only: python3 -m unittest test_darkmoon_explore)."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import darkmoon_explore as dx  # noqa: E402

SECRET = "Zq8vLm2pXr7Tn4-not-a-real-password"


def run(data: Path, *args: str):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = dx.main(["--data", str(data), "--mcp", "/nonexistent", *args])
    return code, out.getvalue(), err.getvalue()


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "data"
        (self.root / "campaigns").mkdir(parents=True)
        (self.root / "vulnerabilities").mkdir()
        (self.root / "reports").mkdir()
        (self.root / "projects.json").write_text(json.dumps([{"id": "p1", "name": "Lab", "target_id": "t1"}]))
        (self.root / "targets.json").write_text(json.dumps([{"id": "t1", "host": "10.0.0.5"}]))
        (self.root / "campaigns" / "c1.json").write_text(json.dumps(
            {"id": "c1", "project_id": "p1", "date": "2026-11-18T10:00:00Z", "report_path": "/reports/r1.md"}))
        (self.root / "campaigns" / "sub.json").write_text(json.dumps({"id": "sub", "is_subagent": True}))
        vulns = [
            {"id": "v1", "title": "Creds", "severity": "critical", "status": "exploited",
             "evidence": {"raw_response": f'{{"password":"{SECRET}"}}', "explanation": "dumped"}},
            {"id": "v2", "title": "RCE", "severity": "high", "status": "exploited", "enabled_by": ["v1"],
             "evidence": {"commands": [f"sshpass -p {SECRET} ssh root@x"]}},
        ]
        (self.root / "vulnerabilities" / "c1.json").write_text(json.dumps(vulns))
        (self.root / "reports" / "r1.md").write_text(f"# Report\n\npassword={SECRET}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_shapes_match_the_api(self):
        code, out, _ = run(self.root, "projects")
        p = json.loads(out)["data"][0]
        self.assertEqual((code, p["campaigns_count"], p["vulnerabilities_count"], p["latest_risk"]), (0, 1, 2, "critical"))
        self.assertEqual(p["target"]["host"], "10.0.0.5")
        code, out, _ = run(self.root, "campaigns")
        self.assertEqual([c["id"] for c in json.loads(out)["data"]], ["c1"])  # sub-agent runs hidden
        code, out, _ = run(self.root, "vulnerabilities", "--project", "p1")
        self.assertEqual(json.loads(out)["stats"]["by_severity"], {"critical": 1, "high": 1})

    def test_counts_use_the_one_stats_function(self):
        """exec_core.stats (vendored copy, no MCP installed): held and false-positive findings counted nowhere."""
        extra = json.loads((self.root / "vulnerabilities" / "c1.json").read_text()) + [
            {"id": "v3", "title": "Held", "severity": "critical", "status": "exploited", "quarantined": True},
            {"id": "v4", "title": "FP", "severity": "high", "status": "false_positive"},
            {"id": "v5", "title": "Low", "severity": "Low", "status": "confirmed"},
        ]
        (self.root / "vulnerabilities" / "c1.json").write_text(json.dumps(extra))
        code, out, _ = run(self.root, "campaign", "c1")
        st = json.loads(out)["data"]["stats"]
        self.assertEqual((code, st["total_findings"], st["critical"], st["high"], st["low"]), (0, 3, 1, 1, 1))
        self.assertEqual(st["excluded"], {"quarantined": 1, "false_positive": 1})
        code, out, _ = run(self.root, "projects")
        p = json.loads(out)["data"][0]
        self.assertEqual((p["vulnerabilities_count"], p["latest_risk"]), (3, "critical"))

    def test_fail_closed_without_redaction_engine(self):
        real = dx.load_redaction
        dx.load_redaction = lambda *_: None  # the engine cannot be loaded
        self.addCleanup(setattr, dx, "load_redaction", real)
        for args in (["finding", "v1"], ["campaign", "c1"], ["vulnerabilities"], ["report", "c1"], ["finding", "v2"]):
            code, out, _ = run(self.root, *args)
            self.assertEqual(code, 0, args)
            self.assertNotIn(SECRET, out, args)
        f = json.loads(run(self.root, "finding", "v1")[1])["data"]
        self.assertEqual(f["evidence"], {"withheld": True})
        self.assertIn("Report withheld", json.loads(run(self.root, "report", "c1")[1])["content"])

    def test_masked_when_the_engine_is_available(self):
        if dx.load_redaction(None) is None:
            self.skipTest("no redaction engine next to the adapter (Pro image uses the server one)")
        for args in (["finding", "v1"], ["finding", "v2"], ["report", "c1"]):
            code, out, _ = run(self.root, *args)
            self.assertEqual(code, 0, args)
            self.assertNotIn(SECRET, out, args)
            self.assertIn("redacted", out, args)

    def test_report_rendered_from_the_model_keeps_working(self):
        """L6: the report file is the Markdown of the exec_core report model; the report command shows it masked
        (section markers kept for the TUI) and still withholds it without the redaction engine."""
        vendor = str(Path(__file__).resolve().parent / "_vendor")
        if vendor not in sys.path:
            sys.path.insert(0, vendor)
        from exec_core import report_markdown, report_model  # vendored, byte-identical to the MCP server's
        vulns = json.loads((self.root / "vulnerabilities" / "c1.json").read_text())
        md = report_markdown.render(report_model.build({"edition": "community", "campaign": {"id": "c1", "status": "completed"},
                                                        "findings": vulns, "generated_at": "2026-11-20T00:00:00Z"}))
        self.assertIn(SECRET, md)                       # worst case: a file written without masking
        (self.root / "reports" / "r1.md").write_text(md)
        if dx.load_redaction(None) is not None:
            code, out, _ = run(self.root, "report", "c1")
            content = json.loads(out)["content"]
            self.assertEqual(code, 0)
            self.assertNotIn(SECRET, content)
            self.assertIn("<!-- dm-section: cyber-score -->", content)
            self.assertLess(content.index("dm-section: cyber-score"), content.index("dm-section: detailed-findings"))
        real = dx.load_redaction
        dx.load_redaction = lambda *_: None
        self.addCleanup(setattr, dx, "load_redaction", real)
        out = run(self.root, "report", "c1")[1]
        self.assertNotIn(SECRET, out)
        self.assertIn("Report withheld", json.loads(out)["content"])

    def test_declared_links_stay_hypotheses(self):
        doc = json.loads(run(self.root, "paths", "c1")[1])
        self.assertEqual(doc["summary"]["proven_paths"], 0)
        self.assertEqual(doc["summary"]["declared_paths"], 1)
        p = doc["paths"][0]
        self.assertEqual((p["provenance"], p["hypothesis"]), ("agent-declared", True))
        self.assertEqual(p["finding_ids"], ["v1", "v2"])

    def test_path_traversal_and_bad_ids_refused(self):
        for args in (["campaign", "../../etc/passwd"], ["finding", "../x"], ["campaign", "a/b"], ["report", ".."]):
            code, out, err = run(self.root, *args)
            self.assertEqual((code, out), (2, ""), args)

    def test_symlink_leaving_the_root_is_refused(self):
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_text(json.dumps({"id": "evil", "secret": SECRET}))
        os.symlink(outside, self.root / "campaigns" / "evil.json")
        code, out, _ = run(self.root, "campaign", "evil")
        self.assertEqual(code, 2)
        self.assertNotIn(SECRET, out)
        code, out, _ = run(self.root, "campaigns")
        self.assertNotIn(SECRET, out)

    def test_report_symlink_outside_refused(self):
        outside = Path(self.tmp.name) / "secret.md"
        outside.write_text(SECRET)
        (self.root / "reports" / "r1.md").unlink()
        os.symlink(outside, self.root / "reports" / "r1.md")
        code, out, _ = run(self.root, "report", "c1")
        self.assertNotIn(SECRET, out)

    def test_unknown_command_and_missing(self):
        self.assertEqual(run(self.root, "nope")[0], 1)
        self.assertEqual(run(self.root, "finding", "v9")[0], 2)


if __name__ == "__main__":
    unittest.main()


class LocalEngineTests(unittest.TestCase):
    """With the MCP server tree available (as in the image), paths come from its attack-path read model."""

    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown

    MCP = Path(__file__).resolve().parents[3] / "mcp"

    def paths(self, cid: str):
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "DARKMOON_DATA_DIR"}
        return subprocess.run([sys.executable, str(Path(dx.__file__)), "--data", str(self.root), "--mcp", str(self.MCP),
                               "paths", cid], capture_output=True, text=True, env=env, timeout=60)

    @unittest.skipUnless((Path(__file__).resolve().parents[3] / "mcp" / "api" / "attack_paths_local.py").is_file(),
                         "MCP server tree not next to the plugin")
    def test_paths_use_the_engine_and_stay_hypotheses(self):
        r = self.paths("c1")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertIn("schema_revision", doc)  # the engine's document, not the declarations-only fallback
        self.assertEqual(doc["summary"]["proven_paths"], 0)
        declared = [p for p in doc["paths"] if p["provenance"] == "agent-declared"]
        self.assertTrue(declared)
        self.assertTrue(all(p["hypothesis"] and p["level"] == "declared_by_agent" for p in declared))
        self.assertNotIn(SECRET, r.stdout)
        self.assertEqual(self.paths("../etc").returncode, 2)

    @unittest.skipUnless((Path(__file__).resolve().parents[3] / "mcp" / "api" / "attack_paths_local.py").is_file(),
                         "MCP server tree not next to the plugin")
    def test_a_secret_repeated_in_titles_is_masked_everywhere(self):
        vulns = json.loads((self.root / "vulnerabilities" / "c1.json").read_text())
        vulns[1]["title"] = f"Login as admin with {SECRET}"
        vulns[1]["remediation"] = f"rotate {SECRET}"
        (self.root / "vulnerabilities" / "c1.json").write_text(json.dumps(vulns))
        c = json.loads((self.root / "campaigns" / "c1.json").read_text())
        c["executive_summary"] = f"admin password is {SECRET}"
        (self.root / "campaigns" / "c1.json").write_text(json.dumps(c))
        r = self.paths("c1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(SECRET, r.stdout)
        self.assertTrue(json.loads(r.stdout)["paths"])


class RobustnessTests(unittest.TestCase):
    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown

    def test_one_malformed_file_does_not_empty_the_listings(self):
        (self.root / "campaigns" / "broken.json").write_text('{"id": "broken"')
        (self.root / "vulnerabilities" / "broken.json").write_text("[{")
        code, out, _ = run(self.root, "campaigns")
        self.assertEqual(code, 0)
        self.assertEqual([c["id"] for c in json.loads(out)["data"]], ["c1"])
        code, out, _ = run(self.root, "vulnerabilities")
        self.assertEqual((code, len(json.loads(out)["data"])), (0, 2))

    def test_terminal_control_sequences_are_stripped(self):
        vulns = json.loads((self.root / "vulnerabilities" / "c1.json").read_text())
        vulns[0]["title"] = "A\x1b]52;c;cGF5bG9hZA==\x07B\x9d8;;http://x\x9cC‮D"
        vulns[0]["severity"] = "high\x1b[2J"
        (self.root / "vulnerabilities" / "c1.json").write_text(json.dumps(vulns))
        code, out, _ = run(self.root, "vulnerabilities")
        self.assertEqual(code, 0)
        self.assertFalse(any(ch in out for ch in ("\x1b", "\x07", "\x9d", "\x9c", "‮")))


_HAS_MCP = (Path(__file__).resolve().parents[3] / "mcp" / "api" / "treatment_local.py").is_file()


class PlanTests(unittest.TestCase):
    """``plan CAMPAIGN_ID``: the Prioritized Treatment Plan, the owner's declarations file validated on read,
    read-only, redacted, fail closed. Data lives in throw-away directories only."""

    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown
    MCP = LocalEngineTests.MCP

    def plan(self, cid: str = "c1"):
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "DARKMOON_DATA_DIR"}
        return subprocess.run([sys.executable, str(Path(dx.__file__)), "--data", str(self.root), "--mcp", str(self.MCP),
                               "plan", cid], capture_output=True, text=True, env=env, timeout=60)

    def declare(self, entries, **top):
        d = self.root / "treatments"
        d.mkdir(exist_ok=True)
        (d / "c1.json").write_text(json.dumps({"schema_version": "darkmoon-treatment-declarations/1",
                                               "campaign_id": "c1", "declarations": entries, **top}))

    def test_fail_closed_without_server_or_redaction(self):
        self.assertEqual(run(self.root, "plan", "c1")[0], 2)             # --mcp /nonexistent: no plan module
        real = dx.load_redaction
        dx.load_redaction = lambda *_: None
        self.addCleanup(setattr, dx, "load_redaction", real)
        code, out, err = run(self.root, "plan", "c1")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("withheld", err)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_plan_without_declarations_file(self):
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        p = json.loads(r.stdout)
        self.assertEqual((p["label"], p["verification"], p["can_edit"]), ("Prioritized Treatment Plan", "not_available", False))
        self.assertEqual(p["declarations"]["status"], "absent")
        self.assertTrue(p["actions"])
        self.assertTrue(all(a["status"] == "proposed" for a in p["actions"]))
        self.assertNotIn(SECRET, r.stdout)
        self.assertFalse((self.root / "treatments").exists())          # read-only: nothing written
        self.assertEqual(self.plan("../etc").returncode, 2)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_declared_applied_is_not_verified_and_invalid_entries_are_reported(self):
        aid = json.loads(self.plan().stdout)["actions"][0]["action_id"]
        self.declare([
            {"action_id": aid, "at": "2026-11-20", "by_role": "web team lead", "status": "applied",
             "note": f"rotated {SECRET}"},
            {"action_id": aid, "at": "2026-11-21", "by_role": "x", "status": "verified_resolved"},
            {"action_id": "act_0000000000000000", "at": "2026-11-21", "by_role": "x", "status": "approved"},
            {"action_id": aid, "at": "2026-11-22", "by_role": "x", "status": "applied", "evil": 1},
        ])
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        p = json.loads(r.stdout)
        a = next(x for x in p["actions"] if x["action_id"] == aid)
        self.assertEqual(a["status"], "applied")
        self.assertEqual(a["status_text"], "Declared applied by web team lead, 2026-11-20 — not verified")
        self.assertFalse(a["status_verified"])
        self.assertEqual(len(p["issues"]), 3)
        self.assertNotIn(SECRET, r.stdout)
        # the declaration changes no count
        code, out, _ = run(self.root, "campaign", "c1")
        self.assertEqual(json.loads(out)["data"]["stats"]["total_findings"], 2)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_unreadable_or_foreign_declarations_file(self):
        d = self.root / "treatments"
        d.mkdir()
        (d / "c1.json").write_text("{not json")
        p = json.loads(self.plan().stdout)
        self.assertEqual(p["declarations"]["status"], "unreadable")
        self.assertTrue(all(a["status"] == "proposed" for a in p["actions"]))
        self.declare([], campaign_id="other")
        self.assertEqual(json.loads(self.plan().stdout)["declarations"]["status"], "unreadable")


class FrameworkProfileTests(unittest.TestCase):
    """``frameworks CAMPAIGN_ID`` and ``profile PROJECT_ID``: exec_core assessment and the owner's profile file,
    validated on read, read-only, redacted, fail closed. Data lives in throw-away directories only."""

    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown
    MCP = LocalEngineTests.MCP

    def cmd(self, *args):
        import subprocess
        env = {k: v for k, v in os.environ.items() if k != "DARKMOON_DATA_DIR"}
        return subprocess.run([sys.executable, str(Path(dx.__file__)), "--data", str(self.root), "--mcp", str(self.MCP),
                               *args], capture_output=True, text=True, env=env, timeout=60)

    def declare(self, fields, **top):
        d = self.root / "profiles"
        d.mkdir(exist_ok=True)
        (d / "p1.json").write_text(json.dumps({"schema_version": "darkmoon-application-profile-declarations/1",
                                               "project_id": "p1", "fields": fields, **top}))

    def test_fail_closed_without_server_or_redaction(self):
        self.assertEqual(run(self.root, "frameworks", "c1")[0], 2)
        self.assertEqual(run(self.root, "profile", "p1")[0], 2)
        real = dx.load_redaction
        dx.load_redaction = lambda *_: None
        self.addCleanup(setattr, dx, "load_redaction", real)
        for args in (("frameworks", "c1"), ("profile", "p1")):
            code, out, err = run(self.root, *args)
            self.assertEqual((code, out), (2, ""), args)
            self.assertIn("withheld", err)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_frameworks_without_profile(self):
        r = self.cmd("frameworks", "c1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["schema_version"], "darkmoon-framework-assessment/1")
        self.assertEqual({f["applicability"]["status"] for f in d["frameworks"]}, {"to_confirm"})
        self.assertFalse(d["coverage"]["coverage_ok"])        # no coverage signals in this store
        self.assertNotIn("none_observed_in_tested_scope", {c["state"] for f in d["frameworks"] for c in f["controls"]})
        self.assertNotIn("compliant", r.stdout.lower())
        self.assertNotIn(SECRET, r.stdout)
        self.assertEqual(self.cmd("frameworks", "../etc").returncode, 2)
        self.assertFalse((self.root / "profiles").exists())

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_profile_from_the_owner_file(self):
        r = self.cmd("profile", "p1")
        self.assertEqual(r.returncode, 0, r.stderr)
        p = json.loads(r.stdout)
        self.assertEqual(p["declarations"]["status"], "absent")
        self.assertTrue(all(f["provenance"] in ("unknown", "detected") for f in p["profile"]["fields"].values()))
        self.declare({"business_purpose": {"value": f"Orders portal, password={SECRET}", "by_role": "PO",
                                           "at": "2026-11-20"},
                      "personal_data": {"value": "yes", "provenance": "verified", "at": "2026-11-20", "by_role": "DPO"},
                      "sector": {"value": "health", "provenance": "detected"},
                      "business_owner": "jane@corp.example", "color": "blue"})
        r = self.cmd("profile", "p1")
        self.assertEqual(r.returncode, 0, r.stderr)
        p = json.loads(r.stdout)
        f = p["profile"]["fields"]
        self.assertEqual(f["personal_data"]["provenance"], "verified")
        self.assertEqual(f["sector"]["provenance"], "unknown")          # « detected » is refused in the file
        self.assertIsNone(f["business_owner"]["value"])                 # an e-mail address is not a role
        self.assertEqual(sorted(i.get("field") for i in p["issues"]), ["business_owner", "color", "sector"])
        self.assertNotIn(SECRET, r.stdout)                              # free text redacted on output
        self.assertEqual(p["can_edit"], False)
        d = json.loads(self.cmd("frameworks", "c1").stdout)
        st = {x["framework"]: x["applicability"]["status"] for x in d["frameworks"]}
        self.assertEqual(st["gdpr"], "declared_by_customer")
        self.assertEqual(st["nis2"], "to_confirm")
        self.assertEqual(self.cmd("profile", "nope").returncode, 2)
        self.assertEqual(self.cmd("profile", "../x").returncode, 2)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_unreadable_or_foreign_profile_file(self):
        d = self.root / "profiles"
        d.mkdir()
        (d / "p1.json").write_text("{not json")
        p = json.loads(self.cmd("profile", "p1").stdout)
        self.assertEqual(p["declarations"]["status"], "unreadable")
        self.declare({"sector": "health"}, project_id="other")
        p = json.loads(self.cmd("profile", "p1").stdout)
        self.assertEqual(p["declarations"]["status"], "unreadable")
        self.assertEqual(p["profile"]["fields"]["sector"]["provenance"], "unknown")
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_text(json.dumps({"project_id": "p1", "fields": {"sector": "health"}}))
        (d / "p1.json").unlink()
        os.symlink(outside, d / "p1.json")
        p = json.loads(self.cmd("profile", "p1").stdout)
        self.assertEqual(p["declarations"]["status"], "unreadable")


class ExecutiveTests(unittest.TestCase):
    """``executive`` (campaign / ``--project``) and ``legend``: exec_core documents, read-only, redacted, fail closed;
    Darkmoon's own catalogue texts are never masked while evidence still is."""

    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown
    MCP = LocalEngineTests.MCP
    cmd = FrameworkProfileTests.cmd

    def test_help_lists_every_command(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            dx.main(["--help"])
        for c in ("plan CAMPAIGN_ID", "frameworks CAMPAIGN_ID", "profile PROJECT_ID", "executive CAMPAIGN_ID",
                  "executive --project PROJECT_ID", "legend"):
            self.assertIn(c, out.getvalue())

    def test_legend_needs_no_data(self):
        code, out, _ = run(self.root, "legend")
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(d["path_kind"]["possible"]["label"], "Possible Attack Path")
        self.assertEqual(d["path_kind"]["evidence_backed"]["label"], "Evidence-Backed Attack Path")

    def test_fail_closed_without_server_or_redaction(self):
        self.assertEqual(run(self.root, "executive", "c1")[0], 2)            # --mcp /nonexistent: no executive module
        real = dx.load_redaction
        dx.load_redaction = lambda *_: None
        self.addCleanup(setattr, dx, "load_redaction", real)
        for args in (("executive", "c1"), ("executive", "--project", "p1")):
            code, out, err = run(self.root, *args)
            self.assertEqual((code, out), (2, ""), args)
            self.assertIn("withheld", err)
        self.assertEqual(run(self.root, "executive", "../etc")[0], 2)
        self.assertEqual(run(self.root, "executive", "--project", "nope")[0], 2)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_campaign_block(self):
        r = self.cmd("executive", "c1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["schema_version"], "darkmoon-executive/1")
        self.assertEqual((d["score"]["score_status"], d["score"]["score"], d["score"]["status_label"]), ("not_rated", None, "Not rated"))
        self.assertLessEqual(len(d["treatment_plan"]["top_actions"]), 3)
        self.assertEqual(d["attack_paths"]["evidence_backed"], 0)      # Community: declared paths stay possible
        self.assertTrue(d["frameworks"]["summary_line"])
        self.assertNotIn("compliant", r.stdout.lower())
        self.assertNotIn(SECRET, r.stdout)
        self.assertFalse((self.root / "treatments").exists() or (self.root / "profiles").exists())   # read-only

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_project_block(self):
        r = self.cmd("executive", "--project", "p1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["schema_version"], "darkmoon-project-executive/1")
        self.assertIsNone(d["reference_campaign_id"])                    # no rated full campaign in this store
        self.assertEqual(d["latest_campaign"]["campaign_id"], "c1")
        self.assertEqual(d["plan_campaign_id"], "c1")

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_catalogue_text_kept_evidence_masked(self):
        """The ISO A.8.5 description (« Login and session handling: authentication bypass… ») reads like a credential
        pair to the redaction engine: it is Darkmoon's own text and is shown as written; the secret is still masked."""
        vulns = json.loads((self.root / "vulnerabilities" / "c1.json").read_text())
        vulns.append({"id": "v3", "title": "Login bypass", "severity": "high", "status": "confirmed",
                      "category": "authentication_bypass", "endpoint": "http://10.0.0.5/login",
                      "description": f"default credentials admin:{SECRET}"})
        (self.root / "vulnerabilities" / "c1.json").write_text(json.dumps(vulns))
        r = self.cmd("frameworks", "c1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        a85 = next(c for f in d["frameworks"] for c in f["controls"] if c["key"] == "iso27001:A.8.5")
        self.assertIn("authentication bypass", a85["text"])
        self.assertNotIn("redacted", a85["text"])
        self.assertNotIn(SECRET, r.stdout)

    def test_report_keeps_catalogue_cells_and_masks_secrets(self):
        a85 = "Login and session handling: authentication bypass, brute-force resistance, session token handling."
        (self.root / "reports" / "r1.md").write_text(
            "# Report\n\n| Control | State | Findings | What a test observes / why |\n|---|---|---|---|\n"
            f"| A.8.5 | Weakness observed | 6 | {a85} |\n\npassword={SECRET}\n")
        code, out, _ = run(self.root, "report", "c1")
        self.assertEqual(code, 0)
        content = json.loads(out)["content"]
        self.assertIn(f"| {a85} |", content)
        self.assertNotIn(SECRET, content)


class MaintenanceTests(unittest.TestCase):
    """``maintenance``: the owner's policy file validated on read, in words, with the evaluation now; Community warns,
    never blocks; read-only, redacted, fail closed (L9)."""

    setUp = AdapterTests.setUp
    tearDown = AdapterTests.tearDown
    MCP = LocalEngineTests.MCP
    cmd = FrameworkProfileTests.cmd

    def write(self, doc):
        d = self.root / "policies"
        d.mkdir(exist_ok=True)
        (d / "p1.json").write_text(json.dumps(doc) if not isinstance(doc, str) else doc)

    def test_fail_closed_without_server_or_redaction(self):
        self.assertEqual(run(self.root, "maintenance", "p1")[0], 2)
        real = dx.load_redaction
        dx.load_redaction = lambda *_: None
        self.addCleanup(setattr, dx, "load_redaction", real)
        code, out, err = run(self.root, "maintenance", "p1")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("withheld", err)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_policy_in_words_and_never_enforced(self):
        r = self.cmd("maintenance", "p1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertIsNone(d["policy"])
        self.assertEqual(d["file"]["status"], "absent")
        self.assertEqual(d["summary"], ["No maintenance policy: launches are not restricted by time."])
        # a window that is never open now: Sunday 00:00–00:01 does not cover every instant -> use a blackout for today
        self.write({"timezone": "UTC", "windows": [{"days": ["mon"], "start": "09:00", "end": "10:00",
                                                    "label": f"note password={SECRET}"}],
                    "blackouts": [{"start": "2000-01-01", "end": "2000-01-01"}]})
        r = self.cmd("maintenance", "p1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["file"]["status"], "read")
        self.assertFalse(d["enforced"])
        self.assertNotEqual(d["evaluation_now"]["decision"], "blocked")      # advisory: never « blocked »
        self.assertIn("Monday, 09:00–10:00", " ".join(d["summary"]))
        self.assertNotIn(SECRET, r.stdout)
        self.assertEqual(self.cmd("maintenance", "../etc").returncode, 2)
        self.assertEqual(self.cmd("maintenance", "nope").returncode, 2)

    @unittest.skipUnless(_HAS_MCP, "MCP server tree not next to the plugin")
    def test_broken_or_foreign_file_warns_never_passes_silently(self):
        for doc in ("{not json", {"timezone": "../../etc/passwd", "windows": []},
                    {"project_id": "other", "timezone": "UTC", "windows": []}):
            self.write(doc)
            d = json.loads(self.cmd("maintenance", "p1").stdout)
            self.assertEqual(d["file"]["status"], "unreadable", doc)
            self.assertEqual(d["evaluation_now"]["decision"], "warn", doc)
            self.assertEqual(d["evaluation_now"]["advisory_of"], "blocked", doc)
