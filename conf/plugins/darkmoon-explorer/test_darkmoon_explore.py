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
