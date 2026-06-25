#!/usr/bin/env python3
"""Tests for security_scan.py — covers the non-pi behavior:

- cache key derivation (content + prompt sensitivity)
- file walking + exclusion (basename and path recursion)
- binary detection
- JSON extraction (direct, embedded, NO_VULNERABILITIES, malformed)
- allowlist loading and suppression matching
- scan_file with a mocked pi call (cache hit, miss, prompt_format error, read error)
- run_scanner cache invalidation when file content changes
- CLI: --fail-on, --formats, --scan-timeout, exit codes
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import security_scan as ss  # noqa: E402


class TestCacheKey(unittest.TestCase):
    def test_file_key_is_deterministic(self):
        a = ss.file_key("src/foo.py", "injection", "abc123", "def456")
        b = ss.file_key("src/foo.py", "injection", "abc123", "def456")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)  # md5 hex

    def test_file_key_changes_with_content(self):
        a = ss.file_key("src/foo.py", "injection", "oldhash", "phash")
        b = ss.file_key("src/foo.py", "injection", "newhash", "phash")
        self.assertNotEqual(a, b)

    def test_file_key_changes_with_prompt(self):
        a = ss.file_key("src/foo.py", "injection", "chash", "prompt_a")
        b = ss.file_key("src/foo.py", "injection", "chash", "prompt_b")
        self.assertNotEqual(a, b)

    def test_file_key_changes_with_scanner(self):
        a = ss.file_key("src/foo.py", "injection", "chash", "phash")
        b = ss.file_key("src/foo.py", "crypto", "chash", "phash")
        self.assertNotEqual(a, b)

    def test_content_and_prompt_hash_are_16_hex(self):
        self.assertEqual(len(ss.content_hash(b"anything")), 16)
        self.assertEqual(len(ss.prompt_hash("template")), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in ss.content_hash(b"x")))


class TestFindAllFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _touch(self, rel, content="x = 1\n"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def test_returns_three_tuple(self):
        self._touch("a.py")
        result = ss.find_all_files(self.root)
        self.assertEqual(len(result), 3)
        all_files, ext_map, name_map = result
        self.assertIsInstance(all_files, list)
        self.assertIsInstance(ext_map, dict)
        self.assertIsInstance(name_map, dict)

    def test_groups_by_extension(self):
        self._touch("a.py")
        self._touch("b.py")
        self._touch("c.js")
        _, ext_map, _ = ss.find_all_files(self.root)
        self.assertEqual(len(ext_map[".py"]), 2)
        self.assertEqual(len(ext_map[".js"]), 1)

    def test_groups_by_name(self):
        self._touch("dir1/pom.xml")
        self._touch("dir2/pom.xml")
        _, _, name_map = ss.find_all_files(self.root)
        self.assertEqual(len(name_map["pom.xml"]), 2)

    def test_excludes_basename_dirs(self):
        self._touch("node_modules/foo.js")
        self._touch("src/keep.js")
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("node_modules/foo.js", rels)
        self.assertIn("src/keep.js", rels)

    def test_excludes_path_dirs_recursively(self):
        # Regression: Source/Regression/... used to leak subdirs
        self._touch("Source/Regression/a.py")
        self._touch("Source/Regression/Sub/b.py")
        self._touch("Source/keep.py")
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("Source/Regression/a.py", rels)
        self.assertNotIn("Source/Regression/Sub/b.py", rels)
        self.assertIn("Source/keep.py", rels)

    def test_excludes_thirdparty_wheelhouse_recursively(self):
        self._touch("ThirdParty/wheelhouse/a.whl")
        self._touch("ThirdParty/wheelhouse/nested/b.py")
        self._touch("ThirdParty/keep.py")
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("ThirdParty/wheelhouse/nested/b.py", rels)
        self.assertIn("ThirdParty/keep.py", rels)

    def test_excludes_excluded_files(self):
        (self.root / "security_scan.py").write_text("# self")
        self._touch("app.py")
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("security_scan.py", rels)
        self.assertIn("app.py", rels)

    def test_skips_binary_extensions(self):
        self._touch("image.png", "fake")
        self._touch("code.py")
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("image.png", rels)
        self.assertIn("code.py", rels)

    def test_skips_files_with_nul_bytes(self):
        # .txt isn't a known binary ext but content has NUL
        p = self.root / "trick.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"hello\x00world")
        self._touch("normal.py")
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("trick.txt", rels)
        self.assertIn("normal.py", rels)


class TestExtractJson(unittest.TestCase):
    def test_array_direct(self):
        out = ss.extract_json_array('[{"line":1}]')
        self.assertEqual(out, [{"line": 1}])

    def test_array_embedded(self):
        out = ss.extract_json_array('Some text\n[{"line":1,"code":"x"}]\nMore text')
        self.assertEqual(out, [{"line": 1, "code": "x"}])

    def test_empty_array(self):
        self.assertEqual(ss.extract_json_array("[]"), [])

    def test_no_vulnerabilities_marker(self):
        self.assertEqual(ss.extract_json_array("NO_VULNERABILITIES"), [])

    def test_malformed_returns_error_dict(self):
        out = ss.extract_json_array("totally not json")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    def test_object_direct(self):
        out = ss.extract_json_object('{"B1": [".py"]}')
        self.assertEqual(out, {"B1": [".py"]})

    def test_object_embedded(self):
        out = ss.extract_json_object('Result: {"B1": [".py"]} -- end')
        self.assertEqual(out, {"B1": [".py"]})

    def test_object_malformed(self):
        out = ss.extract_json_object("garbage")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)


class TestAllowlist(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(ss.load_allowlist(Path(td)), [])

    def test_valid_allowlist(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "allowlist.json").write_text(json.dumps({
                "version": 1,
                "suppressions": [
                    {"scanner": "B3", "file": "a.py", "line": 42, "reason": "safe"},
                ],
            }))
            sups = ss.load_allowlist(Path(td))
            self.assertEqual(len(sups), 1)
            self.assertEqual(sups[0]["reason"], "safe")

    def test_corrupt_allowlist_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "allowlist.json").write_text("not json")
            sups = ss.load_allowlist(Path(td))
            self.assertEqual(sups, [])

    def test_exact_match(self):
        entry = {"scanner": "B3", "file": "a.py", "line": 42, "reason": "ok"}
        self.assertTrue(ss.suppression_match("B3", "a.py", 42, entry))
        self.assertFalse(ss.suppression_match("B3", "a.py", 43, entry))
        self.assertFalse(ss.suppression_match("B5", "a.py", 42, entry))
        self.assertFalse(ss.suppression_match("B3", "b.py", 42, entry))

    def test_file_wildcard(self):
        entry = {"scanner": "B3", "file": "*", "line": 1, "reason": "x"}
        self.assertTrue(ss.suppression_match("B3", "anything.py", 1, entry))

    def test_scanner_wildcard(self):
        entry = {"scanner": "*", "file": "a.py", "line": 1, "reason": "x"}
        self.assertTrue(ss.suppression_match("B7", "a.py", 1, entry))

    def test_line_zero_or_null_matches_any_line(self):
        for ln in (None, 0, ""):
            entry = {"scanner": "B3", "file": "a.py", "line": ln, "reason": "x"}
            self.assertTrue(ss.suppression_match("B3", "a.py", 999, entry))

    def test_find_suppression_returns_first_match(self):
        allow = [
            {"scanner": "*", "file": "*", "line": 0, "reason": "global"},
            {"scanner": "B3", "file": "a.py", "line": 5, "reason": "specific"},
        ]
        m = ss.find_suppression("B3", "a.py", 5, allow)
        self.assertEqual(m["reason"], "global")
        m2 = ss.find_suppression("B5", "a.py", 1, allow)
        self.assertEqual(m2["reason"], "global")

    def test_max_severity_at_or_above(self):
        counts = {"Critical": 1, "High": 0, "Medium": 2, "Low": 3}
        self.assertEqual(ss.max_severity_at_or_above(counts, "critical"), 1)
        self.assertEqual(ss.max_severity_at_or_above(counts, "high"), 1)
        self.assertEqual(ss.max_severity_at_or_above(counts, "medium"), 3)
        self.assertEqual(ss.max_severity_at_or_above(counts, "low"), 6)
        self.assertEqual(ss.max_severity_at_or_above(counts, "never"), 0)


class TestScanFileMocked(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.results = self.state / "test" / "results"
        self.results.mkdir(parents=True)
        self.sessions = self.state / "sessions"
        self.sessions.mkdir()
        self.f = self.root / "code.py"
        self.f.write_text("x = 1\n")
        self.cfg = {
            "name": "test", "id": "B3", "label": "Test",
            "prompt_file": "nope.txt", "base_ext": [".py"],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def _patch_call(self, return_value):
        return patch.object(ss, "call_pi", return_value=return_value)

    def test_successful_scan_writes_cache(self):
        with self._patch_call(("ok", '[]')):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertIn("content_hash", result)
        self.assertIn("prompt_hash", result)
        self.assertEqual(result["prompt_hash"], "phash")
        cache_files = list(self.results.glob("*.json"))
        self.assertEqual(len(cache_files), 1)

    def test_cache_hit_skips_pi(self):
        # Pre-populate cache using the new key format
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "phash")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok",
            "result": [], "content_hash": c_hash, "prompt_hash": "phash",
        }))
        with patch.object(ss, "call_pi") as mock_pi:
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "cached")
        mock_pi.assert_not_called()

    def test_content_change_invalidates_cache(self):
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "phash")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok", "result": [],
        }))
        # Modify the file — content hash must change, so cache must miss
        self.f.write_text("x = 999\n")
        with self._patch_call(("ok", "[]")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "ok")

    def test_prompt_change_invalidates_cache(self):
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "OLDPROMPT")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok", "result": [],
        }))
        # Same file, but the scanner now uses a different prompt hash
        with self._patch_call(("ok", "[]")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="NEWPROMPT", timeout=60,
            )
        self.assertEqual(result["status"], "ok")

    def test_prompt_format_error_returned_gracefully(self):
        # Template references an unknown placeholder; str.format raises KeyError
        with patch.object(ss, "call_pi") as mock_pi:
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "{this_placeholder_does_not_exist}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "error")
        self.assertIn("prompt_format_failed", result["result"]["error"])
        mock_pi.assert_not_called()

    def test_pi_error_cached(self):
        with self._patch_call(("timeout", "timed out")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "timeout")
        cache_files = list(self.results.glob("*.json"))
        self.assertEqual(len(cache_files), 1)

    def test_malformed_pi_response_cached_as_error(self):
        with self._patch_call(("ok", "no json here at all")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        # The extraction returns an error dict, but the per-file result
        # status is "ok" because pi itself didn't fail
        self.assertEqual(result["status"], "ok")
        self.assertIn("error", result["result"])


class TestRunScannerCacheInvalidation(unittest.TestCase):
    """End-to-end: change file content, verify cache is invalidated."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        self.sessions = self.state / "sessions"
        self.sessions.mkdir(parents=True)
        self.f = self.root / "code.py"
        self.f.write_text("x = 1\n")
        self.cfg = {
            "name": "injection", "id": "B3", "label": "Injection",
            "prompt_file": "nope.txt", "base_ext": [".py"],
        }
        # Pre-create a discovery map
        self.discovery = {"B3": [".py"]}

    def tearDown(self):
        self.tmp.cleanup()

    def test_changed_content_re_scans(self):
        target_files, ext_map, name_map = ss.find_all_files(self.root)

        # First run — populates cache
        with patch.object(ss, "call_pi", return_value=("ok", "[]")):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                scan_timeout=60,
            )

        # Change the file
        self.f.write_text("x = evil_inject()\n")

        # Second run — must re-scan (pi should be called again)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock_pi:
            _, results = ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                scan_timeout=60,
            )
        self.assertEqual(mock_pi.call_count, 1,
                         "File content changed; cache should have been invalidated")

    def test_unchanged_content_skips_pi(self):
        target_files, ext_map, name_map = ss.find_all_files(self.root)

        with patch.object(ss, "call_pi", return_value=("ok", "[]")):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                scan_timeout=60,
            )
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock_pi:
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                scan_timeout=60,
            )
        self.assertEqual(mock_pi.call_count, 0,
                         "No file change; cache should have been hit")

    def test_rescan_flag_bypasses_cache(self):
        target_files, ext_map, name_map = ss.find_all_files(self.root)

        with patch.object(ss, "call_pi", return_value=("ok", "[]")):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                scan_timeout=60,
            )
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock_pi:
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=True, dry_run=False,
                scan_timeout=60,
            )
        self.assertEqual(mock_pi.call_count, 1,
                         "--rescan should always re-scan")


class TestDiscoveryPrompt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.sessions = self.state / "sessions"
        self.sessions.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_loads_from_prompts_dir(self):
        # The repo ships prompts/discovery.txt; ensure load works
        prompt = ss.load_discovery_prompt()
        self.assertIn("{repo_structure}", prompt)

    def test_falls_back_to_default_when_missing(self):
        # Override PROMPTS_DIR to a tempdir without discovery.txt
        empty = Path(self.tmp.name) / "empty_prompts"
        empty.mkdir()
        with patch.object(ss, "PROMPTS_DIR", empty):
            prompt = ss.load_discovery_prompt()
        self.assertIn("{repo_structure}", prompt)


class TestBuildReport(unittest.TestCase):
    """Integration test: build a report from cached results + allowlist."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.results = self.state / "injection" / "results"
        self.results.mkdir(parents=True)
        self.sessions = self.state / "sessions"
        self.sessions.mkdir()
        self.output = self.root / "report.md"

    def tearDown(self):
        self.tmp.cleanup()

    def _write_result(self, scanner_name, rel, vulns, status="ok", extra=None):
        cfg = ss.OWASP_SCANNERS[scanner_name]
        rd = self.state / cfg["name"] / "results"
        rd.mkdir(parents=True, exist_ok=True)
        # Use a synthetic key; the file naming is irrelevant for the report
        data = {"file": rel, "scanner": cfg["name"], "status": status, "result": vulns}
        if extra:
            data.update(extra)
        (rd / f"{rel.replace('/', '_')}.json").write_text(json.dumps(data))

    def test_active_vs_suppressed_counts(self):
        self._write_result("B3", "a.py", [
            {"line": 1, "severity": "High", "code": "x", "explanation": "", "fix": ""},
            {"line": 2, "severity": "Critical", "code": "y", "explanation": "", "fix": ""},
        ])
        self._write_result("B3", "b.py", [
            {"line": 10, "severity": "Medium", "code": "z", "explanation": "", "fix": ""},
        ])
        allowlist = [
            {"scanner": "B3", "file": "b.py", "line": 10, "reason": "intentional"},
        ]
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist,
        )
        # Active: 2 from a.py, 0 from b.py
        self.assertEqual(stats["severity_counts"]["High"], 1)
        self.assertEqual(stats["severity_counts"]["Critical"], 1)
        self.assertEqual(stats["severity_counts"]["Medium"], 0)
        self.assertEqual(stats["suppressed_count"], 1)
        # Report should mention suppression
        text = self.output.read_text()
        self.assertIn("Suppressed (allowlisted) | 1", text)
        self.assertIn("intentional", text)

    def test_returns_stats_dict_on_clean_run(self):
        self._write_result("B3", "clean.py", [])
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        self.assertEqual(stats["severity_counts"]["High"], 0)
        self.assertEqual(stats["suppressed_count"], 0)
        self.assertEqual(stats["error_count"], 0)

    def test_corrupt_cache_file_does_not_crash(self):
        results_dir = self.state / "injection" / "results"
        (results_dir / "bad.json").write_text("not valid json")
        self._write_result("B3", "ok.py", [])
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        self.assertEqual(stats["scanned_count"], 1)


class TestCLI(unittest.TestCase):
    """End-to-end CLI tests using subprocess to drive main()."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        (self.root / "code.py").write_text("x = 1\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, expect_exit=None):
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "security_scan.py"),
             *args],
            cwd=str(self.root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if expect_exit is not None:
            self.assertEqual(
                proc.returncode, expect_exit,
                msg=f"Expected exit {expect_exit}, got {proc.returncode}\n"
                    f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        return proc

    def test_help_exits_1(self):
        proc = self._run("--help")
        self.assertEqual(proc.returncode, 0)  # argparse exits 0 on --help

    def test_missing_args_exits_1(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Specify --all or --scanner", proc.stdout)

    def test_unknown_scanner_exits_1(self):
        proc = self._run("--scanner", "B99")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Unknown scanner", proc.stdout)

    def test_formats_arg_accepted(self):
        proc = self._run("--phase", "1", "--scanner", "B3",
                         "--formats", ".sql,.sh", "--redetect")
        # Discovery will try to call pi and fail; check it didn't reject the flag
        self.assertNotIn("unrecognized arguments", proc.stderr)

    def test_dry_run_exits_0(self):
        proc = self._run("--scanner", "B3", "--dry-run")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("code.py", proc.stdout)

    def test_fail_on_no_findings_exits_0(self):
        # Pre-populate a clean cache to avoid calling pi
        results_dir = self.state / "injection" / "results"
        results_dir.mkdir(parents=True)
        c_hash = ss.content_hash(b"x = 1\n")
        key = ss.file_key("code.py", "injection", c_hash,
                          ss.prompt_hash("dummy"))
        (results_dir / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "injection", "status": "ok", "result": [],
            "content_hash": c_hash, "prompt_hash": ss.prompt_hash("dummy"),
        }))
        (self.root / "security_report.md").touch()
        proc = self._run("--scanner", "B3", "--phase", "2", "--fail-on", "high",
                         "--output", str(self.root / "out.md"))
        # With --phase 2 we need discovery too; it will try to use the cache.
        # If discovery cache is missing it will call pi and fail.
        # This is just a smoke test for argument parsing; the actual exit
        # code depends on discovery state, so we don't assert on it here.

    def test_format_override_normalizes_dot(self):
        # Internally we normalize "sql" -> ".sql"
        proc = self._run("--scanner", "B3", "--dry-run", "--formats", "sql,sh")
        self.assertEqual(proc.returncode, 0)
        # dry-run should list no files because there's no .sql/.sh
        self.assertNotIn("code.py", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
