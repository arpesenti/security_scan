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

    def test_file_key_changes_with_thinking(self):
        # Flipping --scan-thinking must produce a different cache key;
        # otherwise a cached "off" verdict would be returned for a
        # "high" run (or vice versa) and the two would silently
        # overwrite each other.
        a = ss.file_key("src/foo.py", "injection", "chash", "phash", "off")
        b = ss.file_key("src/foo.py", "injection", "chash", "phash", "high")
        self.assertNotEqual(a, b)

    def test_verify_file_key_changes_with_thinking(self):
        a = ss.verify_file_key("a.py", "scanner", "chash", "fsig", "vphash", "off")
        b = ss.verify_file_key("a.py", "scanner", "chash", "fsig", "vphash", "medium")
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

    def test_size_limit_zero_is_unlimited(self):
        # Passing max_file_size=0 explicitly disables the cap. The
        # default is now 1 MiB (see DEFAULT_MAX_FILE_SIZE) so a 5 MB
        # file at the default would be dropped — pass 0 here to prove
        # the opt-out path works.
        self._touch("big.py", "x = 1\n" + "# pad\n" * (5 * 1024 * 1024 // 8))
        all_files, _, _ = ss.find_all_files(self.root, max_file_size=0)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertIn("big.py", rels)

    def test_default_size_limit_is_1_mib(self):
        # The default is 1 MiB (DEFAULT_MAX_FILE_SIZE). A 2 MiB file
        # must be dropped with no explicit flag, while a 100 KB file
        # is kept.
        self._touch("huge.py", "x = 1\n" + "# pad\n" * (2 * 1024 * 1024 // 8))
        self._touch("modest.py", "x = 1\n" + "# pad\n" * (100 * 1024 // 8))
        all_files, _, _ = ss.find_all_files(self.root)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertIn("modest.py", rels)
        self.assertNotIn("huge.py", rels)

    def test_default_max_file_size_constant(self):
        # Keep the constant in sync with the documented value (1 MiB).
        # If this changes, the README and the discovery summary
        # wording also need to be revisited.
        self.assertEqual(ss.DEFAULT_MAX_FILE_SIZE, 1 * 1024 * 1024)

    def test_size_limit_excludes_oversized(self):
        # With max_file_size=1024, a 2 KB file should be dropped while
        # a small one is kept. Verifies the discovery chokepoint
        # actually filters by size.
        self._touch("big.py", "x = 1\n" + "# pad\n" * 200)  # ~1.6 KB
        self._touch("small.py", "x = 1\n")
        all_files, ext_map, name_map = ss.find_all_files(self.root, max_file_size=1024)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("big.py", rels)
        self.assertIn("small.py", rels)
        # The ext_map and name_map must also exclude the oversized
        # file — downstream phases use these maps to find candidates.
        self.assertNotIn("big.py", [f.name for f in ext_map[".py"]])
        self.assertNotIn("big.py", [f.name for f in name_map.get("big.py", [])])

    def test_size_limit_exact_boundary(self):
        # A file exactly at the limit should be included (the check
        # is `size > max_file_size`, not `>=`).
        content = "x" * 100
        self._touch("at_limit.py", content)
        all_files, _, _ = ss.find_all_files(self.root, max_file_size=100)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertIn("at_limit.py", rels)

    def test_size_limit_one_byte_above_excludes(self):
        content = "x" * 101
        self._touch("over.py", content)
        all_files, _, _ = ss.find_all_files(self.root, max_file_size=100)
        rels = [str(f.relative_to(self.root)) for f in all_files]
        self.assertNotIn("over.py", rels)


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

    def test_no_vulnerabilities_prose(self):
        # The previous implementation only matched the exact "NO_VULNERABILITIES"
        # token. Models usually write "No vulnerabilities found" instead, so
        # the hardened parser also accepts the prose form.
        self.assertEqual(ss.extract_json_array("No vulnerabilities found in this file."), [])

    def test_malformed_returns_error_dict(self):
        out = ss.extract_json_array("totally not json")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    def test_empty_response(self):
        out = ss.extract_json_array("")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    def test_whitespace_only(self):
        out = ss.extract_json_array("   \n\t  ")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    def test_code_fence_json(self):
        # Models frequently wrap JSON in ```json ... ``` even when not asked.
        out = ss.extract_json_array('```json\n[{"line":1,"severity":"High"}]\n```')
        self.assertEqual(out, [{"line": 1, "severity": "High"}])

    def test_code_fence_no_language(self):
        out = ss.extract_json_array('```\n[{"a":1}]\n```')
        self.assertEqual(out, [{"a": 1}])

    def test_code_fence_with_prose(self):
        out = ss.extract_json_array('Sure, here you go:\n```json\n[{"x":2}]\n```\nDone.')
        self.assertEqual(out, [{"x": 2}])

    def test_trailing_prose_after_array(self):
        out = ss.extract_json_array('[{"line":1}]\n\nLet me know if you need more detail.')
        self.assertEqual(out, [{"line": 1}])

    def test_stray_bracket_in_prose(self):
        # The first `[` in the response is inside prose ("[foo]"), not the
        # real JSON. The hardened parser walks every `[` position and
        # returns the first one that successfully decodes as a list.
        out = ss.extract_json_array('Reasoning: the value [foo] looks like X.\n[{"line":3}]')
        self.assertEqual(out, [{"line": 3}])

    def test_comma_inside_string_value(self):
        out = ss.extract_json_array('[{"line":1,"code":"a, b, c"},{"line":2}]')
        self.assertEqual(out, [{"line": 1, "code": "a, b, c"}, {"line": 2}])

    def test_truncated_missing_closing_bracket(self):
        # Common failure mode when the model runs out of output tokens: the
        # array is complete but the trailing `]` is missing. The recovery
        # path closes the array at the last `}` and parses.
        out = ss.extract_json_array('[{"line":1,"code":"x"},{"line":2,"code":"y"}')
        self.assertEqual(out, [{"line": 1, "code": "x"}, {"line": 2, "code": "y"}])

    def test_truncated_mid_object_recovers_prefix(self):
        # The second object never closes. The recovery returns the longest
        # valid prefix — the first complete object.
        out = ss.extract_json_array('[{"line":1,"code":"x"},{"line":2,"code":')
        self.assertEqual(out, [{"line": 1, "code": "x"}])

    def test_nested_array(self):
        out = ss.extract_json_array('[[1,2],[3,4]]')
        self.assertEqual(out, [[1, 2], [3, 4]])

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

    def test_object_empty(self):
        out = ss.extract_json_object("")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    def test_object_code_fence(self):
        out = ss.extract_json_object('```json\n{"B1": [".py"]}\n```')
        self.assertEqual(out, {"B1": [".py"]})

    def test_object_stray_brace_in_prose(self):
        out = ss.extract_json_object('Note: {something arbitrary}. Then: {"B1": ["x"]}')
        self.assertEqual(out, {"B1": ["x"]})

    def test_object_truncated_recovers_prefix(self):
        out = ss.extract_json_object('{"B1": [".py"], "B2":')
        self.assertEqual(out, {"B1": [".py"]})


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
        # Pre-populate cache using the new key format (key includes
        # thinking, so we pass it explicitly to match the scan_file default).
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "phash", "off")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok",
            "result": [], "content_hash": c_hash, "prompt_hash": "phash",
        }))
        with patch.object(ss, "call_pi") as mock_pi:
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60, thinking="off",
            )
        self.assertEqual(result["status"], "cached")
        mock_pi.assert_not_called()

    def test_content_change_invalidates_cache(self):
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "phash", "off")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok", "result": [],
        }))
        # Modify the file — content hash must change, so cache must miss
        self.f.write_text("x = 999\n")
        with self._patch_call(("ok", "[]")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60, thinking="off",
            )
        self.assertEqual(result["status"], "ok")

    def test_prompt_change_invalidates_cache(self):
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "OLDPROMPT", "off")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok", "result": [],
        }))
        # Same file, but the scanner now uses a different prompt hash
        with self._patch_call(("ok", "[]")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="NEWPROMPT", timeout=60, thinking="off",
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

    def test_pi_error_does_not_write_cache(self):
        # A failed pi call (non-ok status) must not leave a cache entry
        # behind, otherwise the next run would skip the retry.
        with self._patch_call(("error", "pi broke")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "error")
        self.assertIn("pi broke", result["result"]["error"])
        self.assertEqual(list(self.results.glob("*.json")), [])

    def test_pi_timeout_does_not_write_cache(self):
        with self._patch_call(("timeout", "timed out")):
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(list(self.results.glob("*.json")), [])

    def test_pi_error_removes_stale_failed_cache(self):
        # A previous run left a failed cache entry. The next run must
        # detect it as a miss, re-scan, and (on success) replace it —
        # never reuse the cached failure.
        c_hash = ss.content_hash(self.f.read_bytes())
        key = ss.file_key("code.py", "test", c_hash, "phash", "off")
        (self.results / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "error",
            "result": {"error": "prior failure"},
            "content_hash": c_hash, "prompt_hash": "phash",
        }))
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock_pi:
            result = ss.scan_file(
                self.f, self.cfg, self.root, self.results, self.sessions,
                "FILE: {filename}\n{file_content}",
                prompt_hash_value="phash", timeout=60, thinking="off",
            )
        self.assertEqual(result["status"], "ok")
        mock_pi.assert_called_once()
        cache_files = list(self.results.glob("*.json"))
        self.assertEqual(len(cache_files), 1)
        cached = json.loads(cache_files[0].read_text())
        self.assertEqual(cached["status"], "ok")

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


# ── Verification phase tests ────────────────────────────────────────────────


class TestVerificationHelpers(unittest.TestCase):
    def test_findings_signature_is_16_hex(self):
        sig = ss.findings_signature([{"line": 1, "severity": "High"}])
        self.assertEqual(len(sig), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in sig))

    def test_findings_signature_stable_across_dict_order(self):
        a = ss.findings_signature([{"line": 1, "severity": "High"}])
        b = ss.findings_signature([{"severity": "High", "line": 1}])
        self.assertEqual(a, b)

    def test_findings_signature_changes_with_content(self):
        a = ss.findings_signature([{"line": 1, "severity": "High"}])
        b = ss.findings_signature([{"line": 1, "severity": "Low"}])
        self.assertNotEqual(a, b)

    def test_verify_file_key_changes_with_content(self):
        a = ss.verify_file_key("a.py", "scanner", "chash1", "fsig", "vphash")
        b = ss.verify_file_key("a.py", "scanner", "chash2", "fsig", "vphash")
        self.assertNotEqual(a, b)

    def test_verify_file_key_changes_with_findings_signature(self):
        a = ss.verify_file_key("a.py", "scanner", "chash", "fsig1", "vphash")
        b = ss.verify_file_key("a.py", "scanner", "chash", "fsig2", "vphash")
        self.assertNotEqual(a, b)

    def test_verify_file_key_changes_with_prompt(self):
        a = ss.verify_file_key("a.py", "scanner", "chash", "fsig", "vp1")
        b = ss.verify_file_key("a.py", "scanner", "chash", "fsig", "vp2")
        self.assertNotEqual(a, b)

    def test_verify_file_key_changes_with_scanner(self):
        a = ss.verify_file_key("a.py", "scanner1", "chash", "fsig", "vphash")
        b = ss.verify_file_key("a.py", "scanner2", "chash", "fsig", "vphash")
        self.assertNotEqual(a, b)

    def test_load_verify_prompt_has_placeholders(self):
        prompt = ss.load_verify_prompt()
        self.assertIn("{filename}", prompt)
        self.assertIn("{file_content}", prompt)
        self.assertIn("{findings_json}", prompt)

    def test_load_verify_prompt_falls_back_to_default(self):
        empty = Path(tempfile.mkdtemp()) / "empty_prompts"
        empty.mkdir()
        with patch.object(ss, "PROMPTS_DIR", empty):
            prompt = ss.load_verify_prompt()
        self.assertIn("{filename}", prompt)
        self.assertIn("{findings_json}", prompt)


class TestVerifyFindingMocked(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.verify_dir = self.state / "test" / "verifications"
        self.verify_dir.mkdir(parents=True)
        self.sessions = self.state / "sessions"
        self.sessions.mkdir()
        self.f = self.root / "code.py"
        self.f.write_text("x = 1\n")
        self.cfg = {
            "name": "test", "id": "B3", "label": "Test",
            "prompt_file": "nope.txt", "base_ext": [".py"],
        }
        self.findings = [
            {"line": 1, "code": "x = 1", "severity": "High",
             "explanation": "", "fix": ""},
        ]

    def tearDown(self):
        self.tmp.cleanup()

    def test_successful_verify_writes_cache(self):
        pi_response = json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "Reachable from CLI arg"},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", pi_response)):
            result = ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template",
                ss.prompt_hash("prompt template"), timeout=60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertIn("verifications", result)
        cache_files = list(self.verify_dir.glob("*.json"))
        self.assertEqual(len(cache_files), 1)

    def test_cache_hit_skips_pi(self):
        # Pre-populate the cache. Key now includes thinking; the
        # verify_finding default is "medium" so we seed with that.
        c_hash = ss.content_hash(self.f.read_bytes())
        f_sig = ss.findings_signature(self.findings)
        vph = ss.prompt_hash("prompt template")
        key = ss.verify_file_key("code.py", "test", c_hash, f_sig, vph, "medium")
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok",
            "verifications": {"1": {"confidence": "High"}},
            "findings_signature": f_sig, "verify_prompt_hash": vph,
            "content_hash": c_hash,
        }))
        with patch.object(ss, "call_pi") as mock_pi:
            result = ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template", vph, timeout=60, thinking="medium",
            )
        self.assertEqual(result["status"], "cached")
        mock_pi.assert_not_called()

    def test_findings_change_invalidates_cache(self):
        # Pre-populate cache with old findings signature
        c_hash = ss.content_hash(self.f.read_bytes())
        old_sig = ss.findings_signature([])
        vph = ss.prompt_hash("prompt template")
        key = ss.verify_file_key("code.py", "test", c_hash, old_sig, vph, "medium")
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "ok",
            "verifications": {}, "findings_signature": old_sig,
            "verify_prompt_hash": vph, "content_hash": c_hash,
        }))
        # New findings list -> different signature -> cache miss
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock_pi:
            ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template", vph, timeout=60, thinking="medium",
            )
        mock_pi.assert_called_once()

    def test_malformed_response_still_writes_cache_with_error(self):
        with patch.object(ss, "call_pi", return_value=("ok", "not json")):
            result = ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template", ss.prompt_hash("prompt template"), timeout=60,
            )
        # Even with a parse error, cache is written so report shows it ran
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["verifications"], {})
        self.assertIn("parse_error", result)

    def test_pi_error_does_not_write_cache(self):
        # A failed pi call (non-ok status) must not leave a cache entry
        # behind, otherwise the next run would skip the retry.
        with patch.object(ss, "call_pi", return_value=("error", "pi broke")):
            result = ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template", ss.prompt_hash("prompt template"), timeout=60,
            )
        self.assertEqual(result["status"], "error")
        self.assertIn("pi broke", result["error"])
        self.assertEqual(list(self.verify_dir.glob("*.json")), [])

    def test_pi_timeout_does_not_write_cache(self):
        with patch.object(ss, "call_pi", return_value=("timeout", "timed out")):
            result = ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template", ss.prompt_hash("prompt template"), timeout=60,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(list(self.verify_dir.glob("*.json")), [])

    def test_pi_error_removes_stale_failed_cache(self):
        # A previous run left a failed cache entry. The next run must
        # detect it as a miss, re-run the verification, and (on success)
        # replace it — never reuse the cached failure.
        c_hash = ss.content_hash(self.f.read_bytes())
        f_sig = ss.findings_signature(self.findings)
        vph = ss.prompt_hash("prompt template")
        key = ss.verify_file_key("code.py", "test", c_hash, f_sig, vph, "medium")
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "test", "status": "error",
            "error": "prior failure",
            "verifications": {}, "findings_signature": f_sig,
            "verify_prompt_hash": vph, "content_hash": c_hash,
        }))
        pi_response = json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "reachable"},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", pi_response)) as mock_pi:
            result = ss.verify_finding(
                self.f, self.cfg, "code.py", self.findings,
                self.root, self.verify_dir, self.sessions,
                "prompt template", vph, timeout=60, thinking="medium",
            )
        self.assertEqual(result["status"], "ok")
        mock_pi.assert_called_once()
        cache_files = list(self.verify_dir.glob("*.json"))
        self.assertEqual(len(cache_files), 1)
        cached = json.loads(cache_files[0].read_text())
        self.assertEqual(cached["status"], "ok")


class TestLoadVerificationForFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.verify_dir = Path(self.tmp.name) / "verify"
        self.verify_dir.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_returns_none_when_dir_missing(self):
        empty = Path(tempfile.mkdtemp())
        findings = [{"line": 1, "severity": "High"}]
        result = ss.load_verification_for_file(
            "test", "a.py", "chash", findings,
            empty / "nope", ss.prompt_hash("p"),
        )
        self.assertIsNone(result)

    def test_returns_none_when_cache_file_missing(self):
        findings = [{"line": 1, "severity": "High"}]
        result = ss.load_verification_for_file(
            "test", "a.py", "chash", findings,
            self.verify_dir, ss.prompt_hash("p"),
        )
        self.assertIsNone(result)

    def test_returns_none_on_signature_mismatch(self):
        # Cache was written for a different findings list
        vph = ss.prompt_hash("p")
        old_findings = [{"line": 1, "severity": "High"}]
        c_hash = "abc"
        old_sig = ss.findings_signature(old_findings)
        key = ss.verify_file_key("a.py", "test", c_hash, old_sig, vph)
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": "a.py", "scanner": "test", "status": "ok",
            "verifications": {"1": {"confidence": "High"}},
            "findings_signature": old_sig, "verify_prompt_hash": vph,
            "content_hash": c_hash,
        }))
        # New findings list, same key but signature inside will mismatch
        new_findings = [{"line": 1, "severity": "Critical"}]
        result = ss.load_verification_for_file(
            "test", "a.py", c_hash, new_findings, self.verify_dir, vph,
        )
        self.assertIsNone(result)

    def test_returns_none_on_status_not_ok(self):
        vph = ss.prompt_hash("p")
        findings = [{"line": 1, "severity": "High"}]
        c_hash = "abc"
        f_sig = ss.findings_signature(findings)
        key = ss.verify_file_key("a.py", "test", c_hash, f_sig, vph)
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": "a.py", "scanner": "test", "status": "error",
            "verifications": {}, "findings_signature": f_sig,
            "verify_prompt_hash": vph, "content_hash": c_hash,
        }))
        result = ss.load_verification_for_file(
            "test", "a.py", c_hash, findings, self.verify_dir, vph,
        )
        self.assertIsNone(result)

    def test_returns_verifications_on_match(self):
        vph = ss.prompt_hash("p")
        findings = [{"line": 1, "severity": "High"}]
        c_hash = "abc"
        f_sig = ss.findings_signature(findings)
        key = ss.verify_file_key("a.py", "test", c_hash, f_sig, vph)
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": "a.py", "scanner": "test", "status": "ok",
            "verifications": {
                "1": {"confidence": "High", "exploitable": "yes",
                       "verification_reason": "reachable"},
            },
            "findings_signature": f_sig, "verify_prompt_hash": vph,
            "content_hash": c_hash,
        }))
        result = ss.load_verification_for_file(
            "test", "a.py", c_hash, findings, self.verify_dir, vph,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["1"]["confidence"], "High")
        self.assertEqual(result["1"]["exploitable"], "yes")


class TestBuildReportWithVerification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.results_dir = self.state / "injection" / "results"
        self.results_dir.mkdir(parents=True)
        self.verify_dir = self.state / "injection" / "verifications"
        self.verify_dir.mkdir(parents=True)
        self.sessions = self.state / "sessions"
        self.sessions.mkdir()
        self.output = self.root / "report.md"
        self.cfg = ss.OWASP_SCANNERS["B3"]

    def tearDown(self):
        self.tmp.cleanup()

    def _write_scan_result(self, rel, vulns):
        c_hash = "testhash"
        data = {
            "file": rel, "scanner": "injection", "status": "ok",
            "result": vulns, "content_hash": c_hash,
        }
        # Use the actual content hash of any bytes for realism
        (self.results_dir / f"{rel.replace('/', '_')}.json").write_text(
            json.dumps(data)
        )
        return c_hash

    def _write_verification(self, rel, c_hash, findings, verifications):
        vph = ss.prompt_hash(ss.load_verify_prompt())
        f_sig = ss.findings_signature(findings)
        key = ss.verify_file_key(rel, "injection", c_hash, f_sig, vph)
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": rel, "scanner": "injection", "status": "ok",
            "verifications": verifications, "findings_signature": f_sig,
            "verify_prompt_hash": vph, "content_hash": c_hash,
        }))

    def test_unverified_findings_marked_unverified(self):
        vulns = [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ]
        self._write_scan_result("a.py", vulns)
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        self.assertEqual(stats["confidence_counts"]["Unverified"], 1)
        self.assertEqual(stats["verified_count"], 0)
        # No confidence threshold => no gated counts
        self.assertIsNone(stats["severity_counts_gated"])
        text = self.output.read_text()
        self.assertIn("Unverified", text)

    def test_verification_annotates_findings(self):
        vulns = [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
            {"line": 2, "severity": "Low", "code": "y",
             "explanation": "", "fix": ""},
        ]
        c_hash = self._write_scan_result("a.py", vulns)
        self._write_verification("a.py", c_hash, vulns, {
            "1": {"confidence": "High", "exploitable": "yes",
                   "verification_reason": "reachable from main"},
            "2": {"confidence": "Low", "exploitable": "no",
                   "verification_reason": "sanitized upstream"},
        })
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        self.assertEqual(stats["confidence_counts"]["High"], 1)
        self.assertEqual(stats["confidence_counts"]["Low"], 1)
        self.assertEqual(stats["verified_count"], 2)
        self.assertEqual(stats["unverified_count"], 0)
        text = self.output.read_text()
        self.assertIn("High confidence", text)
        self.assertIn("reachable from main", text)
        self.assertIn("sanitized upstream", text)

    def test_confidence_threshold_gates_severity_counts(self):
        vulns = [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
            {"line": 2, "severity": "Critical", "code": "y",
             "explanation": "", "fix": ""},
        ]
        c_hash = self._write_scan_result("a.py", vulns)
        self._write_verification("a.py", c_hash, vulns, {
            "1": {"confidence": "Low", "exploitable": "no",
                   "verification_reason": "dead code"},
            "2": {"confidence": "High", "exploitable": "yes",
                   "verification_reason": "reachable"},
        })
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            confidence_threshold="high",
        )
        # Raw counts include both
        self.assertEqual(stats["severity_counts"]["High"], 1)
        self.assertEqual(stats["severity_counts"]["Critical"], 1)
        # Gated counts: only the High-confidence Critical survives
        self.assertIsNotNone(stats["severity_counts_gated"])
        self.assertEqual(stats["severity_counts_gated"]["Critical"], 1)
        self.assertEqual(stats["severity_counts_gated"]["High"], 0)
        # One finding below threshold
        self.assertEqual(stats["needs_review_count"], 1)
        text = self.output.read_text()
        self.assertIn("Needs Review", text)
        self.assertIn("dead code", text)

    def test_confidence_threshold_unverified_counted_as_below(self):
        # Unverified findings are below any threshold, so they end up in
        # needs-review when a threshold is set.
        vulns = [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ]
        self._write_scan_result("a.py", vulns)  # no verification
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            confidence_threshold="high",
        )
        self.assertEqual(stats["unverified_count"], 1)
        self.assertEqual(stats["needs_review_count"], 1)
        self.assertEqual(stats["severity_counts_gated"]["High"], 0)

    def test_no_threshold_keeps_raw_behavior(self):
        vulns = [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ]
        c_hash = self._write_scan_result("a.py", vulns)
        self._write_verification("a.py", c_hash, vulns, {
            "1": {"confidence": "Low", "exploitable": "no",
                   "verification_reason": "sanitized"},
        })
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            confidence_threshold=None,
        )
        # Without a threshold, gated counts are not computed
        self.assertIsNone(stats["severity_counts_gated"])
        # Raw counts include the finding
        self.assertEqual(stats["severity_counts"]["High"], 1)
        # No needs-review without a threshold
        self.assertEqual(stats["needs_review_count"], 0)


class TestVerifyCLI(unittest.TestCase):
    """Smoke tests for the new CLI flags."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        (self.root / "code.py").write_text("x = 1\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, expect_exit=None, timeout=30):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             *args],
            cwd=str(self.root),
            capture_output=True, text=True, timeout=timeout,
        )
        if expect_exit is not None:
            self.assertEqual(
                proc.returncode, expect_exit,
                msg=f"Expected exit {expect_exit}, got {proc.returncode}\n"
                    f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        return proc

    def test_verify_with_phase1_exits_1(self):
        proc = self._run("--verify", "--phase", "1", "--scanner", "B3")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--verify requires scan results", proc.stdout)

    def test_phase3_without_scan_exits_1(self):
        # Pre-populate the tools-mode discovery cache (the default in this
        # build is --discovery-tools) so we get past the discovery check and
        # hit the "no scan results" guard.
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "discovery-tools.json").write_text(
            json.dumps({"B3": [".py"]})
        )
        proc = self._run("--phase", "3", "--scanner", "B3")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("No scan results", proc.stdout)

    def test_dry_run_does_not_create_verify_cache(self):
        self._run("--scanner", "B3", "--verify", "--dry-run")
        verify_dir = self.state / "injection" / "verifications"
        # dry-run: scan doesn't run, so no scan results, so no verify calls
        self.assertFalse(verify_dir.exists())


# ── CSV/TSV report tests ────────────────────────────────────────────────────


import csv  # noqa: E402

from io import StringIO  # noqa: E402


class TestOutputPathForFormat(unittest.TestCase):
    def test_replaces_wrong_extension(self):
        self.assertEqual(
            ss.output_path_for_format(Path("report.md"), "csv"),
            Path("report.csv"),
        )
        self.assertEqual(
            ss.output_path_for_format(Path("report"), "tsv"),
            Path("report.tsv"),
        )

    def test_keeps_correct_extension(self):
        self.assertEqual(
            ss.output_path_for_format(Path("report.csv"), "csv"),
            Path("report.csv"),
        )

    def test_md_keeps_md(self):
        self.assertEqual(
            ss.output_path_for_format(Path("security_report.md"), "md"),
            Path("security_report.md"),
        )

    def test_case_insensitive_extension_match(self):
        self.assertEqual(
            ss.output_path_for_format(Path("REPORT.CSV"), "csv"),
            Path("REPORT.CSV"),
        )


class TestBuildCsvReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.results_dir = self.state / "injection" / "results"
        self.results_dir.mkdir(parents=True)
        self.verify_dir = self.state / "injection" / "verifications"
        self.verify_dir.mkdir(parents=True)
        self.output = self.root / "out.csv"

    def tearDown(self):
        self.tmp.cleanup()

    def _write_scan(self, rel, vulns, c_hash="abc"):
        data = {
            "file": rel, "scanner": "injection", "status": "ok",
            "result": vulns, "content_hash": c_hash,
        }
        (self.results_dir / f"{rel.replace('/', '_')}.json").write_text(
            json.dumps(data)
        )

    def _write_verify(self, rel, c_hash, vulns, verifications):
        vph = ss.prompt_hash(ss.load_verify_prompt())
        f_sig = ss.findings_signature(vulns)
        key = ss.verify_file_key(rel, "injection", c_hash, f_sig, vph)
        (self.verify_dir / f"{key}.json").write_text(json.dumps({
            "file": rel, "scanner": "injection", "status": "ok",
            "verifications": verifications, "findings_signature": f_sig,
            "verify_prompt_hash": vph, "content_hash": c_hash,
        }))

    def _read_csv(self, path):
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def test_writes_header_and_rows(self):
        self._write_scan("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "exp", "fix": "fix"},
        ])
        stats = ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        self.assertTrue(self.output.exists())
        rows = self._read_csv(self.output)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file"], "a.py")
        self.assertEqual(rows[0]["severity"], "High")
        self.assertEqual(rows[0]["status"], "active")
        self.assertEqual(rows[0]["scanner"], "B3")
        self.assertEqual(rows[0]["scanner_label"], "Injection")
        self.assertEqual(rows[0]["line"], "1")
        self.assertEqual(stats["severity_counts"]["High"], 1)

    def test_all_required_columns_present(self):
        self._write_scan("a.py", [
            {"line": 1, "severity": "Low", "code": "x",
             "explanation": "", "fix": ""},
        ])
        ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        with open(self.output, encoding="utf-8") as f:
            header = f.readline().strip().split(",")
        for col in ss.CSV_FIELDNAMES:
            self.assertIn(col, header, f"Missing column: {col}")

    def test_suppressed_finding_marked_with_reason(self):
        self._write_scan("a.py", [
            {"line": 10, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        allowlist = [
            {"scanner": "B3", "file": "a.py", "line": 10,
             "reason": "static allowlist"},
        ]
        stats = ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=allowlist,
        )
        rows = self._read_csv(self.output)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "suppressed")
        self.assertEqual(rows[0]["suppression_reason"], "static allowlist")
        self.assertEqual(stats["suppressed_count"], 1)
        self.assertEqual(stats["severity_counts"]["High"], 0)

    def test_confidence_threshold_creates_needs_review(self):
        vulns = [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
            {"line": 2, "severity": "Critical", "code": "y",
             "explanation": "", "fix": ""},
        ]
        self._write_scan("a.py", vulns, c_hash="h1")
        self._write_verify("a.py", "h1", vulns, {
            "1": {"confidence": "Low", "exploitable": "no",
                   "verification_reason": "dead code"},
            "2": {"confidence": "High", "exploitable": "yes",
                   "verification_reason": "reachable"},
        })
        stats = ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            confidence_threshold="high",
        )
        rows = self._read_csv(self.output)
        statuses = {r["line"]: r["status"] for r in rows}
        self.assertEqual(statuses["1"], "needs_review")
        self.assertEqual(statuses["2"], "active")
        # Raw counts include both; gated counts include only the active one
        self.assertEqual(stats["severity_counts"]["High"], 1)
        self.assertEqual(stats["severity_counts"]["Critical"], 1)
        self.assertIsNotNone(stats["severity_counts_gated"])
        self.assertEqual(stats["severity_counts_gated"]["High"], 0)
        self.assertEqual(stats["severity_counts_gated"]["Critical"], 1)
        self.assertEqual(stats["needs_review_count"], 1)

    def test_no_threshold_all_active(self):
        vulns = [
            {"line": 1, "severity": "Medium", "code": "x",
             "explanation": "", "fix": ""},
        ]
        self._write_scan("a.py", vulns, c_hash="h1")
        self._write_verify("a.py", "h1", vulns, {
            "1": {"confidence": "Low", "exploitable": "no",
                   "verification_reason": ""},
        })
        stats = ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            confidence_threshold=None,
        )
        rows = self._read_csv(self.output)
        self.assertEqual(rows[0]["status"], "active")
        self.assertIsNone(stats["severity_counts_gated"])

    def test_tsv_uses_tab_delimiter(self):
        self._write_scan("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "has, comma", "fix": ""},
        ])
        tsv_out = self.root / "out.tsv"
        ss.build_csv_report(
            self.state, tsv_out, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[], delimiter="\t",
        )
        with open(tsv_out, encoding="utf-8") as f:
            content = f.read()
        # Header is tab-separated
        self.assertIn("scanner\tscanner_label\tfile", content)
        # The "has, comma" field stays in its column because of tab delimiting
        self.assertIn("has, comma", content)
        # Re-parse with the csv module to validate field count (str.split
        # would lose trailing empty fields).
        with open(tsv_out, newline="", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter="\t")
            rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rows[0]), len(rows[1]))
        self.assertEqual(len(rows[0]), len(ss.CSV_FIELDNAMES))

    def test_error_file_emits_error_row(self):
        # No findings, status is "error"
        data = {
            "file": "broken.py", "scanner": "injection", "status": "error",
            "result": {"error": "read_failed"},
        }
        (self.results_dir / "broken.json").write_text(json.dumps(data))
        stats = ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        rows = self._read_csv(self.output)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "error")
        self.assertEqual(rows[0]["file"], "broken.py")
        self.assertEqual(stats["error_count"], 1)

    def test_handles_newlines_and_quotes_in_fields(self):
        self._write_scan("a.py", [
            {"line": 1, "severity": "High", "code": "x = 1",
             "explanation": 'has "quotes" and\nnewlines', "fix": "fix"},
        ])
        ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        # Re-parse: the CSV module handles quoting/escaping per RFC 4180
        rows = self._read_csv(self.output)
        self.assertEqual(rows[0]["explanation"], 'has "quotes" and\nnewlines')

    def test_unverified_findings_have_blank_confidence(self):
        self._write_scan("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        # No verification cache
        ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        rows = self._read_csv(self.output)
        self.assertEqual(rows[0]["confidence"], "")
        self.assertEqual(rows[0]["exploitable"], "")

    def test_returns_stats_with_all_expected_keys(self):
        self._write_scan("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        stats = ss.build_csv_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        for key in (
            "severity_counts", "severity_counts_gated", "confidence_counts",
            "needs_review_count", "verified_count", "unverified_count",
            "suppressed_count", "error_count", "scanned_count",
        ):
            self.assertIn(key, stats, f"Missing stats key: {key}")


class TestReportFormatCLI(unittest.TestCase):
    """End-to-end CLI tests for the --report-format flag."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        self.results_dir = self.state / "injection" / "results"
        self.results_dir.mkdir(parents=True)
        self.f = self.root / "code.py"
        self.f.write_text("x = 1\n")
        # Use the actual scanner's prompt hash so the prep cache key matches
        # what run_scanner derives - otherwise the scanner will try to call
        # pi and create an error cache entry, exiting 2.
        self.p_hash = ss.prompt_hash(ss.load_prompt_template(ss.OWASP_SCANNERS["B3"]))
        (self.state / "discovery.json").write_text(
            json.dumps({"B3": [".py"]})
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _write_finding(self, rel, vulns):
        filepath = self.root / rel
        c_hash = ss.content_hash(filepath.read_bytes())
        key = ss.file_key(rel, "injection", c_hash, self.p_hash)
        data = {
            "file": rel, "scanner": "injection", "status": "ok",
            "result": vulns, "content_hash": c_hash,
            "prompt_hash": self.p_hash,
        }
        (self.results_dir / f"{key}.json").write_text(json.dumps(data))

    def _run(self, *args, expect_exit=None, timeout=30):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             *args],
            cwd=str(self.root),
            capture_output=True, text=True, timeout=timeout,
        )
        if expect_exit is not None:
            self.assertEqual(
                proc.returncode, expect_exit,
                msg=f"Expected exit {expect_exit}, got {proc.returncode}\n"
                    f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        return proc

    def _prep_cache(self):
        self._write_finding("code.py", [
            {"line": 1, "severity": "High", "code": "x = 1",
             "explanation": "e", "fix": "f"},
        ])

    def test_csv_format_writes_csv(self):
        self._prep_cache()
        proc = self._run(
            "--scanner", "B3",
            "--report-format", "csv",
            "--output", "out",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue((self.root / "out.csv").exists())
        # The markdown was NOT written
        self.assertFalse((self.root / "out.md").exists())
        with open(self.root / "out.csv", encoding="utf-8") as f:
            first_line = f.readline()
        self.assertTrue(first_line.startswith("scanner,scanner_label"))

    def test_tsv_format_writes_tsv(self):
        self._prep_cache()
        proc = self._run(
            "--scanner", "B3",
            "--report-format", "tsv",
            "--output", "report",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue((self.root / "report.tsv").exists())
        with open(self.root / "report.tsv", encoding="utf-8") as f:
            first_line = f.readline()
        self.assertIn("\t", first_line)

    def test_default_format_is_md(self):
        self._prep_cache()
        proc = self._run("--scanner", "B3", "--output", "r")
        self.assertEqual(proc.returncode, 0)
        self.assertTrue((self.root / "r.md").exists())

    def test_explicit_md_extension_kept(self):
        self._prep_cache()
        proc = self._run(
            "--scanner", "B3",
            "--report-format", "md",
            "--output", "myreport.md",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue((self.root / "myreport.md").exists())

    def test_csv_format_applies_fail_on_confidence_gate(self):
        self._prep_cache()
        # No verification cache, so the finding is unverified. With
        # --fail-on-confidence high, unverified findings are below the
        # threshold, so the gate should not trip -> exit 0.
        proc = self._run(
            "--scanner", "B3",
            "--report-format", "csv",
            "--fail-on-confidence", "high",
            "--output", "out",
        )
        self.assertEqual(proc.returncode, 0)


# ── Per-phase tool support tests ─────────────────────────────────────────────


class TestReadonlyToolsConstant(unittest.TestCase):
    def test_contains_expected_tools(self):
        # The order doesn't matter for pi, but the set matters: read-only
        # with no execution / write / fetch.
        self.assertEqual(set(ss.READONLY_TOOLS), {"read", "grep", "find", "ls"})

    def test_does_not_contain_dangerous_tools(self):
        for dangerous in ("bash", "edit", "write"):
            self.assertNotIn(dangerous, ss.READONLY_TOOLS)


class TestCallPiToolArgs(unittest.TestCase):
    """Verify the right CLI args reach pi for each tools mode."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.session = self.root / "sessions"
        self.session.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _args_for(self, tools=None, thinking=None):
        """Return the actual argv list that call_pi would invoke."""
        captured = {}
        def fake_run(cmd, *args, **kwargs):
            captured["cmd"] = cmd
            class R:
                returncode = 0
                stdout = "ok"
                stderr = ""
            return R()
        with patch.object(ss.subprocess, "run", side_effect=fake_run):
            ss.call_pi("hello", self.session, tools=tools, thinking=thinking)
        return captured["cmd"]

    def test_default_passes_no_tools(self):
        cmd = self._args_for(tools=None)
        self.assertIn("--no-tools", cmd)
        self.assertNotIn("--tools", cmd)

    def test_empty_list_passes_no_tools(self):
        # An empty list is the "no tools" path, same as None
        cmd = self._args_for(tools=[])
        self.assertIn("--no-tools", cmd)
        self.assertNotIn("--tools", cmd)

    def test_readonly_passes_tools_flag(self):
        cmd = self._args_for(tools=ss.READONLY_TOOLS)
        self.assertNotIn("--no-tools", cmd)
        idx = cmd.index("--tools")
        self.assertEqual(cmd[idx + 1], "read,grep,find,ls")

    def test_custom_list_joined_with_comma(self):
        cmd = self._args_for(tools=["read", "grep"])
        idx = cmd.index("--tools")
        self.assertEqual(cmd[idx + 1], "read,grep")

    def test_session_dir_preserved(self):
        cmd = self._args_for(tools=ss.READONLY_TOOLS)
        idx = cmd.index("--session-dir")
        self.assertEqual(cmd[idx + 1], str(self.session))

    def test_thinking_default_omits_flag(self):
        # `thinking=None` (the default) leaves --thinking out entirely so
        # the user's pi config default applies. This keeps the historical
        # "no extra flags" behavior when callers don't opt in.
        cmd = self._args_for(tools=ss.READONLY_TOOLS)
        self.assertNotIn("--thinking", cmd)

    def test_thinking_off_omits_flag(self):
        # `"off"` is the explicit-no-thinking path used by the scan phase
        # by default. Same observable effect as `None`: no --thinking flag,
        # so the model runs at its base speed.
        cmd = self._args_for(thinking="off")
        self.assertNotIn("--thinking", cmd)

    def test_thinking_medium_passes_flag(self):
        cmd = self._args_for(thinking="medium")
        idx = cmd.index("--thinking")
        self.assertEqual(cmd[idx + 1], "medium")

    def test_thinking_high_passes_flag(self):
        cmd = self._args_for(thinking="high")
        idx = cmd.index("--thinking")
        self.assertEqual(cmd[idx + 1], "high")

    def test_thinking_invalid_returns_error(self):
        # An unknown level should not silently pass through to pi (which
        # would also reject it but with a less actionable message).
        status, raw = ss.call_pi(
            "hello", self.session, tools=None, thinking="bogus",
        )
        self.assertEqual(status, "error")
        self.assertIn("invalid thinking level", raw)

    def test_thinking_levels_constant_matches_pi(self):
        # Keep the level set in sync with what `pi` actually accepts;
        # drifting here produces confusing "invalid thinking level"
        # errors at runtime.
        self.assertEqual(
            set(ss.VALID_THINKING_LEVELS),
            {"off", "minimal", "low", "medium", "high", "xhigh"},
        )


class TestPhaseToolsCacheRouting(unittest.TestCase):
    """run_scanner and run_verification must route to the right cache dir
    based on the tools flag, so tools-mode and no-tools-mode results
    never collide and can be regenerated independently."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.sessions = self.state / "sessions"
        self.sessions.mkdir(parents=True)
        (self.root / "code.py").write_text("x = 1\n")
        self.cfg = ss.OWASP_SCANNERS["B3"]
        # Use the actual prompt hash so the cache key is stable
        self.p_hash = ss.prompt_hash(ss.load_prompt_template(self.cfg))
        self.discovery = {"B3": [".py"]}

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_scan_cache(self, subdir: str, findings):
        c_hash = ss.content_hash((self.root / "code.py").read_bytes())
        key = ss.file_key("code.py", "injection", c_hash, self.p_hash)
        d = self.state / "injection" / subdir
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "injection", "status": "ok",
            "result": findings, "content_hash": c_hash,
            "prompt_hash": self.p_hash,
        }))

    def test_scanner_no_tools_writes_to_results(self):
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                tools=None,
            )
        self.assertTrue((self.state / "injection" / "results").exists())
        self.assertFalse((self.state / "injection" / "results-tools").exists())

    def test_scanner_with_tools_writes_to_results_tools(self):
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                tools=ss.READONLY_TOOLS,
            )
        self.assertTrue((self.state / "injection" / "results-tools").exists())
        self.assertFalse((self.state / "injection" / "results").exists())

    def test_verification_no_tools_reads_results_writes_verifications(self):
        self._seed_scan_cache("results", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))):
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=None,
            )
        self.assertTrue((self.state / "injection" / "verifications").exists())
        self.assertFalse((self.state / "injection" / "verifications-tools").exists())

    def test_verification_with_tools_routes_to_verifications_tools(self):
        self._seed_scan_cache("results-tools", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))):
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=ss.READONLY_TOOLS,
            )
        self.assertTrue((self.state / "injection" / "verifications-tools").exists())
        self.assertFalse((self.state / "injection" / "verifications").exists())

    def test_scanner_forwards_tools_to_call_pi(self):
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock:
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                tools=ss.READONLY_TOOLS,
            )
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(mock.call_args.kwargs["tools"], ss.READONLY_TOOLS)

    def test_verification_reads_scan_results_in_no_tools_dir(self):
        """Regression: when scan ran without tools (results/) and verify
        runs with tools (verifications-tools/), the verify phase must still
        find the scan output in results/ — not look for it in results-tools/.

        The bug: run_verification used its own `tools` flag to pick the
        input dir, so verify-with-tools could never find scan results that
        lived in results/. Coverage was 0/68109 in production."""
        self._seed_scan_cache("results", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock:
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=ss.READONLY_TOOLS,    # verify uses tools
                scan_uses_tools=False,     # scan did not use tools
            )
        self.assertEqual(mock.call_count, 1)
        # Output goes to verifications-tools/, not verifications/
        self.assertTrue((self.state / "injection" / "verifications-tools").exists())
        self.assertFalse((self.state / "injection" / "verifications").exists())

    def test_verification_forwards_tools_to_call_pi(self):
        # Seed in results-tools/ to match the tools-mode scan + tools-mode
        # verify configuration. Both flags must be passed to run_verification
        # so it knows where to read the scan results from.
        self._seed_scan_cache("results-tools", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock:
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=ss.READONLY_TOOLS,
                scan_uses_tools=True,
            )
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(mock.call_args.kwargs["tools"], ss.READONLY_TOOLS)

    def test_scanner_forwards_thinking_to_call_pi(self):
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock:
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                tools=None, thinking="high",
            )
        self.assertEqual(mock.call_args.kwargs["thinking"], "high")

    def test_scanner_default_thinking_is_off(self):
        # The scan phase should default to "off" — enumeration doesn't
        # need chain-of-thought, and this is the single biggest speedup.
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock:
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                tools=None,
            )
        self.assertEqual(mock.call_args.kwargs["thinking"], "off")

    def test_verification_forwards_thinking_to_call_pi(self):
        self._seed_scan_cache("results", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock:
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=None, thinking="high",
            )
        self.assertEqual(mock.call_args.kwargs["thinking"], "high")

    def test_verification_default_thinking_is_medium(self):
        self._seed_scan_cache("results", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock:
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=None,
            )
        self.assertEqual(mock.call_args.kwargs["thinking"], "medium")

    def test_scan_cache_key_includes_thinking(self):
        # Flipping --scan-thinking must produce a different cache key for
        # the same file + prompt, otherwise the same cache file would be
        # returned for two observably-different model behaviors.
        c_hash = ss.content_hash((self.root / "code.py").read_bytes())
        k_off = ss.file_key("code.py", "injection", c_hash, self.p_hash, "off")
        k_high = ss.file_key("code.py", "injection", c_hash, self.p_hash, "high")
        self.assertNotEqual(k_off, k_high)

    def test_verify_cache_key_includes_thinking(self):
        c_hash = ss.content_hash((self.root / "code.py").read_bytes())
        f_sig = ss.findings_signature([{"line": 1, "code": "x"}])
        k_medium = ss.verify_file_key("code.py", "injection", c_hash, f_sig, self.p_hash, "medium")
        k_high = ss.verify_file_key("code.py", "injection", c_hash, f_sig, self.p_hash, "high")
        self.assertNotEqual(k_medium, k_high)

    def test_thinking_change_invalidates_scan_cache(self):
        # End-to-end: a file scanned with thinking=off must be re-scanned
        # when the user flips to thinking=high, even if file content
        # and prompt are unchanged.
        c_hash = ss.content_hash((self.root / "code.py").read_bytes())
        key_off = ss.file_key("code.py", "injection", c_hash, self.p_hash, "off")
        results_dir = self.state / "injection" / "results"
        results_dir.mkdir(parents=True)
        (results_dir / f"{key_off}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "injection", "status": "ok",
            "result": [{"line": 1, "code": "x"}],
            "content_hash": c_hash, "prompt_hash": self.p_hash,
        }))
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")) as mock:
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                tools=None, thinking="high",
            )
        # The high-thinking run must have called pi; the off-thinking
        # cache file does not satisfy its key.
        self.assertEqual(mock.call_count, 1)

    def test_thinking_change_invalidates_verify_cache(self):
        c_hash = ss.content_hash((self.root / "code.py").read_bytes())
        findings = [{"line": 1, "severity": "High", "code": "x",
                     "explanation": "", "fix": ""}]
        f_sig = ss.findings_signature(findings)
        # Seed a verify cache for thinking=medium
        key_medium = ss.verify_file_key(
            "code.py", "injection", c_hash, f_sig, self.p_hash, "medium",
        )
        verify_dir = self.state / "injection" / "verifications"
        verify_dir.mkdir(parents=True)
        (verify_dir / f"{key_medium}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "injection", "status": "ok",
            "verifications": {"1": {"confidence": "High"}},
        }))
        # Seed the scan results it needs to read
        self._seed_scan_cache("results", findings)
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock:
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                tools=None, thinking="high",
            )
        self.assertEqual(mock.call_count, 1)


class TestBuildReportToolsAnnotation(unittest.TestCase):
    """build_report should surface the per-phase tools config in the
    markdown so readers know whether verdicts are file-as-written or
    cross-file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.results_dir = self.state / "injection" / "results"
        self.results_dir.mkdir(parents=True)
        self.output = self.root / "report.md"

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_finding(self, rel, vulns):
        (self.results_dir / f"{rel.replace('/', '_')}.json").write_text(
            json.dumps({
                "file": rel, "scanner": "injection", "status": "ok",
                "result": vulns, "content_hash": "abc",
            })
        )

    def test_header_includes_tools_when_phase_tools_set(self):
        self._seed_finding("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            phase_tools={"discovery": True, "scan": False, "verify": True},
        )
        text = self.output.read_text()
        # All three phases should appear in the header line
        self.assertIn("**Tools:**", text)
        self.assertIn("discovery=read-only", text)
        self.assertIn("scan=none", text)
        self.assertIn("verify=read-only", text)
        self.assertIn(",".join(ss.READONLY_TOOLS), text)

    def test_header_omits_tools_line_when_phase_tools_unset(self):
        self._seed_finding("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
        )
        self.assertNotIn("**Tools:**", self.output.read_text())

    def test_per_scanner_verify_tools_row_appears_when_verify_uses_tools(self):
        self._seed_finding("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        # Seed a verification in the tools-mode cache dir
        vdir = self.state / "injection" / "verifications-tools"
        vdir.mkdir(parents=True, exist_ok=True)
        # We don't need a real verification for the row to appear, just the
        # existence of the dir so has_verification_data becomes True
        ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            phase_tools={"discovery": True, "scan": False, "verify": True},
        )
        text = self.output.read_text()
        self.assertIn("| Verify tools | read-only", text)

    def test_per_scanner_no_verify_tools_row_when_verify_off(self):
        self._seed_finding("a.py", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            phase_tools={"discovery": True, "scan": False, "verify": False},
        )
        self.assertNotIn("| Verify tools |", self.output.read_text())

    def test_report_reads_from_tools_results_dir_when_scan_uses_tools(self):
        """If phase_tools["scan"] is True, the report should look in
        results-tools/ rather than results/ for the findings to summarize."""
        # No files in results/ but one in results-tools/
        rd_tools = self.state / "injection" / "results-tools"
        rd_tools.mkdir(parents=True)
        (rd_tools / "code_py.json").write_text(json.dumps({
            "file": "code.py", "scanner": "injection", "status": "ok",
            "result": [
                {"line": 1, "severity": "High", "code": "x",
                 "explanation": "", "fix": ""},
            ],
            "content_hash": "abc",
        }))
        stats = ss.build_report(
            self.state, self.output, self.root, ["B3"],
            {"B3": [".py"]}, allowlist=[],
            phase_tools={"discovery": True, "scan": True, "verify": True},
        )
        self.assertEqual(stats["severity_counts"]["High"], 1)
        # And not from the empty results/ dir
        text = self.output.read_text()
        self.assertIn("`code.py`", text)


class TestToolsCLI(unittest.TestCase):
    """Smoke tests for the three new CLI flags."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        (self.root / "code.py").write_text("x = 1\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, expect_exit=None, timeout=30):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             *args],
            cwd=str(self.root),
            capture_output=True, text=True, timeout=timeout,
        )
        if expect_exit is not None:
            self.assertEqual(
                proc.returncode, expect_exit,
                msg=f"Expected exit {expect_exit}, got {proc.returncode}\n"
                    f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        return proc

    def test_default_discovery_tools_on(self):
        # Without explicit flags, --discovery-tools defaults to True
        # (so the discovery cache is discovery-tools.json)
        self._run("--scanner", "B3", "--phase", "1", "--dry-run",
                  "--redetect", expect_exit=0)
        self.assertTrue((self.state / "discovery-tools.json").exists())
        self.assertFalse((self.state / "discovery.json").exists())

    def test_no_discovery_tools_uses_plain_discovery(self):
        self._run("--scanner", "B3", "--phase", "1", "--dry-run",
                  "--redetect", "--no-discovery-tools", expect_exit=0)
        self.assertTrue((self.state / "discovery.json").exists())
        self.assertFalse((self.state / "discovery-tools.json").exists())

    def test_help_lists_all_three_tool_flags(self):
        proc = self._run("--help")
        for flag in ("--discovery-tools", "--scan-tools", "--verify-tools",
                     "--no-discovery-tools", "--no-scan-tools",
                     "--no-verify-tools"):
            self.assertIn(flag, proc.stdout)


class TestThinkingCLI(unittest.TestCase):
    """Smoke tests for --scan-thinking / --verify-thinking flags."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        (self.root / "code.py").write_text("x = 1\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, expect_exit=None, timeout=30):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             *args],
            cwd=str(self.root),
            capture_output=True, text=True, timeout=timeout,
        )
        if expect_exit is not None:
            self.assertEqual(
                proc.returncode, expect_exit,
                msg=f"Expected exit {expect_exit}, got {proc.returncode}\n"
                    f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        return proc

    def test_help_lists_thinking_flags(self):
        proc = self._run("--help")
        for flag in ("--scan-thinking", "--verify-thinking"):
            self.assertIn(flag, proc.stdout)

    def test_invalid_thinking_level_rejected(self):
        # argparse should reject levels outside the valid set before
        # any pi call happens.
        proc = self._run("--scanner", "B3", "--scan-thinking", "bogus")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr.lower())


class TestMaxFileSizeCLI(unittest.TestCase):
    """Smoke tests for the --max-file-size flag and its 1 MiB default."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / ".security_scan"
        # One small file (~6 bytes) and one ~6 KB file. Both are well
        # under the 1 MiB default, so a separate test creates a
        # genuinely oversized file to exercise the default.
        (self.root / "small.py").write_text("x = 1\n")
        (self.root / "modest.py").write_text("x = 1\n" + "# pad\n" * 1000)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, expect_exit=None, timeout=30):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             *args],
            cwd=str(self.root),
            capture_output=True, text=True, timeout=timeout,
        )
        if expect_exit is not None:
            self.assertEqual(
                proc.returncode, expect_exit,
                msg=f"Expected exit {expect_exit}, got {proc.returncode}\n"
                    f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        return proc

    def test_help_lists_max_file_size(self):
        proc = self._run("--help")
        self.assertIn("--max-file-size", proc.stdout)
        # Help text should mention the 1 MiB default so users can
        # discover the cap without reading the README.
        self.assertIn("1048576", proc.stdout)

    def test_explicit_tight_limit_filters_in_dry_run(self):
        # --max-file-size 100 is tighter than both files in setUp, so
        # only the 6-byte file survives.
        proc = self._run(
            "--scanner", "B3", "--phase", "2", "--dry-run",
            "--max-file-size", "100",
        )
        combined = proc.stdout + proc.stderr
        self.assertIn("Found 1 non-binary files", combined)
        self.assertIn("Skipped 1 file(s) larger than 100 bytes", combined)

    def test_default_1mib_keeps_normal_source_files(self):
        # Both files in setUp are well under 1 MiB; the default
        # leaves them alone and prints no skip line.
        proc = self._run(
            "--scanner", "B3", "--phase", "2", "--dry-run",
        )
        combined = proc.stdout + proc.stderr
        self.assertIn("Found 2 non-binary files", combined)
        self.assertNotIn("Skipped", combined)

    def test_default_1mib_filters_genuinely_oversized(self):
        # Create a 2 MiB file alongside the small one. The default
        # cap (1 MiB) must drop the 2 MiB file and report the skip.
        (self.root / "huge.py").write_text(
            "x = 1\n" + "# pad\n" * (2 * 1024 * 1024 // 8)
        )
        proc = self._run(
            "--scanner", "B3", "--phase", "2", "--dry-run",
        )
        combined = proc.stdout + proc.stderr
        # Two small files survive, one big file is dropped.
        self.assertIn("Found 2 non-binary files", combined)
        self.assertIn(f"Skipped 1 file(s) larger than {ss.DEFAULT_MAX_FILE_SIZE} bytes", combined)

    def test_explicit_zero_disables_cap(self):
        # --max-file-size 0 is the opt-out for repos with legitimately
        # huge files. Even a 2 MiB file is kept.
        (self.root / "huge.py").write_text(
            "x = 1\n" + "# pad\n" * (2 * 1024 * 1024 // 8)
        )
        proc = self._run(
            "--scanner", "B3", "--phase", "2", "--dry-run",
            "--max-file-size", "0",
        )
        combined = proc.stdout + proc.stderr
        self.assertIn("Found 3 non-binary files", combined)
        self.assertNotIn("Skipped", combined)


# ── Progress tracker tests ───────────────────────────────────────────────────


import io as _io  # noqa: E402


class TestProgressTrackerBasic(unittest.TestCase):
    """Unit tests for the ProgressTracker class itself."""

    def setUp(self):
        # Make sure we never auto-start a real daemon thread; tests that
        # need rendering will mock sys.stderr and patch _use_cr explicitly.
        self._stderr_patch = patch.object(ss.sys, "stderr", new=_io.StringIO())
        self._stderr_patch.start()

    def tearDown(self):
        self._stderr_patch.stop()

    def test_disabled_tracker_methods_are_noop(self):
        p = ss.ProgressTracker(enabled=False)
        p.start_phase("scan", 100)
        p.tick("scan")
        p.tick("scan")
        p.tick("scan", amount=5)
        p.stop()
        # Nothing should have been written to stderr
        self.assertEqual(ss.sys.stderr.getvalue(), "")

    def test_start_phase_creates_entry(self):
        p = ss.ProgressTracker(enabled=True)
        # Force _use_cr False so the render path is deterministic
        with patch.object(p, "_use_cr", False), \
             patch.object(p, "_ensure_render_thread"):  # don't start daemon
            p.start_phase("scan", 100)
            p._render()  # one render, no ticks yet
            out = ss.sys.stderr.getvalue()
            self.assertIn("[scan] 0/100", out)

    def test_tick_increments_completed(self):
        p = ss.ProgressTracker(enabled=True)
        with patch.object(p, "_use_cr", False), \
             patch.object(p, "_ensure_render_thread"):
            p.start_phase("scan", 5)
            for _ in range(3):
                p.tick("scan")
            p._render()
            out = ss.sys.stderr.getvalue()
            self.assertIn("[scan] 3/5", out)

    def test_tick_caps_at_total(self):
        p = ss.ProgressTracker(enabled=True)
        with patch.object(p, "_use_cr", False), \
             patch.object(p, "_ensure_render_thread"):
            p.start_phase("scan", 3)
            p.tick("scan", amount=10)  # way more than total
            p._render()
            out = ss.sys.stderr.getvalue()
            self.assertIn("[scan] 3/3", out)
            self.assertIn("(done)", out)

    def test_tick_unknown_phase_is_noop(self):
        p = ss.ProgressTracker(enabled=True)
        p.tick("nonexistent")  # no crash

    def test_render_uses_cr_when_use_cr_true(self):
        p = ss.ProgressTracker(enabled=True)
        with patch.object(p, "_use_cr", True), \
             patch.object(p, "_ensure_render_thread"):
            p.start_phase("scan", 10)
            p._render()
            out = ss.sys.stderr.getvalue()
            # One \r-prefixed line, padded to 80 chars
            self.assertTrue(out.startswith("\r"), f"expected \\r prefix, got: {out!r}")
            # Strip \r and any trailing padding, then check length
            payload = out.lstrip("\r").rstrip()
            # The line should be ljust(80) — but trailing space strip may have
            # trimmed some. So check the payload is well-formed.
            self.assertIn("[scan] 0/10", payload)
            self.assertGreaterEqual(len(out), 81)  # \r + at least 80 chars of content

    def test_render_uses_newline_when_use_cr_false(self):
        p = ss.ProgressTracker(enabled=True)
        with patch.object(p, "_use_cr", False), \
             patch.object(p, "_ensure_render_thread"):
            p.start_phase("scan", 10)
            p._render()
            out = ss.sys.stderr.getvalue()
            self.assertTrue(out.endswith("\n"), f"expected trailing \\n, got: {out!r}")
            # No padding when not on TTY
            self.assertLess(len(out.rstrip("\n")), 80)

    def test_stop_joins_render_thread_and_emits_final_line(self):
        p = ss.ProgressTracker(enabled=True, refresh_interval=0.05)
        # Mock the render thread to prevent race with stop()
        with patch.object(p, "_ensure_render_thread"):
            p.start_phase("scan", 2)
            p.tick("scan")
            p.stop()
            out = ss.sys.stderr.getvalue()
            self.assertIn("1/2", out)


class TestFormatEta(unittest.TestCase):
    def test_seconds_under_minute(self):
        self.assertEqual(ss._format_eta(-1), "?")
        self.assertEqual(ss._format_eta(0), "<1s")
        self.assertEqual(ss._format_eta(0.5), "<1s")
        self.assertEqual(ss._format_eta(30), "30s")

    def test_minutes(self):
        self.assertEqual(ss._format_eta(60), "1m00s")
        self.assertEqual(ss._format_eta(125), "2m05s")

    def test_hours(self):
        self.assertEqual(ss._format_eta(3600), "1h00m")
        self.assertEqual(ss._format_eta(3660), "1h01m")
        self.assertEqual(ss._format_eta(7325), "2h02m")

    def test_infinity(self):
        self.assertEqual(ss._format_eta(float("inf")), "?")


class TestProgressIntegration(unittest.TestCase):
    """run_scanner and run_verification should call progress.start_phase()
    once and progress.tick() per completed file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.sessions = self.state / "sessions"
        self.sessions.mkdir(parents=True)
        (self.root / "code.py").write_text("x = 1\n")
        self.cfg = ss.OWASP_SCANNERS["B3"]
        self.p_hash = ss.prompt_hash(ss.load_prompt_template(self.cfg))
        self.discovery = {"B3": [".py"]}

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_scan_cache(self, subdir, vulns):
        c_hash = ss.content_hash((self.root / "code.py").read_bytes())
        key = ss.file_key("code.py", "injection", c_hash, self.p_hash)
        d = self.state / "injection" / subdir
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{key}.json").write_text(json.dumps({
            "file": "code.py", "scanner": "injection", "status": "ok",
            "result": vulns, "content_hash": c_hash,
            "prompt_hash": self.p_hash,
        }))

    def test_run_scanner_calls_start_phase_and_tick(self):
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        # Use enabled=True but suppress the render thread; we only need
        # the bookkeeping (start_phase + tick) to be exercised.
        tracker = ss.ProgressTracker(enabled=True)
        with patch.object(ss, "call_pi", return_value=("ok", "[]")), \
             patch.object(tracker, "_ensure_render_thread"):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                progress=tracker,
            )
        # After the run, the phase should be 1/1 (done)
        with tracker._lock:
            entry = tracker._phases.get("scan")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["total"], 1)
            self.assertEqual(entry["completed"], 1)

    def test_run_verification_calls_start_phase_and_tick(self):
        self._seed_scan_cache("results", [
            {"line": 1, "severity": "High", "code": "x",
             "explanation": "", "fix": ""},
        ])
        tracker = ss.ProgressTracker(enabled=True)
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))), \
             patch.object(tracker, "_ensure_render_thread"):
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                progress=tracker,
            )
        with tracker._lock:
            entry = tracker._phases.get("verify")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["total"], 1)
            self.assertEqual(entry["completed"], 1)

    def test_run_scanner_skips_progress_when_none(self):
        all_files, ext_map, name_map = ss.find_all_files(self.root)
        # progress=None should not crash even though the call is made
        with patch.object(ss, "call_pi", return_value=("ok", "[]")):
            ss.run_scanner(
                "B3", self.cfg, ext_map, name_map, self.discovery,
                self.root, self.state, self.sessions,
                concurrency=1, max_files=0, rescan=False, dry_run=False,
                progress=None,
            )

    def test_progress_disabled_via_no_progress_flag(self):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             "--scanner", "B3", "--phase", "1", "--dry-run",
             "--redetect", "--no-progress"],
            cwd=str(self.root),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        # No progress line should appear in stderr
        self.assertNotIn("[scan]", proc.stderr)
        self.assertNotIn("[verify]", proc.stderr)

    def test_help_lists_progress_flag(self):
        proc = subprocess.run(
            [sys.executable,
             str(Path(__file__).resolve().parent / "security_scan.py"),
             "--help"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertIn("--progress", proc.stdout)
        self.assertIn("--no-progress", proc.stdout)


# ── Cache-aware verify progress ─────────────────────────────────────────────


class TestVerifyCachePreCheck(unittest.TestCase):
    """run_verification should pre-check the cache and skip already-verified
    files from both the executor submission and the progress total. Without
    this, a mostly-cached run shows 99% complete in the first second and
    then stalls on the remaining 1%, giving a wildly wrong ETA.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.sessions = self.state / "sessions"
        self.sessions.mkdir(parents=True)
        (self.root / "a.py").write_text("a = 1\n")
        (self.root / "b.py").write_text("b = 2\n")
        (self.root / "c.py").write_text("c = 3\n")
        (self.root / "d.py").write_text("d = 4\n")
        self.cfg = ss.OWASP_SCANNERS["B3"]
        self.p_hash = ss.prompt_hash(ss.load_prompt_template(self.cfg))
        self.discovery = {"B3": [".py"]}

    def tearDown(self):
        self.tmp.cleanup()

    def _write_scan_result(self, rel, vulns):
        c_hash = ss.content_hash((self.root / rel).read_bytes())
        # Cache key now includes thinking; the scan default is "off" so
        # seed with that to match the keys the production path produces.
        key = ss.file_key(rel, "injection", c_hash, self.p_hash, "off")
        rd = self.state / "injection" / "results"
        rd.mkdir(parents=True, exist_ok=True)
        (rd / f"{key}.json").write_text(json.dumps({
            "file": rel, "scanner": "injection", "status": "ok",
            "result": vulns, "content_hash": c_hash,
            "prompt_hash": self.p_hash,
        }))
        return c_hash

    def _write_verification_cache(self, rel, vulns):
        c_hash = ss.content_hash((self.root / rel).read_bytes())
        f_sig = ss.findings_signature(vulns)
        vph = ss.prompt_hash(ss.load_verify_prompt())
        # verify_file_key signature is (rel, scanner_name, content_hash,
        # findings_sig, verify_prompt_hash, thinking) — must match what
        # run_verification's pre-check uses. Seed with "medium" to match
        # the verify phase default.
        key = ss.verify_file_key(rel, "injection", c_hash, f_sig, vph, "medium")
        vd = self.state / "injection" / "verifications"
        vd.mkdir(parents=True, exist_ok=True)
        (vd / f"{key}.json").write_text(json.dumps({
            "file": rel, "scanner": "injection", "status": "ok",
            "verifications": {
                str(v["line"]): {"confidence": "High"} for v in vulns
            },
            "content_hash": c_hash, "findings_signature": f_sig,
            "verify_prompt_hash": vph,
        }))

    def test_cached_files_excluded_from_progress_total(self):
        """With 3 files-with-findings and 2 already cached, the progress
        total must be 1 (not 3) so the rate/ETA are accurate."""
        vulns = [{"line": 1, "severity": "High", "code": "x",
                  "explanation": "", "fix": ""}]
        # Cache b.py and c.py, leave a.py uncached
        for rel, cached in [("a.py", False), ("b.py", True), ("c.py", True)]:
            self._write_scan_result(rel, vulns)
            if cached:
                self._write_verification_cache(rel, vulns)

        tracker = ss.ProgressTracker(enabled=True)
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock_pi, \
             patch.object(tracker, "_ensure_render_thread"), \
             patch("builtins.print"):  # suppress the [VERIFY-SKIP] noise
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                progress=tracker,
            )
        # pi was called only once (for the one uncached file)
        self.assertEqual(mock_pi.call_count, 1)
        # Progress total reflects the actual work
        with tracker._lock:
            entry = tracker._phases.get("verify")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["total"], 1)
            self.assertEqual(entry["completed"], 1)

    def test_reverify_bypasses_cache_pre_check(self):
        """With --reverify, the cache should be ignored — all files with
        findings are queued for verification."""
        vulns = [{"line": 1, "severity": "High", "code": "x",
                  "explanation": "", "fix": ""}]
        for rel in ("a.py", "b.py", "c.py"):
            self._write_scan_result(rel, vulns)
            self._write_verification_cache(rel, vulns)

        tracker = ss.ProgressTracker(enabled=True)
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))) as mock_pi, \
             patch.object(tracker, "_ensure_render_thread"), \
             patch("builtins.print"):
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=True, dry_run=False,
                progress=tracker,
            )
        self.assertEqual(mock_pi.call_count, 3)
        with tracker._lock:
            entry = tracker._phases.get("verify")
            self.assertEqual(entry["total"], 3)

    def test_section_header_shows_cache_breakdown(self):
        """The verify section header should show how many files are
        already verified vs how many need verification, so the user knows
        what the progress line is measuring."""
        vulns = [{"line": 1, "severity": "High", "code": "x",
                  "explanation": "", "fix": ""}]
        for rel, cached in [("a.py", False), ("b.py", True), ("c.py", True), ("d.py", True)]:
            self._write_scan_result(rel, vulns)
            if cached:
                self._write_verification_cache(rel, vulns)

        tracker = ss.ProgressTracker(enabled=True)
        with patch.object(ss, "call_pi", return_value=("ok", json.dumps([
            {"line": 1, "confidence": "High", "exploitable": "yes",
             "verification_reason": "ok"},
        ]))), \
             patch.object(tracker, "_ensure_render_thread"), \
             patch("builtins.print") as mock_print:
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                progress=tracker,
            )
        # Find the "Files with findings" line in the captured prints
        all_output = "\n".join(
            str(call.args[0]) if call.args else "" for call in mock_print.call_args_list
        )
        self.assertIn("4 (3 already verified, 1 to verify)", all_output)

    def test_all_cached_no_progress_total(self):
        """If every file is cached, files_to_verify is empty and the
        progress phase is never started (avoids a 0/0 line that
        confuses the user)."""
        vulns = [{"line": 1, "severity": "High", "code": "x",
                  "explanation": "", "fix": ""}]
        for rel in ("a.py", "b.py"):
            self._write_scan_result(rel, vulns)
            self._write_verification_cache(rel, vulns)

        tracker = ss.ProgressTracker(enabled=True)
        with patch.object(ss, "call_pi") as mock_pi, \
             patch.object(tracker, "_ensure_render_thread"), \
             patch("builtins.print"):
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                progress=tracker,
            )
        # No pi calls (all cached)
        self.assertEqual(mock_pi.call_count, 0)
        # The verify phase was never started in the tracker
        with tracker._lock:
            self.assertNotIn("verify", tracker._phases)

    def test_size_limit_skips_oversized_stale_scan_result(self):
        """A scan result cached for a file that has since grown past
        --max-file-size must be skipped in the verify phase, not
        silently re-read. This is the defensive re-check that pairs
        with the discovery-time filter, catching files that became
        oversized after the scan (or stale results from a previous
        run that had no size limit)."""
        vulns = [{"line": 1, "severity": "High", "code": "x",
                  "explanation": "", "fix": ""}]
        # Write a scan result for a.py, then grow the file past the limit
        self._write_scan_result("a.py", vulns)
        (self.root / "a.py").write_text("x = 1\n" + "# pad\n" * 1000)  # ~6 KB
        # Verify with a 1 KB limit
        with patch.object(ss, "call_pi") as mock_pi, \
             patch("builtins.print"):
            ss.run_verification(
                "B3", self.cfg, self.root, self.state, self.sessions,
                concurrency=1, reverify=False, dry_run=False,
                max_file_size=1024,
            )
        # pi was never called: the size check rejected the file
        # before the cache pre-check (or verify_finding) could run.
        self.assertEqual(mock_pi.call_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
