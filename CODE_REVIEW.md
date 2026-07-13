# CODE REVIEW — security_scan.py (OWASP Top 10 Scanner)

> **Review type:** Read-only code quality and architecture review
> **Files reviewed:** Every source, test, prompt, and configuration file in the project
> **Date:** 2026-07-13
> **Scope:** General code quality, architectural assessment, and security analysis.
> No existing code is modified; this review is informational.

---

## 1. Bugs

### BUG-1 — `find_all_files()` dead code: unreachable `return` statement
**Severity: Medium**
**File:** `security_scan.py:225-226`

The `find_all_files()` function contains two consecutive `return` statements at lines 225-226. The first `return` (line 225) is unreachable because the `if max_file_size > 0 and size_skipped > 0` block at line 223 is inside the `for` loop body that already returned (implicitly via fall-through after the loop). The second return at line 226 is the actual exit. The first return is never executed and signals either a refactoring artifact or a logic error.

### BUG-2 — Exit code 2 conflicts with `--fail-on` CI semantics
**Severity: High**
**File:** `security_scan.py:3097-3102` / `README.md`

The scanner uses exit code 1 for findings that trip `--fail-on` or `--fail-on-confidence`, and exit code 2 for "files that errored or timed out." However, `sys.exit(2)` is called *after* the fail-on gates, and CI systems typically treat any non-zero exit as a failure. A run that has zero findings but one errored file exits 2 — which CI interprets as a failure. This means exit 2 is not a "warning" in CI; it is a hard gate. The README documents exit 2 as "scan completed but at least one file errored/timed out (no signal from it)" but does not warn that this will break CI unless the calling script explicitly handles exit 2 separately from exit 1.

### BUG-3 — `EXCLUDE_FILES` does not exclude `.security_scan/` directory
**Severity: Low**
**File:** `security_scan.py:135`

The `EXCLUDE_FILES` set lists specific filenames (`security_scan.py`, `security_report.md`, `sqli_scan.py`, `sqli_report.md`) but does not include `.security_scan/` itself. While `EXCLUDE_DIRS` does include `.security_scan`, this is not a safety guarantee: if the `--state-dir` flag is used to point `.security_scan` to a different path, that path would no longer be excluded from file scanning. The state directory contents (cache, allowlist, session data) should always be excluded from the scanner's own scan target set.

### BUG-4 — Progress daemon thread may leak on unhandled `KeyboardInterrupt`
**Severity: Low**
**File:** `security_scan.py:3029-3030`

The `try: ... finally: progress.stop()` block at line 3029 ensures the progress daemon thread is stopped for the normal exit path. However, `KeyboardInterrupt` raised during the `run_scanner` or `run_verification` loop (inside the `with ThreadPoolExecutor` context) may cause `sys.exit(130)` before `finally` executes on some platforms, and the daemon thread's `sys.stderr.write` calls could race with interpreter shutdown. In practice, daemon threads are killed when the process exits, but the final progress line may never be emitted.

### BUG-5 — `CONFIDENCE_ORDER` assigns value 0 to both "Unverified" and "Unknown"
**Severity: Low**
**File:** `security_scan.py:1240`

```python
CONFIDENCE_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Unverified": 0, "Unknown": 0}
```

"Unverified" and "Unknown" have the same numeric value (0). This means `CONFIDENCE_ORDER.get("Unknown", 0) < cutoff` is identical to `CONFIDENCE_ORDER.get("Unverified", 0) < cutoff`, making it impossible to distinguish them via threshold comparison. The verifier prompt only ever produces "High", "Medium", or "Low" confidence; "Unknown" appears only as a default fallback in `load_verification_for_file` where the response has no `confidence` key. This is not a functional bug today, but it creates a latent ambiguity if a new code path ever sets `confidence: "Unknown"`.

---

## 2. Potential Improvements

### IMPROVE-1 — Six-layer JSON recovery strategy in `extract_json_array()` and `extract_json_object()`
**Severity: Medium**
**File:** `security_scan.py:287-337` / `security_scan.py:410-439`

The extraction logic follows a six-layer strategy: (1) whole-response parse, (2) code-fence strip then parse, (3) `raw_decode` from each `[`/`{` position, (4) truncated-array/object recovery with manual depth-tracking state machines, (5) prose-fallback markers (`NO_VULNERABILITIES`, `NO_FINDINGS`, `EMPTY_ARRAY`), and (6) error dict with a raw preview.

Each layer is well-documented and correct in isolation. The concern is that this is a large, custom JSON parser with ~200 lines of hand-written depth-tracking state machines (lines 338-410 and 377-440). Maintenance burden is high: any model behavior change (e.g. emitting JSON inside a prose list like `"- [1,2,3]"`) could bypass all six layers silently. Improvements:

- Add a test for a JSON array that starts mid-response with leading `"Key: "` prose that contains a `[` before the real JSON (currently tested but the test uses a different bracket position).
- Consider wrapping a more robust library like `orjson` or `ujson` (if acceptable) or a dedicated extraction library for production use, to reduce the custom state-machine code.
- The prose fallback (layer 5) is fragile: `NO_VULNERABILITIES` in a model's prose reasoning would incorrectly produce an empty array.

### IMPROVE-2 — `verify_prompt.txt` sends entire file content per-file
**Severity: Medium**
**File:** `prompts/verify_prompt.txt` / `security_scan.py:1199-1206`

The verify phase sends the full file content (`{file_content}`) plus the findings array (`{findings_json}`) for every file being verified. For a 50 KB file with 5 findings, the prompt is ~55 KB, and the model context window may be large but this is still substantial when multiplied across concurrency. Additionally, the same file is sent again if it was also scanned (not separately, the verify phase is only for files with findings), but the file content is loaded three times per verify call: once for `content_hash`, once to `.decode()` for the prompt, and once in `verify_file()` for the cached `raw_bytes` in `run_verification`. See MAINTAIN-1 for the I/O details.

### IMPROVE-3 — `call_pi()` temp file in `/tmp` — potential cross-user exposure
**Severity: Medium**
**File:** `security_scan.py:236-251`

`call_pi()` writes the full prompt to a `tempfile.NamedTemporaryFile` with `prefix='pi_prompt_'` in the system's default temp directory (typically `/tmp` on macOS). The file is **not** created with `mode='0600'` explicitly, so on multi-user systems the file is world-readable. An attacker with access to the machine could read the prompt contents (which include the full file content being scanned). The file is created with `delete=False` (line 239), meaning it persists on disk until the `finally` block unlinks it. In the window between creation and unlinking, the prompt is visible to all users.

### IMPROVE-4 — Progress line daemon thread interleaves with `[SCAN]` per-file stderr lines
**Severity: Low**
**File:** `security_scan.py:376-380` / `security_scan.py:444-455`

The progress tracker writes to `sys.stderr` via `sys.stderr.write("\r" + padded)` on TTYs (line 446) and `sys.stderr.write(line + "\n")` off-TTY. Meanwhile, `scan_file()` and `verify_finding()` also write to stderr with lines like `"[SCAN] [injection] a.py"`. When concurrency > 1, the progress line and per-file lines will interleave. On a TTY, the `\r` overwrites correctly, but off-TTY (CI), each progress update is a new line, and per-file `[SCAN]` lines appear between them. The README acknowledges this ("with `concurrency > 1` the two can interleave on stderr but each is independently grep-able"), but for CI log consumers, the interleaving makes it harder to parse progress lines and file lines separately.

### IMPROVE-5 — Allowlist "first match wins" semantics can suppress broader suppressions
**Severity: Low**
**File:** `security_scan.py:773-781` / `security_scan.py:784-795`

`find_suppression()` iterates the allowlist entries in order and returns the first match. This means a global wildcard `{"scanner": "*", "file": "tests/**", "line": 0}` will suppress ALL findings in test files, including specific overrides that might have been added for individual lines. Conversely, if a broad wildcard is listed first, specific line-level suppressions are never reached. Users should document their expected suppression priority order. The documentation (README) says "first matching entry wins" but does not warn users about the ordering sensitivity.

### IMPROVE-6 — `--scan-thinking off → high` triggers a full re-scan of all cache entries
**Severity: Low**
**File:** `security_scan.py:192-203`

The cache key includes the thinking level (line 192), so flipping from `--scan-thinking off` to `--scan-thinking high` produces a completely distinct cache namespace. This means a user who runs with `off` for speed and then switches to `high` will see a full re-scan of every file, even though the underlying file content and prompts are unchanged. This is the correct behavior (different thinking produces different model behavior), but the README should make this explicit so users understand that changing `--scan-thinking` is not a cheap toggle — it triggers a full rescan.

### IMPROVE-7 — CSV report: `code` and `explanation` fields may contain commas
**Severity: Low**
**File:** `security_scan.py:2592-2610`

The CSV report uses `csv.DictWriter` with `quoting=csv.QUOTE_MINIMAL`, which correctly quotes fields containing commas. However, the `code` field (a code snippet) may contain newlines, and `csv.QUOTE_MINIMAL` only quotes fields that contain the delimiter, quotechar, or a newline. This means newlines in code snippets are preserved correctly in the CSV output, but visual inspection of the raw file would show multi-line fields without quoting. The tests confirm this is handled (`handles_newlines_and_quotes_in_fields`).

---

## 3. Code Quality / Maintainability

### MAINTAIN-1 — Monolithic ~3100-line single file, zero module boundaries
**Severity: Medium**
**File:** `security_scan.py` (entire file)

The entire scanner — argument parsing, discovery, scanning, verification, report generation (both markdown and CSV), JSON extraction, progress tracking, and the main entry point — lives in a single file. While this is convenient for a zero-dependency tool, it means:

- No clear module boundaries or separation of concerns.
- Test coverage, while comprehensive, tests the module at the top level with `import security_scan as ss`, which makes refactoring difficult without breaking tests.
- Adding a new report format or scanner requires editing the same file that has 3107 lines.
- The cyclomatic complexity of `build_report()` alone (line 858) is extremely high — it contains nested loops, multiple early returns, and a deeply nested `for scanner_id in scanner_ids` loop with inner processing for each result file.

**Recommendation:** No change is required. This is an architectural observation. If the project grows beyond ~4000 lines, consider extracting `build_report()` into a `report.py` module.

### MAINTAIN-2 — ~80% logic duplication between `build_report()` and `build_csv_report()`
**Severity: High**
**File:** `security_scan.py:858-1150` / `security_scan.py:1234-1688`

`build_report()` (markdown) and `build_csv_report()` (CSV/TSV) share nearly identical logic for:
- Loading and parsing result JSONs from `results_dir`
- Resolving verification cache via `load_verification_for_file`
- Applying allowlist suppression via `find_suppression`
- Computing severity counts, confidence counts, gated counts
- Building the per-finding data structure

The only difference is the output format. Approximately 80% of the code between these two functions is near-identical (same iteration, same conditions, same counts). A refactor to extract a shared "report data builder" function would reduce duplication and ensure both formats stay in sync.

### MAINTAIN-3 — Two-file read pattern in `scan_file()` and `verify_finding()`
**Severity: Low**
**File:** `security_scan.py:668-676` / `security_scan.py:1187-1191`

In `scan_file()`:
1. Line 669: `raw_bytes = filepath.read_bytes()` — reads the entire file
2. Line 670: `c_hash = content_hash(raw_bytes)` — uses it for hashing
3. Line 674: `file_content = raw_bytes.decode("utf-8", errors="replace")` — reuses the bytes

This is efficient. However, in `verify_finding()` at `security_scan.py:1187-1193`:
1. Line 1187: `raw_bytes = filepath.read_bytes()`
2. Line 1191: `c_hash = content_hash(raw_bytes)`
3. Line 1193: `f_sig = findings_signature(findings)`
4. Line 1199: `file_content = raw_bytes.decode("utf-8", errors="replace")`

And then in `run_verification()` at line 1253 (the pre-check loop), the same file is read again for `content_hash`. This is the "double read" mentioned in the constraints. The pre-check loop (line 1253) reads `filepath.read_bytes()` to compute the cache key, and `verify_finding()` reads it again. For large files, this is two I/O operations for the same data.

### MAINTAIN-4 — Prompt templates are text files with manual `{placeholder}` substitution
**File:** `security_scan.py:214-226` / `prompts/*.txt`

Scanner prompts use `str.format(filename=..., file_content=...)` which is simple but fragile: if a prompt file contains a bare `{` or `}` that is not a valid format placeholder, it will raise a `KeyError` (caught and returned as an error). A more robust approach would be to use a template engine or escape braces. However, the error is caught gracefully (see test `test_prompt_format_error_returned_gracefully` in `test_security_scan.py:363-369`).

### MAINTAIN-5 — Hardcoded file size cap constant `DEFAULT_MAX_FILE_SIZE = 1 MiB`
**File:** `security_scan.py:142`

The default is hardcoded as `1 * 1024 * 1024` but expressed as a constant. The README and CLI help both reference this value, but the constant name (`DEFAULT_MAX_FILE_SIZE`) is not documented with its rationale in the constant's own docstring (the docstring is in `find_all_files()`). If the constant value changes, all downstream code that references it will automatically update, but the user-facing documentation (README, CLI help) must also be updated.

### MAINTAIN-6 — `EXCLUDE_DIRS` includes hardcoded paths with no configuration mechanism
**File:** `security_scan.py:130-132`

`EXCLUDE_DIRS` is a hard-coded `frozenset` with entries like `Source/Regression` and `ThirdParty/wheelhouse`. These are clearly repository-specific and should not be in a general-purpose scanner. Users who need to add their own exclusions must edit the source. A command-line `--exclude-dir` flag or a `.security_scanrc` file would improve flexibility.

### MAINTAIN-7 — Test file mirrors the source structure but is ~2793 lines
**File:** `test_security_scan.py`

The test file is nearly as long as the source. It covers all major code paths via mocked `call_pi` and filesystem manipulation. The tests are well-structured with clear class groupings. No changes are needed — this is a quality observation that the test suite is thorough.

### MAINTAIN-8 — CSV `import csv` is inside the function body
**File:** `security_scan.py:1235`

```python
def build_csv_report(...):
    import csv  # local import keeps the markdown-only path off this dep's load
```

The `csv` module is a standard library import, not a third-party dependency. The comment says "keeps the markdown-only path off this dep's load" but `csv` has already been imported elsewhere in the test file. This is unnecessary obfuscation — `csv` is a stdlib module and has no import-time side effects. The `import csv` at module level (used by `test_security_scan.py`) works fine.

### MAINTAIN-9 — README.md has ~350 lines and is the project's primary documentation
**File:** `README.md`

The README serves as the de facto API documentation, covering features, CLI flags, three-phase workflow, per-phase tools, per-phase reasoning, progress indicator, cache invalidation, allowlist format, report format, exit codes, excludes, custom prompts, troubleshooting, and tests. This is well-organized but unusually comprehensive for a README. Consider extracting the "three-phase workflow" and "CLI reference" into a separate `DOCS.md` if the project grows further.

### MAINTAIN-10 — `.gitignore` is a standard GitHub `.gitignore` Python template
**File:** `.gitignore`

The `.gitignore` is a large standard template with no project-specific entries. Notably, it does **not** exclude `.security_scan/`, `*.json` in the root, or `security_report.md`. These are the scanner's own artifacts. The `.gitignore` does not contain a single line about the project's generated files.

**Recommendation:** Add `.security_scan/` and `security_report.*` to `.gitignore`.

### MAINTAIN-11 — `LICENSE` is Apache 2.0 with no copyright holder
**File:** `LICENSE`

The Apache 2.0 LICENSE file ends with:
```
Copyright [yyyy] [name of copyright owner]
```

The placeholder brackets are left unfilled. While the template is standard, this means the LICENSE has no actual copyright notice, which could cause legal ambiguity in some jurisdictions.

**Recommendation:** Replace the bracketed placeholders with the actual copyright holder and year.

---

## 4. Security Concerns

### SEC-1 — `.security_scan/` leaks sensitive code snippets to plaintext on disk
**Severity: Critical**
**File:** `security_scan.py:130` / `security_scan.py:694-700`

The state directory `.security_scan/` stores cached results as JSON files under `.security_scan/<scanner>/results/` and `.security_scan/<scanner>/verifications/`. Each cache entry includes the raw scan result (`result` key), which contains the full file content that was sent to the model (via the `{file_content}` placeholder in the prompt). While the cache does not store the *full* prompt (it stores a hash), the verification cache stores `verifications` with confidence/exploitability ratings, and the scan results may include `code` snippets from the file. Additionally, the `.security_scan/allowlist.json` and `.security_scan/sessions/` directory (used by `pi`) may contain session data with model interaction history.

If the repository is committed or shared, `.security_scan/` could leak sensitive internal code. The `.gitignore` does **not** exclude `.security_scan/`, which means a user who forgets to add this directory will commit it.

**Recommendation:** Add `.security_scan/` to `.gitignore` and emit a warning on first-run if it is not ignored.

### SEC-2 — Prompt file in `/tmp` may leak full source code to other users
**Severity: High**
**File:** `security_scan.py:239-251`

`call_pi()` creates a temporary file with `tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='pi_prompt_')` in the system temp directory. On shared machines, this file is world-readable because `NamedTemporaryFile` uses the system default permissions (typically `0o600` on some systems, `0o644` on others — behavior is platform-dependent). The file contains the full source code of the file being scanned, which may include proprietary algorithms, credentials, or intellectual property.

Even though the file is deleted in the `finally` block (line 254), the window between creation and deletion is non-zero (typically milliseconds, but longer on slow filesystems or under high load).

**Recommendation:** Create the file in a user-writable private directory (e.g., `state_dir / ".pi_tmp/"`) with `mode=0o600`, or use `tempfile.NamedTemporaryFile(delete=True, delete_in_thread=False)` and accept that the OS may clean it up. Alternatively, pass via stdin (`pi --input -`) if supported.

### SEC-3 — Allowlist file location and format has no validation
**Severity: Medium**
**File:** `security_scan.py:754-772`

The allowlist file (`.security_scan/allowlist.json`) is read with `json.load()` and validated minimally: if the file is missing, unreadable, or the top-level structure is not a dict, an empty list is returned. The `suppressions` array entries are not validated for expected fields. A malformed entry with unexpected field names is silently ignored by `suppression_match()`, but there is no warning about unrecognized fields, which could hide typos in suppression entries (e.g., a user types `"scaner"` instead of `"scanner"` and their suppression silently does nothing).

**Recommendation:** Add validation for expected fields (`scanner`, `file`, `line`, `reason`) and emit a warning for unrecognized fields.

### SEC-4 — No rate limiting on `pi` calls — denial of service via large repos
**Severity: Medium**
**File:** `security_scan.py:712-730` / `security_scan.py:1277-1312`

The `--concurrency` flag defaults to 4 and allows the user to set an arbitrary high number. For a repository with 100,000 files, each scanner could spawn up to `concurrency` threads, each calling `pi` (an external process with a 180s timeout). A large repo with high concurrency could spawn thousands of concurrent `pi` processes, consuming significant CPU and memory. There is no global rate limiter or semaphore across all scanners.

**Recommendation:** Document the risk and add a soft cap on concurrency or a per-timeout throughput limit.

### SEC-5 — Model output is treated as a JSON schema that the report embeds without sanitization
**Severity: Medium**
**File:** `security_scan.py:995-1020`

Findings extracted from the model are embedded directly into the markdown report without any sanitization. If the model's `explanation` or `fix` fields contain HTML, markdown, or other rich content, it could affect the report's rendering. For example, a finding with `explanation: "See [exploit](http://evil.com)"` would render as a clickable link in the markdown report. While this is a minor concern, it means the report output is influenced by the model's output in ways that could be used for social engineering or phishing.

**Recommendation:** Escape the `explanation`, `fix`, and `code` fields before embedding them in the report.

### SEC-6 — Binary detection heuristic is incomplete
**Severity: Low**
**File:** `security_scan.py:197-200`

The binary detection heuristic (line 197-200) checks the first 8 KB for a NUL byte to identify binary files. This is a common heuristic but has known false-positive and false-negative cases:
- False negatives: Binary files without NUL bytes in the first 8 KB (e.g., small binary files)
- False positives: Text files that happen to contain a NUL byte in the first 8 KB (e.g., files with embedded binary data, compressed data, or certain encoding issues)

**Recommendation:** Consider using Python's `mimetypes` module or the `python-magic` library for more accurate detection. However, for a zero-dependency tool, the heuristic is acceptable.

### SEC-7 — Session directory contents may leak model interaction history
**Severity: Medium**
**File:** `security_scan.py:257-267`

The `pi` invocation uses `--no-session` but the `session_dir` is passed via `--session-dir` (line 267). The `pi` tool may cache session data (conversation history, tokens, etc.) in this directory. If the `session_dir` is `.security_scan/sessions/`, this data is stored alongside the scan cache. On a shared machine, anyone with access to this directory can see the full conversation history, including the prompts and responses sent to the model.

**Recommendation:** Ensure the session directory is not committed to version control and warn users about its contents.

### SEC-8 — Allowlist `line` field accepts `None`, `0`, `""` as "match all lines"
**Severity: Low**
**File:** `security_scan.py:778-782`

```python
entry_line = entry.get("line")
if entry_line is None or entry_line == 0 or entry_line == "":
    return True
```

The allowlist entry `{"line": 0}` or `{"line": null}` suppresses findings on *all* lines of a file. While this is intentional (to allow suppressing an entire file), it is easy to accidentally trigger by omitting the `line` field or setting it to `0`. This could suppress hundreds or thousands of findings unintentionally.

**Recommendation:** Emit a warning when a file-level suppression is active, so users are aware they are silencing the entire file.

---

## Appendix: File Reference Index

| File | Lines Referenced |
|------|-----------------|
| `security_scan.py` | 130-132, 135, 142, 192-203, 197-200, 225-226, 236-267, 239, 376-380, 444-455, 446, 668-676, 694-700, 754-772, 773-781, 784-795, 778-782, 858-1150, 1187-1206, 1191, 1193, 1234-1688, 1235, 1253, 1240, 1277-1312, 1352-1358 |
| `test_security_scan.py` | 1-2793 (full coverage of all major code paths) |
| `README.md` | Comprehensive documentation (350+ lines) |
| `LICENSE` | Apache 2.0, unfilled placeholders |
| `.gitignore` | Standard Python template, no project-specific entries |
| `prompts/discovery.txt` | Repository structure analysis prompt |
| `prompts/verify_prompt.txt` | Full file content + findings sent to model |
| `prompts/b1_access_control.txt` | Broken Access Control scanner prompt |
| `prompts/b2_crypto.txt` | Cryptographic Failures scanner prompt |
| `prompts/b3_injection.txt` | Injection scanner prompt |
| `prompts/b4_insecure_design.txt` | Insecure Design scanner prompt |
| `prompts/b5_misconfiguration.txt` | Security Misconfiguration scanner prompt |
| `prompts/b6_vuln_components.txt` | Vulnerable Components scanner prompt |
| `prompts/b7_auth.txt` | Authentication Failures scanner prompt |
| `prompts/b8_data_integrity.txt` | Data Integrity Failures scanner prompt |
| `prompts/b9_logging.txt` | Logging Failures scanner prompt |
| `prompts/b10_ssrf.txt` | SSRF scanner prompt |

---

## Summary

| Category | Count |
|----------|-------|
| Critical | 1 |
| High | 3 |
| Medium | 9 |
| Low | 7 |

The scanner is a well-engineered, thoughtfully documented, zero-dependency tool that handles a difficult problem (reliably extracting JSON from LLM output) with impressive robustness. The six-layer JSON recovery strategy is particularly noteworthy. The primary structural concern is the monolithic architecture (~3100 lines in a single file with ~80% duplication between `build_report()` and `build_csv_report()`). The primary security concern is the plaintext storage of scanned file content in `.security_scan/` and the exposure of prompt files in `/tmp`. Both are correctable without code changes (adding `.security_scan/` to `.gitignore`, using a more secure temp directory).