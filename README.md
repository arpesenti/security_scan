# security_scan

OWASP Top 10 (2025) security scanner that uses [`pi -p`](https://github.com/badlogic/pi-mono) as a
vulnerability analyst. Runs a three-phase pipeline: a discovery pass that classifies which file
extensions in the repo matter for each OWASP category, per-category scans that send each
relevant file to the model for review, and an optional verification pass that asks the model
to rate each finding's confidence and exploitability in the context of the file as written.

## Features

- All 10 OWASP 2025 categories (B1–B10) out of the box
- Discovery phase that narrows the scan to extensions actually present in your repo
- Per-file result caching (`.security_scan/`) that auto-invalidates on file content or prompt
  changes — so a re-run after editing code or a prompt template picks up the new state
- Optional **phase-3 verification** (`--verify`) that overlays a confidence + exploitability
  verdict on every finding, with `--fail-on-confidence` to gate CI on trusted findings only
- Per-phase **read-only tool support** (`--discovery-tools` / `--scan-tools` / `--verify-tools`)
  so the model can inspect related files (callers, sanitizers, auth middleware) when
  making judgments
- Concurrent scans (`--concurrency`)
- Dry-run mode (`--dry-run`) for previewing which files would be scanned
- Override the per-scanner extension list (`--formats`)
- Pluggable prompt templates (`prompts/`) — per-scanner (`b*_*.txt`), the discovery prompt
  (`discovery.txt`), and the verifier prompt (`verify_prompt.txt`)
- False-positive allowlist (`.security_scan/allowlist.json`) with audit trail in the report
- CI-friendly: `--fail-on <severity>` and `--fail-on-confidence <level>` produce non-zero exits
- Configurable per-file, discovery, and verify timeouts
- Markdown report (`security_report.md`) with severity buckets, OWASP heatmap, per-file
  findings, verifier annotations, and a "Needs Review" bucket
- Optional **spreadsheet-friendly reports** (`--report-format csv` or `tsv`) with one row
  per finding for pivot-table / filter workflows

## Requirements

- Python 3.10+ (uses `X | None` union syntax)
- `pi` on `PATH` and authenticated (the scanner shells out to `pi --print --no-tools --no-session --mode text`)

## Installation

Drop `security_scan.py` and the `prompts/` directory somewhere, then:

```bash
chmod +x security_scan.py
./security_scan.py --help
```

There are no Python dependencies to install.

## Quick start

```bash
# Run all 10 scanners end-to-end (discovery + scan + report)
./security_scan.py --all

# Run a single scanner
./security_scan.py --scanner B3

# Run several scanners
./security_scan.py --scanner B1,B3,B7

# Add the phase-3 verification pass + gate CI on High-confidence findings
./security_scan.py --all --verify --fail-on-confidence high

# Spreadsheet-friendly report (one row per finding, opens in Excel/Sheets)
./security_scan.py --all --report-format csv --output findings.csv

# Disable tools for verify (use the original file-as-written verifier)
./security_scan.py --all --verify --no-verify-tools

# Enable tools for scan too (slower, more powerful, opt-in)
./security_scan.py --all --scan-tools --no-verify-tools

# Preview which files WOULD be scanned, without calling the model
./security_scan.py --all --dry-run

# Re-run only the discovery phase
./security_scan.py --phase 1 --redetect

# Re-scan every file even if a cached result exists
./security_scan.py --scanner B3 --rescan

# Re-run only the verification pass (after editing code or the verify prompt)
./security_scan.py --all --verify --reverify

# Limit each scanner to N files (useful for sampling)
./security_scan.py --scanner B3 --max-files 10

# CI usage: fail the build on any High or Critical finding
./security_scan.py --all --fail-on high

# Raise the per-file timeout for slow networks
./security_scan.py --all --scan-timeout 600
```

## Three-phase workflow

### Phase 1 — Discovery

A single call to `pi` that gets a high-level view of the repo (extension counts, notable build
files, top-level directory tree) and decides which extensions are relevant for each OWASP
category in *this* codebase. The result is cached in `.security_scan/discovery.json`.

- Re-runs only on `--redetect` or when the cache is missing/corrupt.
- The output is unioned with `base_ext` from the scanner registry, so a category never loses its
  default extensions even if the model omits them.
- The prompt lives at `prompts/discovery.txt` and is editable; if missing, a built-in default
  is used.

### Phase 2 — Scan

For each selected scanner, every file whose extension matches the discovery result (plus any
`base_names` for B6) is sent to `pi` with the category's prompt template. Results are written
as one JSON file per (scanner, file) under `.security_scan/<scanner>/results/`.

- A file is **only re-scanned if its content hash or the prompt template has changed** since
  the cached result. See [Cache invalidation](#cache-invalidation) below.
- `--rescan` forces a re-scan of every matching file.
- Concurrency is bounded by `--concurrency` (default `4`).
- Per-file pi call timeout is `--scan-timeout` (default `180s`); discovery uses
  `--discovery-timeout` (default `240s`).
- On any error or timeout, the failure is cached as `{"status": "error" | "timeout", "result": ...}`
  so a later report can show the breakdown.

### Phase 3 — Verification (optional)

When `--verify` is set, every file that produced at least one finding in phase 2 is sent to
`pi` again with a single shared prompt template (`prompts/verify_prompt.txt`). The model is
asked to look at the file as a whole and rate each finding's **confidence** (`High` / `Medium` /
`Low`) and **exploitability** (`yes` / `no` / `conditional`), plus a one-line justification.
The verifier is essentially a sanity check on the phase-2 scanner's output — the kinds of
issues that trip a false positive are listed in the prompt: dead code, sanitization upstream
in the same file, defense-in-depth wrappers, hardcoded constants mistaken for user input,
functions only called from tests, etc.

The verdict is overlaid onto the report:

- Each finding shows a `Verification: ✅ High confidence, exploitable: yes — …` line under its
  existing `Why` / `Fix` block.
- The **Vulnerable Files** table grows a per-confidence breakdown (High / Medium / Low /
  Unverified).
- The **Global Summary** gains a verification-coverage row.
- The **Risk Heatmap** and **Overall Risk** line switch to *gated* counts (only findings at
  or above the `--fail-on-confidence` level) when a threshold is set.
- A new **Needs Review** section lists every finding below the gate with its verifier's
  reason, so a human can triage it (and promote confirmed false positives to the allowlist).

Results are cached as one JSON file per (scanner, file) under
`.security_scan/<scanner>/verifications/`, keyed on the file's content hash, the findings
list's signature, and the verify-prompt hash. A re-scan that changes the findings, an edit to
the file, or an edit to `verify_prompt.txt` all auto-invalidate the cache; `--reverify`
forces a re-run.

`--verify` composes with `--phase 3` (verify only) and `--reverify` (force re-run).

### Codebase context via `AGENTS.md` / `CLAUDE.md`

The scanner does **not** need a separate context file mechanism. Pi auto-loads
`AGENTS.md` and `CLAUDE.md` at startup, walking up from the current working
directory, and includes their content in front of the model on every
`pi --print` call. Drop one in the scanned repo's root (or in a parent
directory) and the model sees it for every scan and verify call.

```markdown
# In <repo>/AGENTS.md

# Codebase conventions for the security scanner

- All SQL goes through `db.QueryBuilder`; it's parameterized. Do not flag
  QueryBuilder usage as SQLi.
- Auth is enforced by `middleware/auth.AuthMiddleware`, which runs before
  every handler. Handlers that don't check auth directly are not a finding.
- `utils.safe_html()` escapes all output. Templates use it for every
  variable interpolation.
```

Disable with `--no-context-files` (passes the flag through to pi) if a
project's `AGENTS.md` would mislead the scanner. The flag is per-call and
doesn't affect `pi`'s own settings.

## Per-phase tool support

Each of the three phases can be run with or without tools. The tool list is
hardcoded to the read-only set `read,grep,find,ls` — the same pattern from
`pi`'s own docs for a read-only review. The model can inspect the repo but
cannot execute, edit, write, or fetch.

| Phase | Default | CLI flag | Why / why not |
|-------|---------|----------|----------------|
| Discovery | **on** | `--discovery-tools` / `--no-discovery-tools` | Tools let the model read `package.json`, browse the tree, and check framework-specific files before deciding which extensions matter per OWASP category. Cheap (one call per run) and the input is the repo structure, not untrusted code. |
| Scan | **off** | `--scan-tools` / `--no-scan-tools` | Scan is high-recall single-file pattern matching. Tools add cost (5-10× per file) and a prompt-injection surface on every file read. Off by default; opt in for high-stakes scans. |
| Verify | **on** | `--verify-tools` / `--no-verify-tools` | The whole reason verify exists is to do cross-file judgment — is this input sanitized upstream, is this function only called from tests, does the auth middleware already cover this route. With tools, the model can actually look. Off disables for the original file-as-written verifier. |

Cache is split per phase × tools mode so toggling flags never invalidates
the other mode's cache:

| Phase | No tools | Tools |
|-------|----------|-------|
| Discovery | `.security_scan/discovery.json` | `.security_scan/discovery-tools.json` |
| Scan | `.security_scan/<scanner>/results/` | `.security_scan/<scanner>/results-tools/` |
| Verify | `.security_scan/<scanner>/verifications/` | `.security_scan/<scanner>/verifications-tools/` |

The markdown report's header shows the resolved mode for each phase (e.g.
`Tools: discovery=read-only · scan=none · verify=read-only`), and each
per-scanner section gets a `Verify tools` row when verify is in tools mode.

**Trade-off**: tools mode is slower (multiple round-trips per call), more
expensive (5-10× the tokens), and **less deterministic** — the model might
read different files on different runs, so a re-run can produce a different
verdict. CI that gates on `--fail-on-confidence high` should keep the
default (verify tools on) but accept that the verdict is a probabilistic
signal, not a proof. For pure determinism, pass `--no-verify-tools`.

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | — | Run every scanner (B1–B10). |
| `--scanner IDS` | — | Comma-separated OWASP IDs, e.g. `B1,B3,B7`. Mutually exclusive with `--all`. |
| `--phase N` | `0` | `1` = discovery only, `2` = scan only (uses cached discovery), `3` = verify only (uses cached scan), `0` = all selected phases. |
| `--concurrency N` | `4` | Max parallel `pi` calls. |
| `--max-files N` | `0` (no limit) | Cap files per scanner (truncated after the cached filter is applied). |
| `--output PATH` | `./security_report.md` | Report output path. |
| `--state-dir DIR` | `./.security_scan` | Where discovery cache, per-scanner result JSONs, verifications, `allowlist.json`, and `pi` session files live. |
| `--dry-run` | — | Print the file list for each scanner; do not call `pi` or write reports. |
| `--rescan` | — | Ignore cached results and re-scan every matching file. |
| `--redetect` | — | Re-run phase 1 even if `discovery.json` is present. |
| `--verify` | — | Run phase 3 (verify every file with findings) after phase 2. |
| `--reverify` | — | Force re-verification of all findings, ignoring the verify cache. |
| `--verify-timeout N` | `180` | Per-file verify `pi` call timeout in seconds. |
| `--formats LIST` | — | Comma-separated extension override applied to every selected scanner (e.g. `.sql,.sh`). Takes precedence over discovery and `base_ext`. |
| `--scan-timeout N` | `180` | Per-file `pi` call timeout in seconds. |
| `--discovery-timeout N` | `240` | Discovery `pi` call timeout in seconds. |
| `--fail-on LEVEL` | `never` | Exit non-zero if any finding is at or above `LEVEL` (one of `low`, `medium`, `high`, `critical`). Independent of `--fail-on-confidence`. |
| `--fail-on-confidence LEVEL` | `never` | Exit non-zero if any finding whose verifier confidence is at or above `LEVEL` is present (one of `low`, `medium`, `high`). Unverified findings are treated as below any threshold. |
| `--report-format FMT` | `md` | Output format: `md` (human-readable markdown, default), `csv` or `tsv` (one row per finding, for spreadsheet import). The file extension on `--output` is auto-adjusted to match. |
| `--discovery-tools` / `--no-discovery-tools` | on | Give phase 1 (discovery) read-only tools (`read`,`grep`,`find`,`ls`). The model can browse the repo before deciding which extensions matter. |
| `--scan-tools` / `--no-scan-tools` | off | Give phase 2 (scan) read-only tools. Off by default — scan is high-recall single-file; tools add cost and prompt-injection surface. |
| `--verify-tools` / `--no-verify-tools` | on | Give phase 3 (verify) read-only tools. The model can read related files (callers, sanitizers, auth middleware) before rating each finding's confidence. |

## Cache invalidation

Each cached result is keyed on `scanner + relative path + content hash + prompt hash`. A
re-scan is only triggered when **any** of those change:

- The file's content has changed since the last scan (new vuln won't be missed)
- The prompt template (`prompts/bN_*.txt`) was edited (stricter checks take effect immediately)
- You changed the `--formats` override or the scanner's `base_ext` (a new key dimension)

`--rescan` bypasses this and re-scans every matching file. The discovery prompt
(`prompts/discovery.txt`) and the scanner prompts are hashed independently, so editing one
does not invalidate the other's cache.

Old cache files from previous versions of this script (before content/prompt hashing) are
left in place but ignored. Delete `.security_scan/` to start fresh.

## Customizing prompts

Three kinds of prompts live in the `prompts/` directory:

- **Scanner prompts** — `prompts/bN_<name>.txt`, one per OWASP category. Two placeholders
  are substituted at scan time:
  - `{filename}` — the basename of the file under review
  - `{file_content}` — the full text of the file
- **Discovery prompt** — `prompts/discovery.txt`. Has one placeholder:
  - `{repo_structure}` — the rendered repo tree (extension counts, notable files, top-level
    directory layout) built by `build_repo_structure()`
- **Verify prompt** — `prompts/verify_prompt.txt`. Shared across all scanners; used by
  phase 3. Has three placeholders:
  - `{filename}` — the basename of the file under review
  - `{file_content}` — the full text of the file
  - `{findings_json}` — the JSON array of phase-2 findings to verify

The model is expected to reply to scanner prompts with either an empty JSON array `[]` or one
entry per finding in this shape:

```json
[{"line": 123, "code": "...", "severity": "High", "explanation": "...", "fix": "..."}]
```

The verify prompt expects an array (one entry per input finding) in this shape:

```json
[{"line": 123, "confidence": "High", "exploitable": "yes", "verification_reason": "..."}]
```

To change a scanner's wording:

1. Edit the matching `prompts/bN_*.txt` file. Keep the `{filename}` and `{file_content}`
   placeholders intact.
2. The cache is keyed on the prompt's hash, so the next run will automatically re-scan
   every file with the new prompt. No need to clear `.security_scan/` or pass `--rescan`.

To change how verification judges findings, edit `prompts/verify_prompt.txt`. The next
`--verify` run will pick up the new wording; pass `--reverify` to force a re-run on existing
files.

If a prompt file is missing, the corresponding phase falls back to a generic built-in template
that still works but is less specific than the on-disk one.

## False-positive allowlist

Model output is not always right — you'll get occasional false positives that you don't want
showing up in every report. Add them to `.security_scan/allowlist.json`:

```json
{
  "version": 1,
  "suppressions": [
    {
      "scanner": "B3",
      "file": "src/db.py",
      "line": 42,
      "reason": "The query is built from a static allowlist, not user input"
    },
    {
      "scanner": "B5",
      "file": "config/dev.json",
      "line": 0,
      "reason": "Dev-only configuration; not deployed"
    },
    {
      "scanner": "*",
      "file": "tests/**",
      "line": 0,
      "reason": "Test fixtures intentionally use unsafe patterns"
    }
  ]
}
```

Match semantics (first matching entry wins):

- `scanner` — OWASP ID (`"B3"`) or `"*"` for any
- `file` — exact relative path or `"*"` for any
- `line` — line number; `0`/`null`/missing matches the whole file

Suppressed findings are **excluded from severity counts and from the Overall Risk calculation**,
but they remain visible in a collapsed **Suppressed Findings** section at the bottom of the
report (with your `reason`) so you can audit them later. To unsuppress a finding, remove its
entry from the allowlist and re-run.

## Output report

`security_report.md` is generated at the end of phase 2 (or phase 3 when `--verify` is used)
and contains:

- A header with the timestamp, repo path, selected scanners, and (when applicable) a note
  that phase-3 verification verdicts are included and a confidence gate is in effect
- One section per scanner with: extensions scanned, file/vulnerability counts, severity
  breakdown, suppressed count, clean count, errors, and — when verification ran — a
  per-confidence breakdown (High / Medium / Low / Unverified) plus a needs-review count
- A `<details>` block with the full per-file findings (line number, code snippet, why, fix,
  and verifier annotation)
- A **Suppressed Findings** section (collapsed) listing allowlist hits with their reasons
- A **Global Summary** table and an OWASP risk heatmap
- An **Overall Risk** line that is `INCONCLUSIVE` when there were zero findings but errors or
  timeouts occurred (so a green report after a flaky run is not mistaken for a clean repo)
- A **Needs Review** section (only when verification produced below-threshold findings) that
  lists each gated-out finding with its verifier's confidence, exploitability verdict, and
  one-line reason

If all scans errored out, the report will say so explicitly. Check the per-scanner
`[ERROR]`/`[TIMEOUT]` rows for the affected files.

## Spreadsheet-friendly reports

For pivot-table / filter workflows, pass `--report-format csv` (or `tsv`):

```bash
./security_scan.py --all --verify --report-format csv --output findings.csv
```

The output is a flat file with **one row per finding**. All the same overlays
apply — allowlist, phase-3 verification, `--fail-on`, `--fail-on-confidence` —
so the CSV never disagrees with the markdown about which findings are real.

Columns (in order):

| Column | Description |
|--------|-------------|
| `scanner` | OWASP ID (e.g. `B3`) |
| `scanner_label` | Human-readable name (e.g. `Injection`) |
| `file` | Relative path from the repo root |
| `line` | Line number (blank when not applicable) |
| `severity` | `Critical` / `High` / `Medium` / `Low` |
| `code` | The vulnerable code snippet from phase 2 |
| `explanation` | Phase 2's why |
| `fix` | Phase 2's suggested fix |
| `confidence` | Verifier verdict (`High` / `Medium` / `Low`), blank when no verification has run |
| `exploitable` | Verifier verdict (`yes` / `no` / `conditional`), blank when no verification has run |
| `verification_reason` | Verifier's one-line justification |
| `status` | `active` (above any confidence gate), `needs_review` (below gate), `suppressed` (allowlist hit), `error` / `timeout` (per-file scan failure) |
| `suppression_reason` | Free-text reason from the allowlist entry (suppressed rows only) |

Typical filter recipes once the file is in a spreadsheet:

- "Show me only things I need to act on" → filter `status` to `active` or `error`
- "What did the verifier downgrade?" → filter `status` to `needs_review` and sort by `severity`
- "What did we explicitly silence?" → filter `status` to `suppressed`
- "Pivot findings by scanner" → rows = `scanner`, values = count of `status = active`

`--output` is the path *stem* — the extension is auto-adjusted to `.csv` or
`.tsv` so `--output report --report-format csv` writes `report.csv`. To get
both formats, run twice with different `--output` paths.

## Exit codes (for CI)

```text
exit 0  Clean run (no findings at or above --fail-on or --fail-on-confidence threshold, no scan errors)
exit 1  At least one finding trips --fail-on or --fail-on-confidence
exit 2  Scan completed but at least one file errored/timed out (no signal from it)
```

Default is `--fail-on never` (always exit 0). For raw severity gating:

```bash
./security_scan.py --scanner B1,B3,B7 --fail-on high
```

For confidence-gated gating (only count findings the verifier trusts):

```bash
./security_scan.py --scanner B1,B3,B7 --verify --fail-on-confidence high
```

`--fail-on` and `--fail-on-confidence` are independent — both can be set in the same run,
and either gate that trips exits 1. Unverified findings are treated as below any
`--fail-on-confidence` threshold, so running `--fail-on-confidence` without `--verify` is a
no-op for the gate (no finding will have a confidence to compare).

Inconclusive runs (exit 2) are distinct from clean runs (exit 0) so a flaky pipeline can't
silently pass. Combine the two flags in CI scripts:

```bash
./security_scan.py --all --verify --fail-on high --fail-on-confidence high \
  || { echo "security check failed"; exit 1; }
```

## Excludes

Out of the box the walker skips:

- **Directories**: `.git`, `.svn`, `.idea`, `.vscode`, `node_modules`, `vendor`, `build`,
  `dist`, `.venv`, `__pycache__`, `.security_scan`, `ThirdParty/wheelhouse`, `Source/Regression`
  (and everything beneath them)
- **Files**: `security_scan.py`, `security_report.md`, `sqli_scan.py`, `sqli_report.md`
- **Binary extensions** (`.png`, `.jar`, `.class`, `.dylib`, `.whl`, …) and any file whose
  first 8 KB contains a NUL byte

To change the lists, edit the `EXCLUDE_DIRS`, `EXCLUDE_FILES`, and `BINARY_EXTS` sets at the
top of `security_scan.py`.

## Adding a new scanner

1. Add an entry to the `OWASP_SCANNERS` dict in `security_scan.py` (give it an ID, name, label,
   `base_ext`, and `prompt_file`).
2. Add the matching `prompts/<id>_<name>.txt` file.
3. (Optional) If the scanner is name-based rather than extension-based (like B6), set
   `base_names` in the registry entry.
4. Run with `--scanner <new-id> --redetect` to exercise the full pipeline.

## Troubleshooting

- **`pi command not found`** — install `pi` and make sure it is on `$PATH`.
- **All results are `[ERROR]`** — usually a prompt template typo. Check the per-file JSON in
  `.security_scan/<scanner>/results/`; a malformed template surfaces as
  `{"error": "prompt_format_failed: ..."}`.
- **Stale findings after editing a prompt** — should not happen; the cache is keyed on the
  prompt's hash. If it does, run with `--rescan` to force a re-scan.
- **The report says `INCONCLUSIVE`** — at least one file failed or timed out. See the per-scanner
  error rows and the global error/timeouts count.
- **A scan file disappears from the report** — corrupt cache JSON. The scanner logs a warning
  and skips the bad file rather than aborting the report.
- **CI is failing with exit 2** — at least one file errored during scanning. Look at the
  per-file cache JSONs (`status: "error"` or `status: "timeout"`). It is *not* a finding, so
  the allowlist will not help; fix the underlying scan failure (usually a pi timeout —
  raise `--scan-timeout`).
- **`--fail-on-confidence` never trips** — every finding is being treated as unverified. You
  need to run with `--verify` (or have run it in a prior run) so the verifier verdicts are
  cached under `.security_scan/<scanner>/verifications/`.
- **Stale verdicts after editing `verify_prompt.txt`** — should not happen; the verify cache
  key includes the prompt hash. If it does, run with `--reverify` to force a re-verify.
- **Tests** — `python3 -m unittest test_security_scan.py` runs the unit tests covering
  the non-pi behavior (cache key derivation, exclusion logic, JSON extraction, allowlist
  matching, scan_file + verify_finding with mocked `pi`, confidence gating, CLI exit codes).
  No third-party dependencies required.
