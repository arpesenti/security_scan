# security_scan

OWASP Top 10 (2025) security scanner that uses [`pi -p`](https://github.com/badlogic/pi-mono) as a
vulnerability analyst. Runs a two-phase pipeline: a discovery pass that classifies which file
extensions in the repo matter for each OWASP category, then per-category scans that send each
relevant file to the model for review.

## Features

- All 10 OWASP 2025 categories (B1–B10) out of the box
- Discovery phase that narrows the scan to extensions actually present in your repo
- Per-file result caching (`.security_scan/`) that auto-invalidates on file content or prompt
  changes — so a re-run after editing code or a prompt template picks up the new state
- Concurrent scans (`--concurrency`)
- Dry-run mode (`--dry-run`) for previewing which files would be scanned
- Override the per-scanner extension list (`--formats`)
- Pluggable prompt templates (`prompts/`) — both per-scanner (`b*_*.txt`) and the discovery
  prompt (`discovery.txt`)
- False-positive allowlist (`.security_scan/allowlist.json`) with audit trail in the report
- CI-friendly: `--fail-on <severity>` produces non-zero exits on findings or scan errors
- Configurable per-file and discovery timeouts
- Markdown report (`security_report.md`) with severity buckets, OWASP heatmap, and per-file findings

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

# Preview which files WOULD be scanned, without calling the model
./security_scan.py --all --dry-run

# Re-run only the discovery phase
./security_scan.py --phase 1 --redetect

# Re-scan every file even if a cached result exists
./security_scan.py --scanner B3 --rescan

# Limit each scanner to N files (useful for sampling)
./security_scan.py --scanner B3 --max-files 10

# CI usage: fail the build on any High or Critical finding
./security_scan.py --all --fail-on high

# Raise the per-file timeout for slow networks
./security_scan.py --all --scan-timeout 600
```

## Two-phase workflow

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

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | — | Run every scanner (B1–B10). |
| `--scanner IDS` | — | Comma-separated OWASP IDs, e.g. `B1,B3,B7`. Mutually exclusive with `--all`. |
| `--phase N` | `0` | `1` = discovery only, `2` = scan only (uses cached discovery), `0` = both. |
| `--concurrency N` | `4` | Max parallel `pi` calls. |
| `--max-files N` | `0` (no limit) | Cap files per scanner (truncated after the cached filter is applied). |
| `--output PATH` | `./security_report.md` | Report output path. |
| `--state-dir DIR` | `./.security_scan` | Where discovery cache, per-scanner result JSONs, `allowlist.json`, and `pi` session files live. |
| `--dry-run` | — | Print the file list for each scanner; do not call `pi` or write reports. |
| `--rescan` | — | Ignore cached results and re-scan every matching file. |
| `--redetect` | — | Re-run phase 1 even if `discovery.json` is present. |
| `--formats LIST` | — | Comma-separated extension override applied to every selected scanner (e.g. `.sql,.sh`). Takes precedence over discovery and `base_ext`. |
| `--scan-timeout N` | `180` | Per-file `pi` call timeout in seconds. |
| `--discovery-timeout N` | `240` | Discovery `pi` call timeout in seconds. |
| `--fail-on LEVEL` | `never` | Exit non-zero if any finding is at or above `LEVEL` (one of `low`, `medium`, `high`, `critical`). |

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

Two kinds of prompts live in the `prompts/` directory:

- **Scanner prompts** — `prompts/bN_<name>.txt`, one per OWASP category. Two placeholders
  are substituted at scan time:
  - `{filename}` — the basename of the file under review
  - `{file_content}` — the full text of the file
- **Discovery prompt** — `prompts/discovery.txt`. Has one placeholder:
  - `{repo_structure}` — the rendered repo tree (extension counts, notable files, top-level
    directory layout) built by `build_repo_structure()`

The model is expected to reply to scanner prompts with either an empty JSON array `[]` or one
entry per finding in this shape:

```json
[{"line": 123, "code": "...", "severity": "High", "explanation": "...", "fix": "..."}]
```

To change a scanner's wording:

1. Edit the matching `prompts/bN_*.txt` file. Keep the `{filename}` and `{file_content}`
   placeholders intact.
2. The cache is keyed on the prompt's hash, so the next run will automatically re-scan
   every file with the new prompt. No need to clear `.security_scan/` or pass `--rescan`.

If a prompt file is missing, `scan_file` falls back to a generic template that still works but
is less specific than the per-category prompts.

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

`security_report.md` is generated at the end of phase 2 and contains:

- A header with the timestamp, repo path, and selected scanners
- One section per scanner with: extensions scanned, file/vulnerability counts, severity
  breakdown, suppressed count, and a list of vulnerable files
- A `<details>` block with the full per-file findings (line number, code snippet, why, fix)
- A **Suppressed Findings** section (collapsed) listing allowlist hits with their reasons
- A **Global Summary** table and an OWASP risk heatmap
- An **Overall Risk** line that is `INCONCLUSIVE` when there were zero findings but errors or
  timeouts occurred (so a green report after a flaky run is not mistaken for a clean repo)

If all scans errored out, the report will say so explicitly. Check the per-scanner
`[ERROR]`/`[TIMEOUT]` rows for the affected files.

## Exit codes (for CI)

```text
exit 0  Clean run (no findings at or above --fail-on threshold, no scan errors)
exit 1  At least one finding is at or above --fail-on threshold
exit 2  Scan completed but at least one file errored/timed out (no signal from it)
```

Default is `--fail-on never` (always exit 0). For CI gating, set a threshold:

```bash
./security_scan.py --scanner B1,B3,B7 --fail-on high
```

Inconclusive runs (exit 2) are distinct from clean runs (exit 0) so a flaky pipeline can't
silently pass. Combine the two flags in CI scripts:

```bash
./security_scan.py --all --fail-on high || { echo "security check failed"; exit 1; }
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
- **Tests** — `python3 -m unittest test_security_scan.py` runs the 50+ unit tests covering
  the non-pi behavior (cache key derivation, exclusion logic, JSON extraction, allowlist
  matching, scan_file with mocked `pi`, CLI exit codes). No third-party dependencies required.
