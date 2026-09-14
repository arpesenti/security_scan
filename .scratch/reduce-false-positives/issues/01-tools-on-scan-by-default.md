# 01: Tools-on scan by default

**What to build:** Phase 2 (scan) runs with read-only tools out of the box, so the scanner can inspect callers, sanitizers, and auth middleware in related files instead of judging each file in isolation. Users opt out with an explicit no-tools flag. The README quick start reflects the new default. Results continue to live in the tools-mode cache layout so tools and no-tools results never mix, and per-file caching works unchanged across re-runs.

**Blocked by:** None (can start immediately).

**Status:** done

- [x] Running all scanners with no flag overrides produces scan results in the tools-mode results layout
- [x] The opt-out flag runs phase 2 without tools and reads/writes the no-tools results layout
- [x] Cached scan results are reused on a second run without re-calling the model (both modes)
- [x] README documents the new default and the opt-out
- [x] Report's "Scan tools" configuration line reflects the actual mode used

## Comments

- Implemented in `security_scan.py` (flipped `--scan-tools` default to on) and README quick start / tool table / CLI reference. Tests: `TestScanToolsDefaultCLI` (uses a fake `pi` shim on PATH so the CLI subprocess never calls the real model).
