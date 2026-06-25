#!/usr/bin/env python3
"""
security_scan.py — OWASP Top 10 security scanner using `pi -p`.

Two-phase approach:
  Phase 1 (Discovery):  Ask the agent to classify which extensions/file groups
                         in THIS repo are relevant for each OWASP category.
  Phase 2 (Scan):       Run per-scanner vulnerability analysis using the
                         discovered file→vulnerability mapping.

Usage:
    python3 security_scan.py --all               Run all OWASP scanners
    python3 security_scan.py --scanner B3        Run injection scanner only
    python3 security_scan.py --scanner B1,B3,B7  Run specific scanners
    python3 security_scan.py --phase 1           Discovery only
    python3 security_scan.py --phase 2           Scan only (needs cached discovery)

Options:
    --concurrency N   Max parallel scans (default: 4)
    --max-files N     Limit files per scanner (default: all)
    --output FILE     Report output path (default: security_report.md)
    --state-dir DIR   Directory for cached results (default: .security_scan)
    --dry-run         List files without scanning
    --rescan          Re-scan all files even if cached
    --redetect        Re-run discovery phase even if cached
    --formats         Comma-separated extensions override (per-scanner base)
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── OWASP Top 10 (2025) Scanner Registry ───────────────────────────────────

# Each scanner defines:
#   id           — OWASP 2025 identifier (B1..B10)
#   name         — short name (used in state dirs, CLI --scanner)
#   label        — display name in reports
#   base_ext     — "obvious" extensions for this category (fallback)
#   prompt_file  — path to prompt template relative to this script

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

OWASP_SCANNERS = {
    "B1": {
        "id": "B1",
        "name": "access_control",
        "label": "Broken Access Control",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".rb", ".go", ".kt"],
        "prompt_file": "b1_access_control.txt",
    },
    "B2": {
        "id": "B2",
        "name": "crypto",
        "label": "Cryptographic Failures",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".go", ".kt", ".c", ".xml", ".properties"],
        "prompt_file": "b2_crypto.txt",
    },
    "B3": {
        "id": "B3",
        "name": "injection",
        "label": "Injection",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".sql", ".rb", ".go", ".kt", ".sh", ".xml", ".properties"],
        "prompt_file": "b3_injection.txt",
    },
    "B4": {
        "id": "B4",
        "name": "insecure_design",
        "label": "Insecure Design",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".go", ".kt", ".rb"],
        "prompt_file": "b4_insecure_design.txt",
    },
    "B5": {
        "id": "B5",
        "name": "misconfiguration",
        "label": "Security Misconfiguration",
        "base_ext": [".yml", ".yaml", ".json", ".xml", ".env", ".properties", ".ini", ".conf", ".plist", ".gradle"],
        "prompt_file": "b5_misconfiguration.txt",
    },
    "B6": {
        "id": "B6",
        "name": "vuln_components",
        "label": "Vulnerable and Outdated Components",
        "base_ext": [".gradle", ".xml", ".json"],  # pom.xml, build.gradle, package.json
        "base_names": ["pom.xml", "build.gradle", "settings.gradle", "package.json", "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "requirements.txt", "Podfile", "Podfile.lock", "Cargo.toml", "Cargo.lock", "composer.json"],
        "prompt_file": "b6_vuln_components.txt",
    },
    "B7": {
        "id": "B7",
        "name": "auth",
        "label": "Identification and Authentication Failures",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".rb", ".go", ".kt", ".properties"],
        "prompt_file": "b7_auth.txt",
    },
    "B8": {
        "id": "B8",
        "name": "data_integrity",
        "label": "Software and Data Integrity Failures",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".go", ".kt", ".c", ".xml"],
        "prompt_file": "b8_data_integrity.txt",
    },
    "B9": {
        "id": "B9",
        "name": "logging",
        "label": "Security Logging and Monitoring Failures",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".go", ".kt", ".c", ".properties", ".xml", ".conf"],
        "prompt_file": "b9_logging.txt",
    },
    "B10": {
        "id": "B10",
        "name": "ssrf",
        "label": "Server-Side Request Forgery",
        "base_ext": [".java", ".py", ".m", ".h", ".js", ".ts", ".go", ".kt", ".rb", ".properties"],
        "prompt_file": "b10_ssrf.txt",
    },
}

ALL_IDS = sorted(OWASP_SCANNERS.keys(), key=lambda x: int(x[1:]))

# ── Global exclude lists ────────────────────────────────────────────────────

EXCLUDE_DIRS = {
    ".security_scan", ".git", ".svn", "node_modules", "vendor", "build", "dist",
    ".venv", "__pycache__", ".idea", ".vscode", "ThirdParty/wheelhouse",
    "Source/Regression",
}
EXCLUDE_FILES = {"security_scan.py", "security_report.md", "sqli_scan.py", "sqli_report.md"}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".bin", ".gz", ".wav", ".class", ".jar", ".whl",
    ".dylib", ".so", ".a", ".o", ".framework", ".dmg", ".app",
    ".cvsignore", ".super",
}

# ── Helpers ─────────────────────────────────────────────────────────────────


def find_all_files(root: Path) -> tuple[list[Path], dict[str, list[Path]]]:
    """
    Walk the repo and collect:
      - all non-binary files
      - files grouped by extension
      - files grouped by well-known names
    Returns (all_files, ext_map).
    """
    all_files = []
    ext_map: dict[str, list[Path]] = {}
    name_map: dict[str, list[Path]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded dirs — match by directory name or relative path
        rel_dir = str(Path(dirpath).relative_to(root))
        pruned = []
        for d in dirnames:
            if d in EXCLUDE_DIRS:
                continue
            rel = f"{rel_dir}/{d}" if rel_dir != "." else d
            if any(rel.endswith(excl.lstrip(".")) or rel == excl for excl in EXCLUDE_DIRS):
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for fname in filenames:
            if fname in EXCLUDE_FILES:
                continue
            filepath = Path(dirpath) / fname
            ext = filepath.suffix.lower()

            if ext in BINARY_EXTS:
                continue

            # Check if file is likely binary
            try:
                filepath.read_bytes()[:8192]
            except Exception:
                continue

            all_files.append(filepath)
            ext_map.setdefault(ext, []).append(filepath)
            name_map.setdefault(fname, []).append(filepath)

    return all_files, ext_map, name_map


def file_key(rel_path: str, scanner_name: str) -> str:
    """Cache key = scanner_name + file path."""
    return hashlib.md5(f"{scanner_name}:{rel_path}".encode()).hexdigest()


def ext_key(ext: str, scanner_name: str) -> str:
    return hashlib.md5(f"ext:{scanner_name}:{ext}".encode()).hexdigest()


def extract_json_array(raw_text: str) -> object:
    """Best-effort extraction of a JSON array from model output text."""
    text = raw_text.strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    match = re.search(r"\[[\s\S]*\]", text)
    if match:
        try:
            return json.loads(match.group())
        except (json.JSONDecodeError, ValueError):
            pass

    if "NO_VULNERABILITIES" in text.upper() or "NO VULNERABILITIES" in text.upper():
        return []

    return {"error": "could not parse JSON from response", "raw_preview": text[:2000]}


def extract_json_object(raw_text: str) -> object:
    """Best-effort extraction of a JSON object from model output text."""
    text = raw_text.strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try to find {...} in the text
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group())
        except (json.JSONDecodeError, ValueError):
            pass

    return {"error": "could not parse JSON from response", "raw_preview": text[:2000]}


def call_pi(prompt: str, session_dir: Path, timeout: int = 180) -> tuple[str, str]:
    """
    Call `pi -p` with the given prompt.
    Uses @file syntax to avoid ARG_MAX limits on large prompts.
    Returns (status, raw_output).
    """
    # Write prompt to temp file to avoid argument length limits
    tmp_fd = None
    tmp_path = None
    try:
        tmp_fd = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='pi_prompt_')
        tmp_path = tmp_fd.name
        tmp_fd.write(prompt)
        tmp_fd.close()

        proc = subprocess.run(
            ["pi", "--print", "--no-tools", "--no-session", "--mode", "text",
             "--session-dir", str(session_dir), f"@{tmp_path}"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "timeout", "pi call timed out"
    except FileNotFoundError:
        return "error", "pi command not found"
    except Exception as e:
        return "error", str(e)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if proc.returncode != 0:
        return "error", f"exit_code_{proc.returncode}: {proc.stderr.strip()[:500]}"

    return "ok", raw


# ── Phase 1: Discovery ──────────────────────────────────────────────────────

DISCOVERY_PROMPT = """\
Analyze this repository structure and classify which file types are relevant
for each OWASP Top 10 (2025) vulnerability category.

Repository structure:
{repo_structure}

For each OWASP category, determine which extensions and file groups could
contain relevant security concerns. Consider:
- SQL injection can be in .sql, .java, .py, .m, .properties, .xml, .html
- XSS can be in .html, .js, .jsp, .java, .xml, .properties (template strings)
- Crypto issues can be in .java, .py, .m, .c, .properties (key references)
- Misconfiguration can be in .yml, .yaml, .json, .properties, .xml, .conf, .plist, .env
- Auth issues can be in .java, .py, .m, .js, .properties (session config)
- SSRF can be in .java, .py, .m, .js, .ts (HTTP client usage)
- Injection in general can be in .sh, .sql, .java, .py, .m, .xml
- Logging issues in .java, .py, .m, .c, .properties, .conf
- Data integrity in .java, .py, .m, .xml, .c
- Access control in .java, .py, .m, .js, .ts, .html (auth guards)

Respond with ONLY a JSON object mapping each OWASP category to its relevant
extensions for THIS specific repository. Only include extensions that actually
exist in the repo.

Format:
{{
  "B1": [".java", ".m", ".py"],
  "B2": [".java", ".py", ".c"],
  "B3": [".java", ".py", ".m", ".sql", ".sh"],
  ... (all B1 through B10)
}}

Only output valid JSON. No other text."""


def build_repo_structure(root: Path, ext_map: dict[str, list[Path]], name_map: dict[str, list[Path]]) -> str:
    """Build a concise view of the repo for the discovery prompt."""
    lines = []
    lines.append("Extension counts:")
    for ext, files in sorted(ext_map.items(), key=lambda x: -len(x[1])):
        lines.append(f"  {ext}: {len(files)} files")
    lines.append("")
    lines.append("Notable file names:")
    notable = {"pom.xml", "build.gradle", "settings.gradle", "package.json", "go.mod",
               "requirements.txt", "Gemfile", "Podfile", "Cargo.toml", "composer.json",
               "web.xml", "AndroidManifest.xml", "Info.plist", "Makefile", "GNUmakefile"}
    for name in sorted(notable):
        if name in name_map:
            for f in name_map[name]:
                lines.append(f"  {f.relative_to(root)}")
    lines.append("")
    lines.append("Directory structure (first 3 levels):")
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        depth = len(rel.parts)
        if depth > 3:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        indent = "  " * (depth - 1)
        lines.append(f"{indent}{dirpath.split('/')[-1]}/")

    return "\n".join(lines)


def run_discovery(
    root: Path,
    ext_map: dict[str, list[Path]],
    name_map: dict[str, list[Path]],
    discovery_cache: Path,
    session_dir: Path,
    redetect: bool = False,
) -> dict[str, list[str]]:
    """
    Phase 1: Ask pi to classify which extensions are relevant for each
    OWASP category in this specific repo.

    Returns {"B1": [".java", ".py"], "B2": [...], ...}
    """
    if not redetect and discovery_cache.exists():
        print("[DISCOVERY] Using cached discovery results")
        with open(discovery_cache) as f:
            return json.load(f)

    print("[DISCOVERY] Analyzing repository structure...")
    repo_structure = build_repo_structure(root, ext_map, name_map)

    prompt = DISCOVERY_PROMPT.format(repo_structure=repo_structure)

    print("[DISCOVERY] Asking agent to classify file types per OWASP category...")
    status, raw = call_pi(prompt, session_dir, timeout=240)

    if status != "ok":
        print(f"[DISCOVERY] Warning: discovery call returned {status}: {raw[:300]}")
        # Fall back to base extensions from registry
        print("[DISCOVERY] Falling back to default extension lists")
        result = {}
        for sid, cfg in OWASP_SCANNERS.items():
            result[sid] = cfg["base_ext"]
    else:
        parsed = extract_json_object(raw)
        if isinstance(parsed, dict):
            result = parsed
        else:
            print(f"[DISCOVERY] Warning: invalid JSON, falling back to defaults: {raw[:500]}")
            result = {}
            for sid, cfg in OWASP_SCANNERS.items():
                result[sid] = cfg["base_ext"]

    # Normalize: ensure all values are lists of strings with dots
    normalized = {}
    for sid in ALL_IDS:
        raw_exts = result.get(sid, [])
        if not isinstance(raw_exts, list):
            raw_exts = []
        normalized_exts = []
        for ext in raw_exts:
            if not isinstance(ext, str):
                continue
            ext = ext if ext.startswith(".") else f".{ext}"
            normalized_exts.append(ext)
        # Also include base_ext as fallback (union)
        base = OWASP_SCANNERS.get(sid, {}).get("base_ext", [])
        all_exts = list(dict.fromkeys(normalized_exts + base))  # dedupe, preserve order
        normalized[sid] = all_exts

    # Save cache
    discovery_cache.parent.mkdir(parents=True, exist_ok=True)
    discovery_cache.write_text(json.dumps(normalized, indent=2) + "\n")
    print(f"[DISCOVERY] Saved to {discovery_cache}")

    for sid, exts in sorted(normalized.items()):
        label = OWASP_SCANNERS[sid]["label"]
        print(f"  {sid} ({label}): {', '.join(exts)}")

    return normalized


# ── Phase 2: Scanning ───────────────────────────────────────────────────────


def load_prompt_template(scanner_cfg: dict) -> str:
    """Load the prompt template for a scanner."""
    prompt_path = PROMPTS_DIR / scanner_cfg["prompt_file"]
    if prompt_path.exists():
        return prompt_path.read_text()
    # Fallback
    return f"""\
Analyze this source code file for {scanner_cfg["label"]} vulnerabilities.
Look for patterns associated with {scanner_cfg["label"]} as defined in OWASP Top 10 (2025).

For each vulnerability found, report:
1. Line number(s)
2. The vulnerable code snippet
3. Severity (Critical/High/Medium/Low)
4. Brief explanation of why it is vulnerable
5. Suggested fix

If no vulnerabilities are found, reply with an empty JSON array [].

Output ONLY a JSON array (one entry per vulnerability):
[{{"line":123,"code":"...","severity":"High","explanation":"...","fix":"..."}}]
or [] if none found.

--- FILE CONTENT: {{filename}} ---
{{file_content}}
--- END OF FILE ---
"""


def scan_file(
    filepath: Path,
    scanner_cfg: dict,
    repo_root: Path,
    results_dir: Path,
    session_dir: Path,
    prompt_template: str,
) -> dict:
    """Scan a single file with a given scanner and cache the result."""
    rel = str(filepath.relative_to(repo_root))
    key = file_key(rel, scanner_cfg["name"])
    cache_file = results_dir / f"{key}.json"

    if cache_file.exists():
        print(f"[SKIP] [{scanner_cfg['name']}] {rel}", file=sys.stderr)
        return {"file": rel, "scanner": scanner_cfg["name"], "status": "cached"}

    print(f"[SCAN] [{scanner_cfg['name']}] {rel}", file=sys.stderr)

    try:
        file_content = filepath.read_text(errors="replace")
    except Exception as e:
        return {
            "file": rel,
            "scanner": scanner_cfg["name"],
            "status": "error",
            "result": {"error": f"read_failed: {e}"},
        }

    prompt = prompt_template.format(
        filename=filepath.name,
        file_content=file_content,
    )

    status, raw = call_pi(prompt, session_dir)

    if status != "ok":
        parsed = {"error": raw[:2000]}
    else:
        parsed = extract_json_array(raw)

    data = {
        "file": rel,
        "scanner": scanner_cfg["name"],
        "status": status,
        "result": parsed if isinstance(parsed, (list, dict)) else {"error": "parse_error", "raw": str(parsed)[:2000]},
    }

    # Write atomically
    tmp_path = cache_file.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data))
    shutil.move(str(tmp_path), str(cache_file))

    if status != "ok":
        print(f"[{status.upper()}] [{scanner_cfg['name']}] {rel}", file=sys.stderr)

    return data


def run_scanner(
    scanner_id: str,
    scanner_cfg: dict,
    ext_map: dict[str, list[Path]],
    name_map: dict[str, list[Path]],
    discovery_map: dict[str, list[str]],
    repo_root: Path,
    state_dir: Path,
    session_dir: Path,
    concurrency: int,
    max_files: int,
    rescan: bool,
    dry_run: bool,
) -> tuple[dict, list[dict]]:
    """Run a single OWASP scanner across relevant files."""
    results_dir = state_dir / scanner_cfg["name"] / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Get extensions from discovery (phase 1)
    extensions = discovery_map.get(scanner_id, scanner_cfg["base_ext"])

    # Collect target files
    target_files = []
    for ext in extensions:
        for f in ext_map.get(ext, []):
            if f not in target_files:
                target_files.append(f)

    # Also check for named files (B6: vuln_components)
    for fname in scanner_cfg.get("base_names", []):
        for f in name_map.get(fname, []):
            if f not in target_files:
                target_files.append(f)

    target_files = sorted(target_files, key=lambda p: str(p))

    # Filter already cached
    pending = []
    for f in target_files:
        rel = str(f.relative_to(repo_root))
        key = file_key(rel, scanner_cfg["name"])
        cf = results_dir / f"{key}.json"
        if rescan or not cf.exists():
            pending.append(f)

    already_cached = len(target_files) - len(pending)

    if max_files > 0 and len(pending) > max_files:
        pending = pending[:max_files]

    print(f"\n{'=' * 60}")
    print(f" Scanner: {scanner_cfg['id']} - {scanner_cfg['label']}")
    print(f"{'=' * 60}")
    print(f"  Extensions: {', '.join(extensions)}")
    print(f"  Files total: {len(target_files)} | Cached: {already_cached} | To scan: {len(pending)}")

    if dry_run:
        for f in pending:
            print(f"  {f.relative_to(repo_root)}")
        return scanner_cfg, []

    if not pending:
        print(f"  All files cached. Use --rescan to force.")
        return scanner_cfg, []

    # Load prompt template
    prompt_template = load_prompt_template(scanner_cfg)

    # Scan
    scanned = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(
                scan_file, f, scanner_cfg, repo_root, results_dir, session_dir, prompt_template
            ): f
            for f in pending
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                scanned.append(result)
            except Exception as e:
                f = futures[future]
                print(f"[ERROR] [{scanner_cfg['name']}] {f.relative_to(repo_root)}: {e}", file=sys.stderr)

    return scanner_cfg, scanned


# ── Report Generation ───────────────────────────────────────────────────────


def build_report(
    state_dir: Path,
    output_path: Path,
    repo_root: Path,
    scanner_ids: list[str],
    discovery_map: dict[str, list[str]],
) -> None:
    """Read cached results for all scanners and produce a combined Markdown report."""
    severity_counts_global = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []

    def w(text=""):
        lines.append(text)

    # Header
    w("# OWASP Top 10 (2025) Security Scan Report")
    w()
    w("> Auto-generated by `security_scan.py` using `pi -p`")
    w()
    w(f"**Date:** {now}")
    w(f"**Repository:** {repo_root}")
    w(f"**Scanners:** {', '.join(f'{OWASP_SCANNERS[sid]["label"]} ({sid})' for sid in scanner_ids)}")
    w()

    global_vuln_count = 0
    global_error_count = 0
    global_clean_count = 0
    global_scanned_count = 0

    # Per-scanner sections
    for scanner_id in scanner_ids:
        cfg = OWASP_SCANNERS[scanner_id]
        scanner_name = cfg["name"]
        results_dir = state_dir / scanner_name / "results"

        if not results_dir.exists():
            continue

        result_files = sorted(results_dir.glob("*.json"))
        if not result_files:
            continue

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        no_vulns = 0
        errors = 0
        files_with_vulns = []
        all_findings = []

        for rf in result_files:
            with open(rf) as f:
                data = json.load(f)

            rel = data.get("file", "unknown")
            result_raw = data.get("result", {})
            status = data.get("status", "unknown")
            global_scanned_count += 1

            if status == "cached":
                continue  # Don't double-count cached from previous runs
            if status in ("error", "timeout"):
                errors += 1
                global_error_count += 1
                all_findings.append({"file": rel, "status": status, "vulns": [], "result": result_raw})
                continue

            if isinstance(result_raw, str):
                try:
                    result_raw = json.loads(result_raw)
                except (json.JSONDecodeError, TypeError):
                    pass

            vulns = result_raw if isinstance(result_raw, list) else []

            if not vulns:
                no_vulns += 1
                global_clean_count += 1
            else:
                files_with_vulns.append((rel, len(vulns)))
                for v in vulns:
                    sev = v.get("severity", "Unknown")
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                        severity_counts_global[sev] = severity_counts_global.get(sev, 0) + 1

                all_findings.append({"file": rel, "status": status, "vulns": vulns, "result": result_raw})

        scanner_vuln_count = sum(sev_counts.values())
        global_vuln_count += scanner_vuln_count
        files_with_vulns.sort(key=lambda x: -x[1])

        # Section header
        w(f"## {scanner_id}: {cfg['label']}")
        w()
        w(f"**Extensions scanned:** {', '.join(discovery_map.get(scanner_id, cfg['base_ext']))}")
        w()
        w("| Metric | Count |")
        w("|--------|-------|")
        w(f"| Files scanned | {len(result_files)} |")
        w(f"| Total vulnerabilities | {scanner_vuln_count} |")
        w(f"| Critical | {sev_counts['Critical']} |")
        w(f"| High | {sev_counts['High']} |")
        w(f"| Medium | {sev_counts['Medium']} |")
        w(f"| Low | {sev_counts['Low']} |")
        w(f"| Clean files | {no_vulns} |")
        w(f"| Errors | {errors} |")
        w()

        if files_with_vulns:
            w("### Vulnerable Files")
            w()
            w("| File | Vulnerabilities |")
            w("|------|----------------|")
            for rel, count in files_with_vulns[:20]:
                w(f"| `{rel}` | {count} |")
            w()

        # Findings
        w("### Findings")
        w()
        if not any(e["vulns"] for e in all_findings):
            w("*No vulnerabilities found for this category.*")
            w()
        else:
            w("<details><summary>Toggle full findings</summary>")
            w()
            for entry in all_findings:
                rel = entry["file"]
                vulns = entry["vulns"]
                status = entry["status"]

                if status in ("error", "timeout"):
                    w(f"#### [ERROR] {rel}")
                    w()
                    w(f"**Status:** {status}")
                    w()
                    continue

                if not vulns:
                    w(f"#### [CLEAN] {rel}")
                    w()
                    w("**No issues found**")
                    w()
                    continue

                w(f"#### [VULN] {rel} — {len(vulns)} issue(s)")
                w()
                for i, v in enumerate(vulns, 1):
                    severity = v.get("severity", "Unknown")
                    line_num = v.get("line", "?")
                    code = v.get("code", "")
                    explanation = v.get("explanation", "")
                    fix = v.get("fix", "")

                    w(f"**#{i}** (Line {line_num}) — `{severity}`")
                    w()
                    if code:
                        w("```")
                        w(code)
                        w("```")
                        w()
                    if explanation:
                        w(f"*Why:* {explanation}")
                        w()
                    if fix:
                        w(f"*Fix:* {fix}")
                        w()
                    w("---")
                    w()

            w("</details>")
            w()

    # Global summary
    w("---")
    w()
    w("## Global Summary")
    w()
    w("| Metric | Count |")
    w("|--------|-------|")
    w(f"| Total files scanned | {global_scanned_count} |")
    w(f"| Total vulnerabilities | {global_vuln_count} |")
    w(f"| Critical | {severity_counts_global['Critical']} |")
    w(f"| High | {severity_counts_global['High']} |")
    w(f"| Medium | {severity_counts_global['Medium']} |")
    w(f"| Low | {severity_counts_global['Low']} |")
    w(f"| Clean files | {global_clean_count} |")
    w(f"| Errors/timeouts | {global_error_count} |")
    w()

    # OWASP risk matrix
    w("### Risk Heatmap")
    w()
    w("| Severity | Count | Risk Level |")
    w("|----------|-------|------------|")
    crit = severity_counts_global["Critical"]
    high = severity_counts_global["High"]
    med = severity_counts_global["Medium"]
    low = severity_counts_global["Low"]
    w(f"| Critical | {crit} | {'🔴 CRITICAL' if crit > 0 else '🟢 Clear'} |")
    w(f"| High     | {high} | {'🟠 HIGH' if high > 0 else '🟢 Clear'} |")
    w(f"| Medium   | {med} | {'🟡 MEDIUM' if med > 0 else '🟢 Clear'} |")
    w(f"| Low      | {low} | {'🟢 LOW' if low == 0 else '⚠️ Review'} |")
    w()

    overall = "🔴 CRITICAL" if crit > 0 else "🟠 HIGH" if high > 0 else "🟡 MEDIUM" if med > 0 else "🟢 LOW"
    w(f"**Overall Risk:** {overall}")
    w()

    w("---")
    w()
    w(f"*Report generated on {now} by `security_scan.py`*")

    # Write
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n")

    # Console summary
    print()
    print("=" * 60)
    print(" Scan complete!")
    print("=" * 60)
    print(f"  Scanners run:        {len(scanner_ids)}")
    print(f"  Files scanned:       {global_scanned_count}")
    print(f"  Vulnerabilities:     {global_vuln_count}")
    print(f"    Critical: {severity_counts_global['Critical']}")
    print(f"    High:     {severity_counts_global['High']}")
    print(f"    Medium:   {severity_counts_global['Medium']}")
    print(f"    Low:      {severity_counts_global['Low']}")
    print(f"  Clean files:         {global_clean_count}")
    print(f"  Errors/timeouts:     {global_error_count}")
    print()
    print(f"  Report: {output_path}")


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 (2025) Security Scanner using pi -p",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --all                   Run all OWASP scanners
  %(prog)s --scanner B3            Run injection scanner only
  %(prog)s --scanner B1,B3,B7      Run access control, injection, auth
  %(prog)s --phase 1               Discovery only (classify files)
  %(prog)s --phase 2 --scanner B3  Scan only (uses cached discovery)
  %(prog)s --scanner B3 --rescan   Re-scan all files for injection
  %(prog)s --max-files 10          Limit each scanner to 10 files

OWASP 2025 Categories:
  B1  Broken Access Control
  B2  Cryptographic Failures
  B3  Injection
  B4  Insecure Design
  B5  Security Misconfiguration
  B6  Vulnerable and Outdated Components
  B7  Identification and Authentication Failures
  B8  Software and Data Integrity Failures
  B9  Security Logging and Monitoring Failures
  B10 Server-Side Request Forgery
""",
    )
    parser.add_argument("--all", action="store_true", help="Run all OWASP scanners")
    parser.add_argument("--scanner", default=None, help="Comma-separated OWASP IDs (B1,B3,B7) or --all")
    parser.add_argument("--phase", type=int, default=0, help="Run only phase N (1=discovery, 2=scan). 0=both.")
    parser.add_argument("--concurrency", type=int, default=4, help="Max parallel scans (default: 4)")
    parser.add_argument("--max-files", type=int, default=0, help="Limit files per scanner (default: all)")
    parser.add_argument("--output", default=None, help="Report output path (default: security_report.md)")
    parser.add_argument("--state-dir", default=None, help="Directory for cached results (default: .security_scan)")
    parser.add_argument("--dry-run", action="store_true", help="List files without scanning")
    parser.add_argument("--rescan", action="store_true", help="Re-scan all files even if cached")
    parser.add_argument("--redetect", action="store_true", help="Re-run discovery even if cached")

    args = parser.parse_args()

    # Resolve scanner IDs
    if args.all:
        scanner_ids = ALL_IDS[:]
    elif args.scanner:
        scanner_ids = [s.strip().upper() for s in args.scanner.split(",")]
        for sid in scanner_ids:
            if sid not in OWASP_SCANNERS:
                print(f"Unknown scanner: {sid}. Valid: {', '.join(ALL_IDS)}")
                sys.exit(1)
    else:
        print("Specify --all or --scanner B1,B3,...")
        sys.exit(1)

    # Resolve paths
    repo_root = Path.cwd()
    state_dir = Path(args.state_dir) if args.state_dir else repo_root / ".security_scan"
    output_path = Path(args.output) if args.output else repo_root / "security_report.md"
    discovery_cache = state_dir / "discovery.json"
    session_dir = state_dir / "sessions"

    state_dir.mkdir(parents=True, exist_ok=True)
    session_dir.mkdir(parents=True, exist_ok=True)

    print(f"Repository:  {repo_root}")
    print(f"Scanners:    {', '.join(f'{sid} ({OWASP_SCANNERS[sid]["label"]})' for sid in scanner_ids)}")
    print(f"State:       {state_dir}")
    print(f"Output:      {output_path}")
    print(f"Phase:       {'1 (discovery)' if args.phase == 1 else '2 (scan)' if args.phase == 2 else 'both'}")
    print()

    # ── Discover files ──
    print("Discovering files...")
    all_files, ext_map, name_map = find_all_files(repo_root)
    ext_summary = sorted(ext_map.items(), key=lambda x: -len(x[1]))[:15]
    print(f"Found {len(all_files)} non-binary files across {len(ext_map)} extensions:")
    for ext, files in ext_summary:
        print(f"  {ext}: {len(files)}")
    if len(ext_map) > 15:
        print(f"  ... and {len(ext_map) - 15} more")
    print()

    # ── Phase 1: Discovery ──
    discovery_map = {}
    if args.phase == 0 or args.phase == 1:
        discovery_map = run_discovery(
            repo_root, ext_map, name_map,
            discovery_cache, session_dir,
            redetect=args.redetect,
        )

    if args.phase == 1:
        print("\nDiscovery complete. Run with --phase 2 or no --phase flag to scan.")
        return

    # ── If phase 2 only, load discovery from cache ──
    if args.phase == 2 and not discovery_map:
        if discovery_cache.exists():
            with open(discovery_cache) as f:
                discovery_map = json.load(f)
        else:
            print("No discovery cache found. Run with --phase 1 or no --phase flag first.")
            sys.exit(1)

    # ── Phase 2: Scan ──
    print()
    if args.phase == 2:
        print("Phase 2: Scanning (using cached discovery)...")
    else:
        print("Phase 2: Scanning...")

    all_results = []
    for scanner_id in scanner_ids:
        cfg = OWASP_SCANNERS[scanner_id]
        _, results = run_scanner(
            scanner_id, cfg, ext_map, name_map, discovery_map,
            repo_root, state_dir, session_dir,
            args.concurrency, args.max_files, args.rescan, args.dry_run,
        )
        all_results.extend(results)

    # ── Report ──
    if not args.dry_run:
        print()
        print("=" * 60)
        print(" Building report...")
        print("=" * 60)
        build_report(state_dir, output_path, repo_root, scanner_ids, discovery_map)


if __name__ == "__main__":
    main()
