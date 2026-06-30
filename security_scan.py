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
import threading
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


def find_all_files(root: Path) -> tuple[list[Path], dict[str, list[Path]], dict[str, list[Path]]]:
    """
    Walk the repo and collect:
      - all non-binary files
      - files grouped by extension
      - files grouped by well-known names
    Returns (all_files, ext_map, name_map).
    """
    all_files = []
    ext_map: dict[str, list[Path]] = {}
    name_map: dict[str, list[Path]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded dirs — match by basename or by full relative path prefix
        rel_dir = str(Path(dirpath).relative_to(root))
        pruned = []
        for d in dirnames:
            rel = f"{rel_dir}/{d}" if rel_dir != "." else d
            if any(rel == excl or rel.startswith(excl + "/") for excl in EXCLUDE_DIRS):
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

            # Skip files we can't read
            try:
                sample = filepath.read_bytes()[:8192]
            except Exception:
                continue

            # Skip files that look binary (NUL byte in first 8KB)
            if b"\x00" in sample:
                continue

            all_files.append(filepath)
            ext_map.setdefault(ext, []).append(filepath)
            name_map.setdefault(fname, []).append(filepath)

    return all_files, ext_map, name_map


def file_key(rel_path: str, scanner_name: str, content_hash: str, prompt_hash: str) -> str:
    """Cache key = scanner + rel path + content hash + prompt hash.

    Including content and prompt hashes invalidates the cache when either
    changes, so a modified file or an edited prompt template forces a re-scan.
    """
    return hashlib.md5(
        f"{scanner_name}:{rel_path}:{content_hash}:{prompt_hash}".encode()
    ).hexdigest()


def content_hash(data: bytes) -> str:
    """Short content fingerprint used in the cache key."""
    return hashlib.md5(data).hexdigest()[:16]


def prompt_hash(text: str) -> str:
    """Short prompt-template fingerprint used in the cache key."""
    return hashlib.md5(text.encode()).hexdigest()[:16]


def findings_signature(findings: list[dict]) -> str:
    """Stable fingerprint of a findings list, used to invalidate verification
    cache entries when the underlying scan results change.

    A canonical JSON form (sorted keys, no whitespace) keeps the signature
    stable across Python versions and dict-iteration order.
    """
    canonical = json.dumps(findings, sort_keys=True, separators=(",", ":"))
    return hashlib.md5(canonical.encode()).hexdigest()[:16]


def verify_file_key(
    rel: str, scanner_name: str, content_hash_value: str,
    findings_sig: str, verify_prompt_hash_value: str,
) -> str:
    """Cache key for a per-file verification result.

    Keyed on (scanner, file path, file content hash, findings signature,
    verify-prompt hash) so a change to any of those inputs re-runs verification.
    The findings signature is the link that keeps verification in sync with
    phase 2: a new vuln or a changed finding invalidates the verification.
    """
    return hashlib.md5(
        f"verify:{scanner_name}:{rel}:{content_hash_value}:"
        f"{findings_sig}:{verify_prompt_hash_value}".encode()
    ).hexdigest()


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

    if "NO_VULNERABILITIES" in text.upper():
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


# Read-only tool allowlist used when a phase is run with tools enabled.
# Matches the exact pattern from pi's docs example for read-only review
# (`pi --tools read,grep,find,ls -p "Review the code"`). The model can
# inspect the repo but cannot execute, edit, write, or fetch.
READONLY_TOOLS = ["read", "grep", "find", "ls"]


def call_pi(
    prompt: str,
    session_dir: Path,
    timeout: int = 180,
    tools: list[str] | None = None,
) -> tuple[str, str]:
    """
    Call `pi -p` with the given prompt.
    Uses @file syntax to avoid ARG_MAX limits on large prompts.
    Returns (status, raw_output).

    `tools` controls whether the underlying `pi` invocation gets tool use.
    - `None` (default) preserves the historical behavior: `--no-tools` is
      passed and the model sees only the prompt text.
    - A non-empty list (e.g. `READONLY_TOOLS`) drops `--no-tools` and adds
      `--tools <comma-joined>`, allowing the model to read files, search,
      and so on within whatever allowlist the caller chose.
    """
    # Write prompt to temp file to avoid argument length limits
    tmp_fd = None
    tmp_path = None
    try:
        tmp_fd = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='pi_prompt_')
        tmp_path = tmp_fd.name
        tmp_fd.write(prompt)
        tmp_fd.close()

        cmd = ["pi", "--print"]
        if tools:
            cmd.extend(["--tools", ",".join(tools)])
        else:
            cmd.append("--no-tools")
        cmd.extend([
            "--no-session", "--mode", "text",
            "--session-dir", str(session_dir), f"@{tmp_path}",
        ])

        proc = subprocess.run(
            cmd,
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


# ── Progress tracker ────────────────────────────────────────────────────────


class ProgressTracker:
    """Thread-safe progress reporter that renders a single in-place line on
    stderr, showing per-phase counters and ETA.

    Usage:

        progress = ProgressTracker()                 # enabled, TTY-detected
        progress = ProgressTracker(enabled=False)   # silent, all methods no-op
        progress.start_phase("scan", total=1000)
        ...                                          # do work, call tick() on completion
        progress.tick("scan")
        progress.stop()                             # prints final line

    Rendering strategy:
      - On a TTY, refreshes every `refresh_interval` seconds using `\\r` so
        the line overwrites itself in place. Padded with spaces to clear
        residual characters from longer previous lines.
      - Off-TTY (CI logs, redirected stderr), refreshes on the same
        interval but writes a new line each time. One line per update,
        no escape sequences, easy to grep.

    The renderer runs on a daemon thread; `stop()` joins it and emits the
    final newline-terminated line so the value survives in the terminal.
    """

    def __init__(self, enabled: bool = True, refresh_interval: float = 0.5):
        self.enabled = enabled
        self.refresh_interval = refresh_interval
        # phase name -> {total, completed, started_at}
        self._phases: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._render_thread: threading.Thread | None = None
        # TTY detection: only use \r when stderr is a real terminal AND the
        # user didn't redirect it. CI logs and `2>file.log` get newline
        # updates so each tick is its own grep-able line.
        self._use_cr = enabled and sys.stderr.isatty()

    def start_phase(self, phase: str, total: int) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._phases[phase] = {
                "total": max(int(total), 0),
                "completed": 0,
                "started_at": time.time(),
            }
        self._ensure_render_thread()

    def tick(self, phase: str, amount: int = 1) -> None:
        if not self.enabled:
            return
        with self._lock:
            entry = self._phases.get(phase)
            if entry is not None:
                entry["completed"] = min(
                    entry["completed"] + amount,
                    entry["total"],
                )

    def stop(self) -> None:
        if not self.enabled:
            return
        self._stop_event.set()
        if self._render_thread is not None:
            self._render_thread.join(timeout=2.0)
        # Final render with a real newline so the line survives.
        self._render(force_newline=True)

    def _ensure_render_thread(self) -> None:
        if self._render_thread is not None:
            return
        self._render_thread = threading.Thread(
            target=self._render_loop,
            name="progress-tracker",
            daemon=True,
        )
        self._render_thread.start()

    def _render_loop(self) -> None:
        while not self._stop_event.is_set():
            self._render()
            # sleep in small slices so stop() returns promptly
            self._stop_event.wait(self.refresh_interval)

    def _render(self, force_newline: bool = False) -> None:
        if not self.enabled:
            return
        with self._lock:
            if not self._phases:
                return
            parts: list[str] = []
            now = time.time()
            for phase, data in self._phases.items():
                total = data["total"]
                if total <= 0:
                    continue
                completed = data["completed"]
                if completed >= total:
                    parts.append(f"[{phase}] {completed}/{total} (done)")
                    continue
                elapsed = max(now - data["started_at"], 1e-6)
                rate = completed / elapsed
                remaining = total - completed
                eta = remaining / rate if rate > 0 else float("inf")
                parts.append(
                    f"[{phase}] {completed}/{total} "
                    f"({rate:.1f}/s, ETA {_format_eta(eta)})"
                )
        if not parts:
            return
        line = " · ".join(parts)
        # Pad to 80 chars so a shorter line overwrites any residue from
        # a longer previous one when we're using \r. Off-TTY we don't pad
        # because the trailing spaces would just be noise in logs.
        if self._use_cr and not force_newline:
            padded = line.ljust(80)
            sys.stderr.write("\r" + padded)
            sys.stderr.flush()
        else:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()


def _format_eta(seconds: float) -> str:
    if seconds == float("inf") or seconds < 0:
        return "?"
    if seconds < 1:
        return "<1s"
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, mins = divmod(minutes, 60)
    return f"{hours}h{mins:02d}m"


# ── Phase 1: Discovery ──────────────────────────────────────────────────────

DEFAULT_DISCOVERY_PROMPT = """\
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


def load_discovery_prompt() -> str:
    """Load the discovery prompt template from prompts/discovery.txt.

    Falls back to a built-in default if the file is missing so the script
    still runs after a fresh checkout that only includes the scanner prompts.
    """
    path = PROMPTS_DIR / "discovery.txt"
    if path.exists():
        return path.read_text()
    return DEFAULT_DISCOVERY_PROMPT


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
        lines.append(f"{indent}{Path(dirpath).name}/")

    return "\n".join(lines)


def run_discovery(
    root: Path,
    ext_map: dict[str, list[Path]],
    name_map: dict[str, list[Path]],
    discovery_cache: Path,
    session_dir: Path,
    redetect: bool = False,
    timeout: int = 240,
    tools: list[str] | None = None,
) -> dict[str, list[str]]:
    """
    Phase 1: Ask pi to classify which extensions are relevant for each
    OWASP category in this specific repo.

    `tools` is forwarded to `call_pi`; pass `None` to keep the historical
    no-tools behavior, or a list (typically `READONLY_TOOLS`) to give the
    model the ability to inspect the repo before deciding. The cache file
    path is the caller's responsibility — main() picks `discovery.json`
    vs `discovery-tools.json` so the two modes don't collide.

    Returns {"B1": [".java", ".py"], "B2": [...], ...}
    """
    if not redetect and discovery_cache.exists():
        print("[DISCOVERY] Using cached discovery results")
        try:
            with open(discovery_cache) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[DISCOVERY] Cache unreadable ({e}); re-running discovery")

    print("[DISCOVERY] Analyzing repository structure...")
    repo_structure = build_repo_structure(root, ext_map, name_map)

    prompt = load_discovery_prompt().format(repo_structure=repo_structure)

    print("[DISCOVERY] Asking agent to classify file types per OWASP category...")
    status, raw = call_pi(prompt, session_dir, timeout=timeout, tools=tools)

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
    return """\
Analyze this source code file for {label} vulnerabilities.
Look for patterns associated with {label} as defined in OWASP Top 10 (2025).

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
""".replace("{label}", scanner_cfg["label"])


# ── Phase 3: Verification ───────────────────────────────────────────────────

VERIFY_PROMPT_FILE = "verify_prompt.txt"

DEFAULT_VERIFY_PROMPT = """\
You are a senior security engineer reviewing a set of automated security findings
to determine which are actually exploitable in the specific codebase shown below.

The file under review is: {filename}

Below is the full file content, followed by a list of findings that an automated
scanner produced for this file. Your job is to evaluate each finding against the
code as-written, considering:

1. Is the vulnerable code path actually reachable from a real entry point
   (HTTP handler, CLI argument, queue consumer, public API method, IPC)?
2. Is the value actually tainted, or is it sanitized/validated upstream in the
   same file (e.g. a wrapper function that pre-validates its inputs, an
   allowlist filter, an ORM that parameterizes the underlying query)?
3. Is the function/branch dead code, behind a feature flag that is off, called
   only from test fixtures, or guarded by a permission check that already exists?
4. Is the underlying issue real, or is the scanner misreading a safe pattern
   (e.g. an internal constant mistaken for user input, a config file that is
   never deployed, a hardcoded value that is not actually dynamic)?
5. Could a realistic attacker craft an input that triggers this? If only under
   unusual preconditions (admin role, specific feature flag, internal network
   access), say so.

For EACH finding in the input list, output exactly one JSON object with:

  - "line": the line number (MUST match the input finding's line exactly -
    do not change it, do not add or omit findings)
  - "confidence": one of "High", "Medium", or "Low"
      High   = the finding is real AND the vulnerable code is reachable AND
               a realistic attacker could trigger it
      Medium = the finding looks real but the entry point, sanitization, or
               reachability is unclear from the visible code (e.g. the input
               function is a public method but no caller is shown, or the
               tainted value crosses a trust boundary the file does not show)
      Low    = likely false positive - input is sanitized/validated upstream,
               the code path is dead, the pattern is actually safe, or the
               function is only called by tests
  - "exploitable": one of "yes", "no", or "conditional"
      yes         = a realistic attacker can trigger this with normal input
      no          = cannot be triggered (dead code, sanitized, internal-only)
      conditional = only triggers under specific preconditions (admin role,
                    feature flag, internal-only configuration, specific build)
  - "verification_reason": ONE OR TWO SENTENCES explaining your conclusion,
    citing the specific upstream call / sanitization / entry point you found
    (or stating that you could not find one).

Output ONLY a JSON array (one entry per input finding, IN THE SAME ORDER as the
input). Use exactly the line numbers from the input - do not change them.
If a finding's line number does not match any real issue in the file, mark it
as exploitable: "no" and confidence: "Low".

--- FILE CONTENT: {filename} ---
{file_content}
--- END OF FILE ---

--- FINDINGS (from automated scan, in order) ---
{findings_json}
--- END OF FINDINGS ---
"""


def load_verify_prompt() -> str:
    """Load the verification prompt template. Falls back to a built-in
    default so the script still works on a fresh checkout that does not
    include `prompts/verify_prompt.txt`.
    """
    path = PROMPTS_DIR / VERIFY_PROMPT_FILE
    if path.exists():
        return path.read_text()
    return DEFAULT_VERIFY_PROMPT


def _verify_cache_usable(cache_file: Path) -> bool:
    """True if the cache file exists and holds a successful verification.

    Cache entries with status error/timeout are treated as misses so the
    next run retries the verification rather than reusing a cached failure.
    A corrupt or unreadable cache file also returns False (treated as miss)
    so a transient disk error doesn't permanently block the file.
    """
    if not cache_file.exists():
        return False
    try:
        with open(cache_file) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    return data.get("status") == "ok"


def verify_finding(
    filepath: Path,
    scanner_cfg: dict,
    rel: str,
    findings: list[dict],
    repo_root: Path,
    verify_dir: Path,
    session_dir: Path,
    verify_template: str,
    verify_prompt_hash_value: str,
    timeout: int = 300,
    force: bool = False,
    tools: list[str] | None = None,
) -> dict:
    """Verify a single file's findings: ask the model to rate each finding's
    confidence and exploitability in the context of the file as written.

    Caches the per-(scanner, file) verification result; cache key invalidates
    when file content, findings list, or verify prompt changes.

    Failed verifications (pi error or timeout) are NOT cached. Any
    pre-existing failed cache entry for this key is removed before the
    call so a transient failure on one run is retried on the next.

    `tools` is forwarded to `call_pi`. When set, the model can read related
    files (callers, sanitizers, auth middleware) before judging each
    finding — the cross-file judgment that makes the verify phase
    worthwhile. The cache lives under `verify_dir`, which the caller picks
    so tools-mode and no-tools-mode verdicts never share a path.
    """
    try:
        raw_bytes = filepath.read_bytes()
    except Exception as e:
        return {
            "file": rel, "scanner": scanner_cfg["name"], "status": "error",
            "result": {"error": f"read_failed: {e}"},
        }

    c_hash = content_hash(raw_bytes)
    f_sig = findings_signature(findings)
    key = verify_file_key(rel, scanner_cfg["name"], c_hash, f_sig, verify_prompt_hash_value)
    cache_file = verify_dir / f"{key}.json"

    if not force and _verify_cache_usable(cache_file):
        print(f"[VERIFY-SKIP] [{scanner_cfg['name']}] {rel}", file=sys.stderr)
        return {"file": rel, "scanner": scanner_cfg["name"], "status": "cached"}

    file_content = raw_bytes.decode("utf-8", errors="replace")

    try:
        prompt = verify_template.format(
            filename=filepath.name,
            file_content=file_content,
            findings_json=json.dumps(findings, indent=2),
        )
    except (KeyError, IndexError, ValueError) as e:
        return {
            "file": rel, "scanner": scanner_cfg["name"], "status": "error",
            "result": {"error": f"prompt_format_failed: {e}"},
        }

    print(f"[VERIFY] [{scanner_cfg['name']}] {rel}", file=sys.stderr)
    status, raw = call_pi(prompt, session_dir, timeout=timeout, tools=tools)

    if status != "ok":
        parsed: object = {"error": raw[:2000]}
    else:
        parsed = extract_json_array(raw)

    # Normalize the parsed response into a line-keyed map of
    # {confidence, exploitable, verification_reason}. The scan report joins
    # these onto its findings by line number, so the line MUST be preserved
    # verbatim from the verifier's output.
    verifications: dict[str, dict] = {}
    parse_error: str | None = None
    if isinstance(parsed, list):
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            try:
                line_key = str(int(entry.get("line")))
            except (TypeError, ValueError):
                continue
            verifications[line_key] = {
                "confidence": entry.get("confidence", "Unknown"),
                "exploitable": entry.get("exploitable", "unknown"),
                "verification_reason": entry.get("verification_reason", ""),
            }
    elif isinstance(parsed, dict):
        parse_error = parsed.get("error", "parse_error")

    data = {
        "file": rel,
        "scanner": scanner_cfg["name"],
        "status": status,
        "content_hash": c_hash,
        "findings_signature": f_sig,
        "verify_prompt_hash": verify_prompt_hash_value,
        "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verifications": verifications,
    }
    if parse_error is not None:
        data["parse_error"] = parse_error
    if status != "ok":
        data["error"] = raw[:2000]

    if status == "ok":
        tmp_path = cache_file.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data))
        shutil.move(str(tmp_path), str(cache_file))
    else:
        # Don't cache failures. Remove any prior cache entry (including a
        # stale failed one left by an older run) so the next run treats
        # this file as a miss and retries the verification.
        if cache_file.exists():
            try:
                cache_file.unlink()
            except OSError:
                pass
        print(f"[{status.upper()}] [VERIFY] [{scanner_cfg['name']}] {rel}", file=sys.stderr)

    return data


def run_verification(
    scanner_id: str,
    scanner_cfg: dict,
    repo_root: Path,
    state_dir: Path,
    session_dir: Path,
    concurrency: int,
    reverify: bool,
    dry_run: bool,
    verify_timeout: int = 300,
    tools: list[str] | None = None,
    scan_uses_tools: bool = False,
    progress: "ProgressTracker | None" = None,
) -> tuple[dict, list[dict]]:
    """Phase 3: Verify findings for every file that has at least one finding
    in this scanner's results dir. Files with no findings, suppressed
    findings only, or scan errors are skipped - there is nothing to verify.

    Two independent tool flags:

    - `tools` controls whether the verifier itself runs with read-only
      tools, and where its output lives (`verifications-tools/` vs
      `verifications/`).
    - `scan_uses_tools` controls where the scan results to be verified
      live (`results-tools/` vs `results/`). The verify phase must read
      from the same dir the scan wrote to, so this is a separate flag —
      you can run with `--scan-tools` off and `--verify-tools` on, and
      the verifier still finds the scan output in `results/`.
    """
    results_dir = state_dir / scanner_cfg["name"] / (
        "results-tools" if scan_uses_tools else "results"
    )
    verify_dir = state_dir / scanner_cfg["name"] / (
        "verifications-tools" if tools else "verifications"
    )
    verify_dir.mkdir(parents=True, exist_ok=True)

    if not results_dir.exists():
        return scanner_cfg, []

    # Compute the verify prompt hash once so we can pre-check the cache for
    # each file. Files whose verdict is already cached are skipped from
    # `files_to_verify` so the progress total reflects actual work — a
    # 99%-cached run would otherwise show 99% done in the first second and
    # then stall on the remaining 1%, giving a wildly wrong ETA.
    verify_template = load_verify_prompt()
    v_prompt_hash = prompt_hash(verify_template)

    files_to_verify: list[tuple[Path, str, list[dict]]] = []
    cached_count = 0
    for rf in sorted(results_dir.glob("*.json")):
        try:
            with open(rf) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[WARN] Skipping corrupt cache file {rf}: {e}", file=sys.stderr)
            continue

        if data.get("status") in ("error", "timeout"):
            continue
        rel = data.get("file", "")
        if not rel:
            continue
        result = data.get("result", [])
        if not isinstance(result, list):
            continue
        vulns = [v for v in result if isinstance(v, dict)]
        if not vulns:
            continue

        filepath = repo_root / rel
        if not filepath.exists():
            print(f"[WARN] Skipping verify of {rel}: file no longer exists", file=sys.stderr)
            continue

        # Pre-check the verification cache. Reading the file here is
        # duplicated work for uncached files (verify_finding reads it
        # again) but the cost is one filesystem hit per file — negligible
        # compared to the pi call it would otherwise do unnecessarily.
        if not reverify:
            try:
                raw_bytes = filepath.read_bytes()
                c_hash = content_hash(raw_bytes)
                f_sig = findings_signature(vulns)
                # verify_file_key signature is (rel, scanner_name, content_hash,
                # findings_sig, verify_prompt_hash) — must match what
                # verify_finding uses, or the pre-check silently misses
                # every cache hit.
                v_key = verify_file_key(
                    rel, scanner_cfg["name"], c_hash, f_sig, v_prompt_hash,
                )
                # Treat stale failed cache entries as misses so a prior
                # timeout/error gets retried on the next run instead of
                # blocking the file forever.
                if _verify_cache_usable(verify_dir / f"{v_key}.json"):
                    print(f"[VERIFY-SKIP] [{scanner_cfg['name']}] {rel}", file=sys.stderr)
                    cached_count += 1
                    continue
            except Exception:
                # I/O or permission error reading the file: fall through and
                # let verify_finding handle it (it will emit the error there).
                pass

        files_to_verify.append((filepath, rel, vulns))

    print(f"\n{'=' * 60}")
    print(f" Verification: {scanner_cfg['id']} - {scanner_cfg['label']}")
    print(f"{'=' * 60}")
    mode_label = "read-only tools" if tools else "no tools"
    print(f"  Mode: {mode_label}")
    total_with_findings = len(files_to_verify) + cached_count
    if cached_count and not reverify:
        print(f"  Files with findings: {total_with_findings} "
              f"({cached_count} already verified, {len(files_to_verify)} to verify)")
    else:
        print(f"  Files with findings: {len(files_to_verify)}")

    if dry_run:
        for _, rel, _ in files_to_verify:
            print(f"  {rel}")
        return scanner_cfg, []

    if not files_to_verify:
        return scanner_cfg, []

    verified: list[dict] = []
    if progress is not None and files_to_verify:
        progress.start_phase("verify", total=len(files_to_verify))
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(
                verify_finding, fp, scanner_cfg, rel, vulns, repo_root,
                verify_dir, session_dir, verify_template, v_prompt_hash,
                verify_timeout, reverify, tools,
            ): (fp, rel)
            for fp, rel, vulns in files_to_verify
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                verified.append(result)
            except Exception as e:
                fp, rel = futures[future]
                print(f"[ERROR] [VERIFY] [{scanner_cfg['name']}] {rel}: {e}", file=sys.stderr)
            finally:
                if progress is not None:
                    progress.tick("verify")

    return scanner_cfg, verified


def load_verification_for_file(
    scanner_name: str,
    rel: str,
    content_hash_value: str,
    findings: list[dict],
    verify_dir: Path,
    verify_prompt_hash_value: str,
) -> dict[str, dict] | None:
    """Look up the verification result for a (scanner, file) pair and return
    the line-keyed verification map. Returns None when there is no usable
    verification (no file, signature mismatch = stale, or scan failed).

    Used by `build_report` to overlay confidence/exploitability onto findings
    without having to re-run verification.
    """
    if not verify_dir.exists():
        return None
    f_sig = findings_signature(findings)
    key = verify_file_key(
        rel, scanner_name, content_hash_value, f_sig, verify_prompt_hash_value,
    )
    cache_file = verify_dir / f"{key}.json"
    if not cache_file.exists():
        return None
    try:
        with open(cache_file) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    # Defensive: ensure the cached entry was produced from the same findings
    # list. A mismatch means the scan was re-run since verification and the
    # old verdict is no longer trustworthy.
    if data.get("findings_signature") != f_sig:
        return None
    if data.get("status") != "ok":
        return None
    verifications = data.get("verifications", {})
    if not isinstance(verifications, dict):
        return None
    return verifications


def scan_file(
    filepath: Path,
    scanner_cfg: dict,
    repo_root: Path,
    results_dir: Path,
    session_dir: Path,
    prompt_template: str,
    prompt_hash_value: str,
    timeout: int = 180,
    force: bool = False,
    tools: list[str] | None = None,
) -> dict:
    """Scan a single file with a given scanner and cache the result.

    `tools` is forwarded to `call_pi`. The cache file lives under
    `results_dir`, which the caller (run_scanner) picks so tools-mode and
    no-tools-mode results never share a path.
    """
    rel = str(filepath.relative_to(repo_root))

    print(f"[SCAN] [{scanner_cfg['name']}] {rel}", file=sys.stderr)

    try:
        raw_bytes = filepath.read_bytes()
    except Exception as e:
        return {
            "file": rel,
            "scanner": scanner_cfg["name"],
            "status": "error",
            "result": {"error": f"read_failed: {e}"},
        }

    c_hash = content_hash(raw_bytes)
    key = file_key(rel, scanner_cfg["name"], c_hash, prompt_hash_value)
    cache_file = results_dir / f"{key}.json"

    if not force and cache_file.exists():
        print(f"[SKIP] [{scanner_cfg['name']}] {rel}", file=sys.stderr)
        return {"file": rel, "scanner": scanner_cfg["name"], "status": "cached"}

    file_content = raw_bytes.decode("utf-8", errors="replace")

    try:
        prompt = prompt_template.format(
            filename=filepath.name,
            file_content=file_content,
        )
    except (KeyError, IndexError, ValueError) as e:
        return {
            "file": rel,
            "scanner": scanner_cfg["name"],
            "status": "error",
            "result": {"error": f"prompt_format_failed: {e}"},
        }

    status, raw = call_pi(prompt, session_dir, timeout=timeout, tools=tools)

    if status != "ok":
        parsed = {"error": raw[:2000]}
    else:
        parsed = extract_json_array(raw)

    data = {
        "file": rel,
        "scanner": scanner_cfg["name"],
        "status": status,
        "content_hash": c_hash,
        "prompt_hash": prompt_hash_value,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "result": parsed if isinstance(parsed, (list, dict)) else {"error": "parse_error", "raw": str(parsed)[:2000]},
    }

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
    format_override: list[str] | None = None,
    scan_timeout: int = 180,
    tools: list[str] | None = None,
    progress: "ProgressTracker | None" = None,
) -> tuple[dict, list[dict]]:
    """Run a single OWASP scanner across relevant files.

    When `tools` is non-empty, results are cached under
    `<scanner>/results-tools/` (sibling of the no-tools `results/` dir) so
    the two modes never collide and can be toggled without invalidating
    each other.
    """
    results_dir = state_dir / scanner_cfg["name"] / (
        "results-tools" if tools else "results"
    )
    results_dir.mkdir(parents=True, exist_ok=True)

    if format_override:
        extensions = list(format_override)
    else:
        extensions = discovery_map.get(scanner_id, scanner_cfg["base_ext"])

    target_set: set[Path] = set()
    for ext in extensions:
        target_set.update(ext_map.get(ext, []))
    for fname in scanner_cfg.get("base_names", []):
        target_set.update(name_map.get(fname, []))

    target_files = sorted(target_set, key=str)

    # Load prompt template and hash it once for the cache key
    prompt_template = load_prompt_template(scanner_cfg)
    p_hash = prompt_hash(prompt_template)

    # Filter to files whose content has changed since the cached result.
    # A cache entry is valid when (a) it exists, (b) its content_hash matches
    # the current file content, and (c) its prompt_hash matches the current
    # prompt template. --rescan skips this check entirely.
    pending = []
    for f in target_files:
        if rescan:
            pending.append(f)
            continue
        try:
            c_hash = content_hash(f.read_bytes())
        except Exception:
            # Unreadable now — re-scan so the new error is cached
            pending.append(f)
            continue
        key = file_key(str(f.relative_to(repo_root)), scanner_cfg["name"], c_hash, p_hash)
        if not (results_dir / f"{key}.json").exists():
            pending.append(f)

    if max_files > 0 and len(pending) > max_files:
        pending = pending[:max_files]

    already_cached = len(target_files) - len(pending)

    print(f"\n{'=' * 60}")
    print(f" Scanner: {scanner_cfg['id']} - {scanner_cfg['label']}")
    print(f"{'=' * 60}")
    print(f"  Extensions: {', '.join(extensions)}")
    mode_label = "read-only tools" if tools else "no tools"
    print(f"  Mode: {mode_label}")
    print(f"  Files total: {len(target_files)} | Cached: {already_cached} | To scan: {len(pending)}")

    if dry_run:
        for f in pending:
            print(f"  {f.relative_to(repo_root)}")
        return scanner_cfg, []

    if not pending:
        print(f"  All files cached. Use --rescan to force.")
        return scanner_cfg, []

    scanned = []
    if progress is not None and pending:
        progress.start_phase("scan", total=len(pending))
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(
                scan_file, f, scanner_cfg, repo_root, results_dir, session_dir,
                prompt_template, p_hash, scan_timeout, rescan, tools,
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
            finally:
                if progress is not None:
                    progress.tick("scan")

    return scanner_cfg, scanned


# ── Report Generation ───────────────────────────────────────────────────────

ALLOWLIST_FILENAME = "allowlist.json"

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# Confidence levels assigned by the phase-3 verifier. Order is high-to-low so
# threshold comparisons can use a single `>=` check.
CONFIDENCE_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Unverified": 0, "Unknown": 0}


def load_allowlist(state_dir: Path) -> list[dict]:
    """Load the false-positive allowlist from <state_dir>/allowlist.json.

    Returns an empty list if the file is missing or unreadable. Each entry is
    a dict that may include:

        scanner:  OWASP ID (e.g. "B3") or "*" for any
        file:     relative file path or "*" for any
        line:     line number, or null/0 to match the whole file
        reason:   free-text justification (shown in the report)
    """
    path = state_dir / ALLOWLIST_FILENAME
    if not path.exists():
        return []
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARN] Allowlist unreadable ({e}); ignoring", file=sys.stderr)
        return []
    if not isinstance(data, dict):
        return []
    sups = data.get("suppressions", [])
    return [s for s in sups if isinstance(s, dict)]


def suppression_match(scanner_id: str, rel: str, line: object, entry: dict) -> bool:
    """True if `entry` matches the given (scanner, file, line)."""
    s = entry.get("scanner", "*")
    if s != "*" and s != scanner_id:
        return False
    f = entry.get("file", "*")
    if f != "*" and f != rel:
        return False
    entry_line = entry.get("line")
    if entry_line is None or entry_line == 0 or entry_line == "":
        return True
    try:
        return int(entry_line) == int(line)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False


def find_suppression(scanner_id: str, rel: str, line: object, allowlist: list[dict]) -> dict | None:
    """Return the first matching suppression entry, or None."""
    for entry in allowlist:
        if suppression_match(scanner_id, rel, line, entry):
            return entry
    return None


def max_severity_at_or_above(counts: dict[str, int], threshold: str) -> int:
    """Count of findings at or above the given severity threshold.

    `threshold="never"` returns 0 regardless of counts — it's the explicit
    opt-out for `--fail-on never`.
    """
    cap = threshold.capitalize()
    if cap == "Never":
        return 0
    order = SEVERITY_ORDER.get(cap, 0)
    return sum(c for sev, c in counts.items() if SEVERITY_ORDER.get(sev, 0) >= order)


def build_report(
    state_dir: Path,
    output_path: Path,
    repo_root: Path,
    scanner_ids: list[str],
    discovery_map: dict[str, list[str]],
    allowlist: list[dict] | None = None,
    confidence_threshold: str | None = None,
    phase_tools: dict[str, bool] | None = None,
) -> dict:
    """Read cached results for all scanners and produce a combined Markdown report.

    When phase-3 verification cache files exist under
    `<state_dir>/<scanner>/verifications/` (or `verifications-tools/` when
    `phase_tools["verify"]` is set), the report overlays each finding with
    the verifier's confidence and exploitability verdict. The optional
    `confidence_threshold` is the minimum confidence required to count a
    finding toward the gated severity totals (and the Overall Risk line used
    for `--fail-on-confidence` gating). Findings below the threshold are still
    listed in the report, but in a separate "Needs Review" section.

    `phase_tools` is a `{phase: bool}` map that tells the report which cache
    directory variant to read from for each phase: `results/` vs
    `results-tools/` for scan, `verifications/` vs `verifications-tools/`
    for verify. The `discovery` key is currently informational only
    (discovery output is loaded from `discovery.json` separately by main,
    not here). Defaults to all-False (no tools) for backward compat.

    Returns a stats dict so callers (e.g. CI) can decide on an exit code without
    re-parsing the markdown: {"severity_counts": {...}, "severity_counts_gated":
    {...} | None, "suppressed_count": N, "error_count": N, "scanned_count": N,
    "confidence_counts": {...}, "needs_review_count": N, "verified_count": N,
    "unverified_count": N}.
    """
    if allowlist is None:
        allowlist = []
    if phase_tools is None:
        phase_tools = {}
    verify_uses_tools = bool(phase_tools.get("verify", False))
    scan_uses_tools = bool(phase_tools.get("scan", False))

    # Pick the verify dir variant once; per-scanner paths below are computed
    # by appending the scanner name to this base.
    verify_dir_variant = "verifications-tools" if verify_uses_tools else "verifications"
    results_dir_variant = "results-tools" if scan_uses_tools else "results"

    # If any scanner has a verification directory in the chosen variant,
    # pre-load the verify prompt hash so the per-file lookup key matches what
    # the verifier wrote.
    verify_prompt_hash_value: str | None = None
    has_verification_data = False
    for sid in scanner_ids:
        cfg = OWASP_SCANNERS[sid]
        if (state_dir / cfg["name"] / verify_dir_variant).exists():
            has_verification_data = True
            break
    if has_verification_data:
        verify_prompt_hash_value = prompt_hash(load_verify_prompt())

    severity_counts_global = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    confidence_counts_global = {"High": 0, "Medium": 0, "Low": 0, "Unverified": 0}
    needs_review_global: list[dict] = []
    suppressed_count_global = 0
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
    if phase_tools:
        def _mode(enabled: bool) -> str:
            return f"read-only ({','.join(READONLY_TOOLS)})" if enabled else "none"
        w(f"**Tools:** discovery={_mode(bool(phase_tools.get('discovery', False)))} · "
          f"scan={_mode(scan_uses_tools)} · "
          f"verify={_mode(verify_uses_tools)}")
    if has_verification_data:
        w("**Verification:** phase-3 verdicts included (see confidence per finding)")
    if confidence_threshold is not None and confidence_threshold != "never":
        w(f"**Confidence gate:** only findings with `confidence >= {confidence_threshold}` count toward severity totals and Overall Risk")
    w()

    global_vuln_count = 0
    global_error_count = 0
    global_clean_count = 0
    global_scanned_count = 0
    suppressed_findings: list[dict] = []

    # Per-scanner sections
    for scanner_id in scanner_ids:
        cfg = OWASP_SCANNERS[scanner_id]
        scanner_name = cfg["name"]
        results_dir = state_dir / scanner_name / results_dir_variant

        if not results_dir.exists():
            continue

        result_files = sorted(results_dir.glob("*.json"))
        if not result_files:
            continue

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        confidence_counts = {"High": 0, "Medium": 0, "Low": 0, "Unverified": 0}
        suppressed_scanner = 0
        no_vulns = 0
        errors = 0
        files_with_vulns = []
        all_findings = []
        scanner_verify_dir = state_dir / scanner_name / verify_dir_variant

        for rf in result_files:
            try:
                with open(rf) as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                print(f"[WARN] Skipping corrupt cache file {rf}: {e}", file=sys.stderr)
                continue

            rel = data.get("file", "unknown")
            result_raw = data.get("result", {})
            status = data.get("status", "unknown")
            c_hash = data.get("content_hash", "")
            global_scanned_count += 1

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

            if isinstance(result_raw, list):
                parsed = []
                for item in result_raw:
                    if isinstance(item, str):
                        try:
                            item = json.loads(item)
                        except (json.JSONDecodeError, TypeError):
                            print(f"[WARN] Dropping unparseable finding in {rel}: {item[:200]}", file=sys.stderr)
                            continue
                    if isinstance(item, dict):
                        parsed.append(item)
                    else:
                        print(f"[WARN] Dropping non-dict finding in {rel}: {type(item).__name__}", file=sys.stderr)
                result_raw = parsed

            vulns = result_raw if isinstance(result_raw, list) else []

            # Split into active and suppressed findings
            active = []
            for v in vulns:
                line = v.get("line")
                sup = find_suppression(scanner_id, rel, line, allowlist)
                if sup is not None:
                    suppressed_findings.append({
                        "file": rel,
                        "scanner": scanner_id,
                        "vuln": v,
                        "reason": sup.get("reason", "(no reason given)"),
                    })
                    suppressed_scanner += 1
                else:
                    active.append(v)

            # Overlay phase-3 verification: look up a per-(scanner, file)
            # verdict keyed on content hash + findings signature. Missing or
            # stale verifications leave findings as "Unverified" - they are
            # still counted in raw severity totals but not in gated ones.
            verifications: dict[str, dict] = {}
            if verify_prompt_hash_value is not None and vulns and c_hash:
                verifications = load_verification_for_file(
                    scanner_name, rel, c_hash, vulns,
                    scanner_verify_dir, verify_prompt_hash_value,
                ) or {}

            for v in active:
                try:
                    line_key = str(int(v.get("line")))
                except (TypeError, ValueError):
                    line_key = ""
                vfd = verifications.get(line_key) or {}
                conf = vfd.get("confidence", "Unverified")
                if conf not in confidence_counts:
                    conf = "Unverified"
                v["_confidence"] = conf
                v["_exploitable"] = vfd.get("exploitable", "unknown")
                v["_verification_reason"] = vfd.get("verification_reason", "")

            if not vulns:
                no_vulns += 1
                global_clean_count += 1
            else:
                files_with_vulns.append((rel, len(active)))
                for v in active:
                    sev = v.get("severity", "Unknown")
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                        severity_counts_global[sev] = severity_counts_global.get(sev, 0) + 1
                    conf = v.get("_confidence", "Unverified")
                    confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
                    confidence_counts_global[conf] = confidence_counts_global.get(conf, 0) + 1

                all_findings.append({
                    "file": rel,
                    "status": status,
                    "vulns": active,
                    "result": result_raw,
                })

        suppressed_count_global += suppressed_scanner
        scanner_vuln_count = sum(sev_counts.values())
        global_vuln_count += scanner_vuln_count
        files_with_vulns.sort(key=lambda x: -x[1])

        # Compute per-scanner gated counts (only findings at or above the
        # confidence threshold are kept; the rest are tracked as needs-review).
        # Files with no verification coverage are treated as Unverified and
        # gated out whenever a threshold is set, so an unverified repo never
        # silently passes `--fail-on-confidence`.
        gated_sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        scanner_needs_review: list[dict] = []
        if confidence_threshold is not None and confidence_threshold != "never":
            cutoff = CONFIDENCE_ORDER.get(confidence_threshold.capitalize(), 0)
            for entry in all_findings:
                for v in entry.get("vulns", []):
                    conf = v.get("_confidence", "Unverified")
                    if CONFIDENCE_ORDER.get(conf, 0) >= cutoff:
                        sev = v.get("severity", "Unknown")
                        if sev in gated_sev_counts:
                            gated_sev_counts[sev] += 1
                    else:
                        scanner_needs_review.append({
                            "scanner": scanner_id,
                            "file": entry["file"],
                            "vuln": v,
                        })
        needs_review_global.extend(scanner_needs_review)

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
        w(f"| Suppressed (allowlisted) | {suppressed_scanner} |")
        w(f"| Clean files | {no_vulns} |")
        w(f"| Errors | {errors} |")
        if has_verification_data:
            scanner_verified = sum(
                1 for e in all_findings for v in e.get("vulns", [])
                if v.get("_confidence", "Unverified") != "Unverified"
            )
            scanner_active = sum(len(e.get("vulns", [])) for e in all_findings)
            if verify_uses_tools:
                w(f"| Verify tools | read-only ({','.join(READONLY_TOOLS)}) |")
            w(f"| Verification coverage | {scanner_verified}/{scanner_active} |")
            w(f"| ... High confidence | {confidence_counts['High']} |")
            w(f"| ... Medium confidence | {confidence_counts['Medium']} |")
            w(f"| ... Low confidence | {confidence_counts['Low']} |")
            w(f"| ... Unverified | {confidence_counts['Unverified']} |")
            if confidence_threshold is not None and confidence_threshold != "never":
                gated_total = sum(gated_sev_counts.values())
                w(f"| Gated by confidence >= {confidence_threshold} | {gated_total} |")
                w(f"| Needs review (below threshold) | {len(scanner_needs_review)} |")
        w()

        if files_with_vulns:
            w("### Vulnerable Files")
            w()
            if has_verification_data:
                w("| File | Vulnerabilities | High-conf | Medium-conf | Low-conf | Unverified |")
                w("|------|----------------|-----------|-------------|----------|------------|")
                for rel, _ in files_with_vulns[:20]:
                    counts = {"High": 0, "Medium": 0, "Low": 0, "Unverified": 0}
                    for entry in all_findings:
                        if entry["file"] != rel:
                            continue
                        for v in entry.get("vulns", []):
                            counts[v.get("_confidence", "Unverified")] = (
                                counts.get(v.get("_confidence", "Unverified"), 0) + 1
                            )
                    total = sum(counts.values())
                    w(
                        f"| `{rel}` | {total} | {counts['High']} | "
                        f"{counts['Medium']} | {counts['Low']} | {counts['Unverified']} |"
                    )
                w()
            else:
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
                    conf = v.get("_confidence", "Unverified")
                    exploitable = v.get("_exploitable", "unknown")
                    reason = v.get("_verification_reason", "")

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
                    if has_verification_data:
                        if conf == "High":
                            conf_glyph = "✅"
                        elif conf == "Medium":
                            conf_glyph = "🟡"
                        elif conf == "Low":
                            conf_glyph = "⚠️"
                        else:
                            conf_glyph = "❔"
                        w(f"*Verification:* {conf_glyph} **{conf} confidence**, exploitable: `{exploitable}`")
                        if reason:
                            w(f"  — {reason}")
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
    w(f"| Suppressed (allowlisted) | {suppressed_count_global} |")
    w(f"| Clean files | {global_clean_count} |")
    w(f"| Errors/timeouts | {global_error_count} |")
    if has_verification_data:
        verified_total = (
            confidence_counts_global['High']
            + confidence_counts_global['Medium']
            + confidence_counts_global['Low']
        )
        active_total = verified_total + confidence_counts_global['Unverified']
        w(f"| Verification coverage | {verified_total}/{active_total} |")
        w(f"| ... High confidence | {confidence_counts_global['High']} |")
        w(f"| ... Medium confidence | {confidence_counts_global['Medium']} |")
        w(f"| ... Low confidence | {confidence_counts_global['Low']} |")
        w(f"| ... Unverified | {confidence_counts_global['Unverified']} |")
    w()

    if suppressed_findings:
        w("### Suppressed Findings (allowlist)")
        w()
        w("<details><summary>Toggle suppressed findings</summary>")
        w()
        w("These findings matched an entry in `.security_scan/allowlist.json` and")
        w("are excluded from severity counts and the Overall Risk calculation.")
        w("They remain visible here for auditability.")
        w()
        for sf in suppressed_findings:
            v = sf["vuln"]
            line_num = v.get("line", "?")
            severity = v.get("severity", "Unknown")
            w(f"- `{sf['scanner']}` `{sf['file']}:{line_num}` — `{severity}` — {sf['reason']}")
        w()
        w("</details>")
        w()

    # OWASP risk matrix
    # When a confidence threshold is set, the heatmap reflects the gated
    # counts (only findings at or above the threshold). Otherwise it shows
    # the raw severity totals, preserving the original behavior.
    heatmap_counts = severity_counts_global
    if confidence_threshold is not None and confidence_threshold != "never":
        heatmap_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for item in needs_review_global:
            sev = item["vuln"].get("severity", "Unknown")
            if sev in heatmap_counts:
                heatmap_counts[sev] += 1
        heatmap_counts = {
            sev: severity_counts_global[sev] - heatmap_counts[sev]
            for sev in heatmap_counts
        }
    w("### Risk Heatmap")
    w()
    if (confidence_threshold is not None and confidence_threshold != "never"):
        w(f"*Counts reflect findings with `confidence >= {confidence_threshold}`. "
          f"Lower-confidence findings are listed under [Needs Review](#needs-review).*")
        w()
    w("| Severity | Count | Risk Level |")
    w("|----------|-------|------------|")
    crit = heatmap_counts["Critical"]
    high = heatmap_counts["High"]
    med = heatmap_counts["Medium"]
    low = heatmap_counts["Low"]
    w(f"| Critical | {crit} | {'🔴 CRITICAL' if crit > 0 else '🟢 Clear'} |")
    w(f"| High     | {high} | {'🟠 HIGH' if high > 0 else '🟢 Clear'} |")
    w(f"| Medium   | {med} | {'🟡 MEDIUM' if med > 0 else '🟢 Clear'} |")
    w(f"| Low      | {low} | {'🟢 LOW' if low == 0 else '⚠️ Review'} |")
    w()

    if crit > 0:
        overall = "🔴 CRITICAL"
    elif high > 0:
        overall = "🟠 HIGH"
    elif med > 0:
        overall = "🟡 MEDIUM"
    elif global_error_count > 0 or global_scanned_count == 0:
        overall = "⚠️ INCONCLUSIVE (no signal — check errors)"
    else:
        overall = "🟢 LOW (clean)"
    w(f"**Overall Risk:** {overall}")
    w()

    # Needs Review section - only emitted when confidence-based gating is in
    # effect, OR when a verification pass produced non-High verdicts the user
    # should be aware of. Findings here are below the gate and are NOT counted
    # toward severity totals or the Overall Risk line above.
    if needs_review_global:
        w("---")
        w()
        w("## Needs Review")
        w()
        if confidence_threshold is not None and confidence_threshold != "never":
            w(f"The following findings are below the `{confidence_threshold}` "
              f"confidence threshold (or are unverified). They are excluded from "
              f"the severity counts and the Overall Risk line above. Promote them "
              f"to the allowlist (`.security_scan/allowlist.json`) once triaged, "
              f"or re-run with `--reverify` after addressing the underlying issue.")
        else:
            w("The following findings are below `High` confidence. They are still "
              "counted in the severity totals above, but are surfaced here so a "
              "human can triage them. Promote confirmed false positives to the "
              "allowlist, or run with `--fail-on-confidence` to gate CI on High-"
              "confidence findings only.")
        w()
        w("<details><summary>Toggle needs-review findings</summary>")
        w()
        for item in needs_review_global:
            v = item["vuln"]
            conf = v.get("_confidence", "Unverified")
            exploitable = v.get("_exploitable", "unknown")
            reason = v.get("_verification_reason", "")
            scanner_label = OWASP_SCANNERS[item["scanner"]]["label"]
            line_num = v.get("line", "?")
            severity = v.get("severity", "Unknown")
            w(f"- `{item['scanner']}` `{item['file']}:{line_num}` — `{severity}` — "
              f"confidence: **{conf}**, exploitable: `{exploitable}`")
            if reason:
                w(f"  - _{reason}_")
        w()
        w("</details>")
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
    print(f"  Suppressed:          {suppressed_count_global}")
    print(f"  Clean files:         {global_clean_count}")
    print(f"  Errors/timeouts:     {global_error_count}")
    if has_verification_data:
        verified_total = (
            confidence_counts_global['High']
            + confidence_counts_global['Medium']
            + confidence_counts_global['Low']
        )
        active_total = verified_total + confidence_counts_global['Unverified']
        print()
        print("  Verification:")
        print(f"    Coverage:        {verified_total}/{active_total}")
        print(f"    High confidence: {confidence_counts_global['High']}")
        print(f"    Medium:          {confidence_counts_global['Medium']}")
        print(f"    Low:             {confidence_counts_global['Low']}")
        print(f"    Unverified:      {confidence_counts_global['Unverified']}")
        if confidence_threshold is not None and confidence_threshold != "never":
            print(f"    Needs review:    {len(needs_review_global)}")
    print()
    print(f"  Report: {output_path}")

    # Build gated severity counts: same totals but with findings below the
    # confidence threshold (or unverified) removed. None when no threshold is
    # set so callers can fall back to the raw counts.
    gated_severity_counts: dict[str, int] | None = None
    if confidence_threshold is not None and confidence_threshold != "never":
        gated_severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for sev in gated_severity_counts:
            gated_severity_counts[sev] = severity_counts_global.get(sev, 0)
        for item in needs_review_global:
            sev = item["vuln"].get("severity", "Unknown")
            if sev in gated_severity_counts:
                gated_severity_counts[sev] -= 1

    return {
        "severity_counts": dict(severity_counts_global),
        "severity_counts_gated": (
            dict(gated_severity_counts) if gated_severity_counts is not None else None
        ),
        "confidence_counts": dict(confidence_counts_global),
        "needs_review_count": len(needs_review_global),
        "verified_count": sum(
            confidence_counts_global[k] for k in ("High", "Medium", "Low")
        ),
        "unverified_count": confidence_counts_global['Unverified'],
        "suppressed_count": suppressed_count_global,
        "error_count": global_error_count,
        "scanned_count": global_scanned_count,
    }


# ── Tabular (CSV/TSV) report builder ────────────────────────────────────────

CSV_FIELDNAMES = [
    "scanner", "scanner_label", "file", "line", "severity",
    "code", "explanation", "fix", "confidence", "exploitable",
    "verification_reason", "status", "suppression_reason",
]

REPORT_FORMAT_EXTENSIONS = {"md": ".md", "csv": ".csv", "tsv": ".tsv"}


def output_path_for_format(path: Path, report_format: str) -> Path:
    """Return `path` with an extension that matches `report_format`.

    If `path` already has the right extension, it is returned unchanged. If
    the extension is missing or differs, it is replaced (not appended) so
    e.g. `--output report.md --report-format csv` produces `report.csv`
    rather than a misleading `report.md.csv`.
    """
    expected = REPORT_FORMAT_EXTENSIONS.get(report_format, ".md")
    if path.suffix.lower() == expected:
        return path
    return path.with_suffix(expected)


def build_csv_report(
    state_dir: Path,
    output_path: Path,
    repo_root: Path,
    scanner_ids: list[str],
    discovery_map: dict[str, list[str]],
    allowlist: list[dict] | None = None,
    confidence_threshold: str | None = None,
    delimiter: str = ",",
    phase_tools: dict[str, bool] | None = None,
) -> dict:
    """Produce a CSV/TSV report with one row per finding, suitable for
    importing into a spreadsheet. Mirrors `build_report`'s allowlist and
    verification overlays but writes a flat row per finding instead of a
    multi-section markdown document.

    Columns (in order):

      scanner, scanner_label, file, line, severity, code, explanation, fix,
      confidence, exploitable, verification_reason, status,
      suppression_reason

    `status` is one of:

      - "active"        = non-suppressed finding at or above the confidence
                          threshold (or any non-suppressed finding when no
                          threshold is set)
      - "needs_review"  = non-suppressed finding below the confidence threshold
                          (only emitted when a threshold is set; excluded from
                          severity_counts_gated and Overall Risk)
      - "suppressed"    = allowlist hit; `suppression_reason` carries the reason
      - "error" / "timeout" = per-file scan failure (no finding data)

    The `confidence` and `exploitable` columns are blank when no verification
    has been run for that file. The function returns the same stats dict
    shape as `build_report` so the CLI's `--fail-on` / `--fail-on-confidence`
    logic can stay format-agnostic.

    `phase_tools` is a `{phase: bool}` map that selects the cache dir
    variants to read from, matching `build_report`.
    """
    import csv  # local import keeps the markdown-only path off this dep's load

    if allowlist is None:
        allowlist = []
    if phase_tools is None:
        phase_tools = {}
    verify_uses_tools = bool(phase_tools.get("verify", False))
    scan_uses_tools = bool(phase_tools.get("scan", False))
    verify_dir_variant = "verifications-tools" if verify_uses_tools else "verifications"
    results_dir_variant = "results-tools" if scan_uses_tools else "results"

    verify_prompt_hash_value: str | None = None
    for sid in scanner_ids:
        cfg = OWASP_SCANNERS[sid]
        if (state_dir / cfg["name"] / verify_dir_variant).exists():
            verify_prompt_hash_value = prompt_hash(load_verify_prompt())
            break

    has_threshold = confidence_threshold is not None and confidence_threshold != "never"
    cutoff = (
        CONFIDENCE_ORDER.get(confidence_threshold.capitalize(), 0)
        if has_threshold else 0
    )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    confidence_counts = {"High": 0, "Medium": 0, "Low": 0, "Unverified": 0}
    gated_severity_counts: dict[str, int] | None = (
        {"Critical": 0, "High": 0, "Medium": 0, "Low": 0} if has_threshold else None
    )
    suppressed_count = 0
    needs_review_count = 0
    error_count = 0
    scanned_count = 0
    rows: list[dict] = []

    for scanner_id in scanner_ids:
        cfg = OWASP_SCANNERS[scanner_id]
        scanner_name = cfg["name"]
        scanner_label = cfg["label"]
        results_dir = state_dir / scanner_name / results_dir_variant
        verify_dir = state_dir / scanner_name / verify_dir_variant

        if not results_dir.exists():
            continue

        for rf in sorted(results_dir.glob("*.json")):
            try:
                with open(rf) as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                print(f"[WARN] Skipping corrupt cache file {rf}: {e}", file=sys.stderr)
                continue

            rel = data.get("file", "unknown")
            result_raw = data.get("result", {})
            status = data.get("status", "unknown")
            c_hash = data.get("content_hash", "")
            scanned_count += 1

            if status in ("error", "timeout"):
                error_count += 1
                rows.append({
                    "scanner": scanner_id,
                    "scanner_label": scanner_label,
                    "file": rel,
                    "line": "",
                    "severity": "",
                    "code": "",
                    "explanation": "",
                    "fix": "",
                    "confidence": "",
                    "exploitable": "",
                    "verification_reason": "",
                    "status": status,
                    "suppression_reason": "",
                })
                continue

            if isinstance(result_raw, str):
                try:
                    result_raw = json.loads(result_raw)
                except (json.JSONDecodeError, TypeError):
                    pass

            if isinstance(result_raw, list):
                parsed = []
                for item in result_raw:
                    if isinstance(item, str):
                        try:
                            item = json.loads(item)
                        except (json.JSONDecodeError, TypeError):
                            print(f"[WARN] Dropping unparseable finding in {rel}: {item[:200]}", file=sys.stderr)
                            continue
                    if isinstance(item, dict):
                        parsed.append(item)
                    else:
                        print(f"[WARN] Dropping non-dict finding in {rel}: {type(item).__name__}", file=sys.stderr)
                result_raw = parsed

            vulns = result_raw if isinstance(result_raw, list) else []

            verifications: dict[str, dict] = {}
            if verify_prompt_hash_value is not None and vulns and c_hash:
                verifications = load_verification_for_file(
                    scanner_name, rel, c_hash, vulns,
                    verify_dir, verify_prompt_hash_value,
                ) or {}

            for v in vulns:
                raw_line = v.get("line")
                if isinstance(raw_line, bool):
                    line_str = ""
                elif raw_line is None:
                    line_str = ""
                else:
                    line_str = str(raw_line)

                sup = find_suppression(scanner_id, rel, raw_line, allowlist)

                try:
                    line_key = str(int(raw_line))
                except (TypeError, ValueError):
                    line_key = ""
                vfd = verifications.get(line_key) or {}
                conf = vfd.get("confidence", "Unverified")
                if conf not in CONFIDENCE_ORDER:
                    conf = "Unverified"

                base_row = {
                    "scanner": scanner_id,
                    "scanner_label": scanner_label,
                    "file": rel,
                    "line": line_str,
                    "severity": v.get("severity", ""),
                    "code": v.get("code", ""),
                    "explanation": v.get("explanation", ""),
                    "fix": v.get("fix", ""),
                    "confidence": "" if conf == "Unverified" else conf,
                    "exploitable": vfd.get("exploitable", ""),
                    "verification_reason": vfd.get("verification_reason", ""),
                }

                if sup is not None:
                    rows.append({**base_row,
                                 "status": "suppressed",
                                 "suppression_reason": sup.get("reason", "")})
                    suppressed_count += 1
                    continue

                # Non-suppressed: contributes to raw severity_counts. The
                # status column tells the user whether the row is gated in
                # (active) or gated out (needs_review) under the current
                # confidence threshold; severity_counts_gated below tracks
                # only the active subset.
                sev = v.get("severity", "")
                is_below = CONFIDENCE_ORDER.get(conf, 0) < cutoff
                if sev in severity_counts:
                    severity_counts[sev] += 1
                if has_threshold and is_below:
                    rows.append({**base_row,
                                 "status": "needs_review",
                                 "suppression_reason": ""})
                    needs_review_count += 1
                else:
                    rows.append({**base_row,
                                 "status": "active",
                                 "suppression_reason": ""})
                    if gated_severity_counts is not None and sev in gated_severity_counts:
                        gated_severity_counts[sev] += 1
                confidence_counts[conf] = confidence_counts.get(conf, 0) + 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=CSV_FIELDNAMES, delimiter=delimiter,
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    active_count = sum(1 for r in rows if r["status"] == "active")
    needs_review_rows = sum(1 for r in rows if r["status"] == "needs_review")
    suppressed_rows = sum(1 for r in rows if r["status"] == "suppressed")
    error_rows = sum(1 for r in rows if r["status"] in ("error", "timeout"))

    print()
    print("=" * 60)
    print(f" Report written ({'TSV' if delimiter == '\t' else 'CSV'})!")
    print("=" * 60)
    print(f"  Rows:           {len(rows)}")
    print(f"  Active:         {active_count}")
    print(f"  Needs review:   {needs_review_rows}")
    print(f"  Suppressed:     {suppressed_rows}")
    print(f"  Errors:         {error_rows}")
    print()
    print(f"  Report: {output_path}")

    return {
        "severity_counts": severity_counts,
        "severity_counts_gated": gated_severity_counts,
        "confidence_counts": confidence_counts,
        "needs_review_count": needs_review_count,
        "verified_count": sum(confidence_counts[k] for k in ("High", "Medium", "Low")),
        "unverified_count": confidence_counts["Unverified"],
        "suppressed_count": suppressed_count,
        "error_count": error_count,
        "scanned_count": scanned_count,
    }


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
    parser.add_argument("--phase", type=int, default=0, help="Run only phase N (1=discovery, 2=scan, 3=verify). 0=all selected phases.")
    parser.add_argument("--concurrency", type=int, default=4, help="Max parallel scans (default: 4)")
    parser.add_argument("--max-files", type=int, default=0, help="Limit files per scanner (default: all)")
    parser.add_argument("--output", default=None, help="Report output path (default: security_report.md)")
    parser.add_argument("--state-dir", default=None, help="Directory for cached results (default: .security_scan)")
    parser.add_argument("--dry-run", action="store_true", help="List files without scanning")
    parser.add_argument("--rescan", action="store_true", help="Re-scan all files even if cached")
    parser.add_argument("--redetect", action="store_true", help="Re-run discovery even if cached")
    parser.add_argument(
        "--formats",
        default=None,
        help="Comma-separated extensions to override the per-scanner base (e.g. '.sql,.sh')",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=180,
        help="Per-file pi call timeout in seconds (default: 180)",
    )
    parser.add_argument(
        "--discovery-timeout",
        type=int,
        default=240,
        help="Discovery pi call timeout in seconds (default: 240)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["never", "low", "medium", "high", "critical"],
        default="never",
        help="Exit non-zero if a finding at or above this severity is found "
             "(default: never — always exit 0)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Add a phase-3 verification pass: for every file with findings, "
             "ask the model to rate each finding's confidence and "
             "exploitability in the context of the file as written. Results "
             "are cached and overlaid onto the report.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Force re-verification of all findings, ignoring the verify cache "
             "(analogous to --rescan for phase 2).",
    )
    parser.add_argument(
        "--verify-timeout",
        type=int,
        default=300,
        help="Per-file verification pi call timeout in seconds (default: 300). "
             "Longer than --scan-timeout because the verifier uses read-only "
             "tools by default and may chase callers/sanitizers across files.",
    )
    parser.add_argument(
        "--discovery-tools",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Give phase 1 (discovery) read-only tools (read,grep,find,ls). "
             "Default: on. Disable with --no-discovery-tools.",
    )
    parser.add_argument(
        "--scan-tools",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Give phase 2 (scan) read-only tools (read,grep,find,ls). "
             "Default: off (scan is high-recall single-file; tools add cost "
             "and prompt-injection surface). Enable with --scan-tools.",
    )
    parser.add_argument(
        "--verify-tools",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Give phase 3 (verify) read-only tools (read,grep,find,ls). "
             "Default: on. Disable with --no-verify-tools for the original "
             "file-as-written verifier.",
    )
    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show an in-place stderr progress line with per-phase counters "
             "and ETA. Default: on. Disable with --no-progress for quiet CI "
             "logs or batch runs.",
    )
    parser.add_argument(
        "--fail-on-confidence",
        choices=["never", "low", "medium", "high"],
        default="never",
        help="Gate the exit code on findings whose verifier confidence is at "
             "or above the given level. Findings below the threshold (or "
             "unverified) are excluded from severity totals and Overall Risk, "
             "and are listed in a Needs Review section. 'never' (default) "
             "disables confidence-based gating entirely.",
    )
    parser.add_argument(
        "--report-format",
        choices=["md", "csv", "tsv"],
        default="md",
        help="Output format for the report. 'md' (default) writes the human-"
             "readable markdown report. 'csv' and 'tsv' write one row per "
             "finding (active, needs_review, and suppressed) for spreadsheet "
             "import; the file extension on --output is auto-adjusted to "
             "match. Both formats apply the same allowlist and verification "
             "overlays and the same --fail-on / --fail-on-confidence gates.",
    )

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

    # Validate phase / verify flag combinations. --verify is meaningless
    # without scan results, and --phase 3 is contradictory when explicitly
    # disabled. Catching these up front produces a clearer error than letting
    # the run silently no-op.
    run_verify = bool(args.verify) or args.phase == 3
    if args.verify and args.phase == 1:
        print("--verify requires scan results; cannot combine with --phase 1")
        sys.exit(1)
    if args.phase == 3 and not args.verify:
        # --phase 3 implies verification; the user's CLI doesn't need a
        # separate --verify in that case, so this is just a friendly default.
        run_verify = True

    # Resolve paths
    repo_root = Path.cwd()
    state_dir = Path(args.state_dir) if args.state_dir else repo_root / ".security_scan"
    default_output = {"md": "security_report.md",
                      "csv": "security_report.csv",
                      "tsv": "security_report.tsv"}[args.report_format]
    raw_output_path = Path(args.output) if args.output else repo_root / default_output
    output_path = output_path_for_format(raw_output_path, args.report_format)
    # Per-phase tools config. The default per the user is: discovery on,
    # scan off, verify on. Each flag has a BooleanOptionalAction so the
    # user can flip any of them with --no-<phase>-tools. The tools list
    # (read-only) is fixed; only the per-phase on/off is user-configurable.
    phase_tools = {
        "discovery": bool(args.discovery_tools),
        "scan": bool(args.scan_tools),
        "verify": bool(args.verify_tools),
    }
    phase_tool_lists = {
        phase: READONLY_TOOLS if enabled else None
        for phase, enabled in phase_tools.items()
    }
    discovery_cache = state_dir / (
        "discovery-tools.json" if phase_tools["discovery"] else "discovery.json"
    )
    session_dir = state_dir / "sessions"

    state_dir.mkdir(parents=True, exist_ok=True)
    session_dir.mkdir(parents=True, exist_ok=True)

    phase_label = (
        "1 (discovery)" if args.phase == 1
        else "2 (scan)" if args.phase == 2
        else "3 (verify)" if args.phase == 3
        else "1+2+verify" if run_verify
        else "1+2"
    )

    print(f"Repository:  {repo_root}")
    print(f"Scanners:    {', '.join(f'{sid} ({OWASP_SCANNERS[sid]["label"]})' for sid in scanner_ids)}")
    print(f"State:       {state_dir}")
    print(f"Output:      {output_path} ({args.report_format.upper()})")
    print(f"Phase:       {phase_label}")
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

    # Progress tracker. On a TTY it refreshes a single line in place with
    # \r; off-TTY it writes one line per update so CI logs are grep-able.
    # Wrapped in try/finally so the renderer is always stopped and the
    # final line is emitted — even on sys.exit() from the report gates.
    progress = ProgressTracker(enabled=bool(args.progress))
    try:
        # ── Phase 1: Discovery ──
        discovery_map = {}
        if args.phase == 0 or args.phase == 1:
            discovery_map = run_discovery(
                repo_root, ext_map, name_map,
                discovery_cache, session_dir,
                redetect=args.redetect,
                timeout=args.discovery_timeout,
                tools=phase_tool_lists["discovery"],
            )
    
        if args.phase == 1:
            print("\nDiscovery complete. Run with --phase 2 or no --phase flag to scan.")
            return
    
        # ── If phase 2 or 3, load discovery from cache ──
        if args.phase in (2, 3) and not discovery_map:
            if discovery_cache.exists():
                try:
                    with open(discovery_cache) as f:
                        discovery_map = json.load(f)
                except (OSError, json.JSONDecodeError) as e:
                    print(f"Discovery cache unreadable ({e}). Run with --phase 1 or --redetect first.")
                    sys.exit(1)
            else:
                print("No discovery cache found. Run with --phase 1 or no --phase flag first.")
                sys.exit(1)
    
        # ── Phase 2: Scan (skipped when --phase 3: run verification only) ──
        all_results = []
        if args.phase != 3:
            print()
            if args.phase == 2:
                print("Phase 2: Scanning (using cached discovery)...")
            else:
                print("Phase 2: Scanning...")
    
            format_override = None
            if args.formats:
                format_override = [e if e.startswith(".") else f".{e}" for e in args.formats.split(",")]
    
            for scanner_id in scanner_ids:
                cfg = OWASP_SCANNERS[scanner_id]
                _, results = run_scanner(
                    scanner_id, cfg, ext_map, name_map, discovery_map,
                    repo_root, state_dir, session_dir,
                    args.concurrency, args.max_files, args.rescan, args.dry_run,
                    format_override=format_override,
                    scan_timeout=args.scan_timeout,
                    tools=phase_tool_lists["scan"],
                    progress=progress,
            )
            all_results.extend(results)
    
        # ── Phase 3: Verification (only when --verify or --phase 3) ──
        if run_verify and not args.dry_run:
            # For phase 3, verify even with --dry-run is a no-op (we'd be listing
            # files that may or may not have scan results yet).
            # Look in the results dir that matches the current scan tools config,
            # so the verifier and the scanner it judges are in lockstep.
            results_dir_for_verify = (
                "results-tools" if phase_tools["scan"] else "results"
            )
            any_results = False
            for sid in scanner_ids:
                cfg = OWASP_SCANNERS[sid]
                if (state_dir / cfg["name"] / results_dir_for_verify).exists():
                    any_results = True
                    break
            if not any_results:
                if args.phase == 3:
                    print("No scan results found. Run with --phase 2 (or no --phase flag) first.")
                    sys.exit(1)
                else:
                    print("[VERIFY] No scan results yet; skipping verification pass.")
            else:
                print()
                print("=" * 60)
                print(" Phase 3: Verifying findings...")
                print("=" * 60)
                for scanner_id in scanner_ids:
                    cfg = OWASP_SCANNERS[scanner_id]
                    _, vresults = run_verification(
                        scanner_id, cfg, repo_root, state_dir, session_dir,
                        args.concurrency, args.reverify, args.dry_run,
                        verify_timeout=args.verify_timeout,
                        tools=phase_tool_lists["verify"],
                        scan_uses_tools=phase_tools["scan"],
                        progress=progress,
                    )
                    # Verification results are read back from disk in build_report
                    # via load_verification_for_file, so we don't need to forward
                    # them here. The list is kept for parity with the scan loop.
                    all_results.extend(vresults)
    
        # ── Report ──
        if not args.dry_run:
            print()
            print("=" * 60)
            print(f" Building report ({args.report_format.upper()})...")
            print("=" * 60)
            allowlist = load_allowlist(state_dir)
            if allowlist:
                print(f"  Allowlist: {len(allowlist)} suppression(s) loaded")
            confidence_threshold = (
                None if args.fail_on_confidence == "never" else args.fail_on_confidence
            )
            if args.report_format == "md":
                stats = build_report(
                    state_dir, output_path, repo_root, scanner_ids, discovery_map,
                    allowlist, confidence_threshold=confidence_threshold,
                    phase_tools=phase_tools,
                )
            else:
                delimiter = "\t" if args.report_format == "tsv" else ","
                stats = build_csv_report(
                    state_dir, output_path, repo_root, scanner_ids, discovery_map,
                    allowlist, confidence_threshold=confidence_threshold,
                    delimiter=delimiter,
                    phase_tools=phase_tools,
                )
    
            # Exit-code logic for CI integration.
            #
            # Two independent gates can be in play:
            #   --fail-on <sev>           -> raw severity counts
            #   --fail-on-confidence <lvl> -> gated counts (only findings whose
            #                                 verifier confidence is at or above
            #                                 the level)
            # Either gate that trips exits 1. The raw --fail-on is intentionally
            # unchanged from the original behavior; --fail-on-confidence is the
            # new knob for confidence-based gating.
            if args.fail_on != "never":
                triggered = max_severity_at_or_above(stats["severity_counts"], args.fail_on)
                if triggered > 0:
                    print(f"\n[FAIL] Findings at or above '{args.fail_on}' threshold "
                          f"({triggered}). Exiting 1.")
                    sys.exit(1)
            if args.fail_on_confidence != "never":
                gated = stats.get("severity_counts_gated") or stats["severity_counts"]
                triggered = sum(gated.values())
                if triggered > 0:
                    print(f"\n[FAIL] {triggered} finding(s) at or above "
                          f"'{args.fail_on_confidence}' confidence threshold. Exiting 1.")
                    sys.exit(1)
            if stats["error_count"] > 0:
                print(f"\n[WARN] {stats['error_count']} file(s) errored during scan. "
                      f"Exiting 2.")
                sys.exit(2)
            sys.exit(0)
    finally:
        progress.stop()


if __name__ == "__main__":
    main()
