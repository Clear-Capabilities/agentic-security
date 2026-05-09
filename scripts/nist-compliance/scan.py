#!/usr/bin/env python3
"""NIST AI 600-1 compliance scanner v2.

Scans a code repository for evidence of the 122 NIST AI 600-1 controls
that are code-testable (column F = Yes or Partial in NIST AI 600-1.xlsx).
Produces an auditor-ready attestation sheet (markdown, CSV, JSON).

Architecture:
  - Manifest parsing  — package.json, requirements.txt, pyproject.toml,
                        Pipfile, go.mod, Cargo.toml, Gemfile, composer.json.
                        A dependency match is the most precise signal.
  - Import detection  — language-specific imports (Python, JS/TS, Go, Ruby).
  - Path matching     — fnmatch globs against file/dir names; test paths
                        score higher than other named paths.
  - Term matching     — case-insensitive word-boundary; weighted by file
                        kind (code > config > doc > comment).
  - Negation filter   — matches inside "we don't / not yet / future work /
                        missing / planned" contexts are skipped.

Scoring (weighted):
  manifest       5.0
  import         4.0
  test_path      3.0
  named_path     2.5
  code_term      2.0
  config_term    1.5
  doc_term       1.0
  comment        0.5

Status is determined by total weight AND distinct signal-type count:

  Yes-bucket controls:
    Compliant    weight >= 8 and signal_types >= 2
    Partial      weight >= 3
    Not Compliant otherwise

  Partial-bucket controls (always also need external attestation):
    Partial                       weight >= 6 and signal_types >= 2
    Partial (limited evidence)    weight >= 2
    Not Compliant                 otherwise
"""

import argparse
import csv
import fnmatch
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import openpyxl
except ImportError:
    sys.stderr.write(
        "ERROR: openpyxl is required. Install with: pip3 install openpyxl\n"
    )
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_XLSX = REPO_ROOT / "NIST AI 600-1.xlsx"
DEFAULT_RULES = Path(__file__).resolve().parent / "evidence-rules.json"

SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".next", ".nuxt", ".cache", "coverage",
    ".idea", ".vscode", "target", ".tox", ".mypy_cache",
    ".pytest_cache", ".agentic-security", ".gradle",
}

SCAN_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".rb", ".php", ".cs", ".swift",
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".md", ".rst", ".txt", ".sh", ".bash", ".zsh",
    ".tf", ".hcl", ".dockerfile",
}
NAMED_FILES = {
    "DOCKERFILE", "MAKEFILE", "README", "LICENSE", "NOTICE",
    "SECURITY", "GOVERNANCE", "GEMFILE", "PIPFILE",
}

SKIP_FILE_SUFFIXES = (
    "scripts/nist-compliance/scan.py",
    "scripts/nist-compliance/evidence-rules.json",
    "skills/nist-ai-600-1/SKILL.md",
    "commands/nist-ai-600-1.md",
    "nist-ai-600-1-attestation.md",
    "nist-ai-600-1-attestation.csv",
    "nist-ai-600-1-attestation.json",
)

MAX_FILE_SIZE = 1_000_000  # 1 MB

# File-kind classification by extension
CODE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".rb", ".php", ".cs",
    ".swift", ".sh", ".bash", ".zsh",
}
CONFIG_EXTS = {
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".tf", ".hcl",
}
DOC_EXTS = {".md", ".rst", ".txt"}

LANG_BY_EXT = {
    ".py": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "ts", ".tsx": "ts",
    ".go": "go",
    ".rb": "ruby",
}

# Test-path patterns (file or directory)
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e)(/|$)"
    r"|(^|/)test_[A-Za-z0-9_]+\.\w+$"
    r"|_test\.\w+$"
    r"|\.test\.\w+$"
    r"|\.spec\.\w+$",
    re.IGNORECASE,
)

# Comment-leading patterns by language
COMMENT_LEADERS = (
    re.compile(r"^\s*#"),               # Python, shell, YAML
    re.compile(r"^\s*//"),              # JS, Go, Java, etc.
    re.compile(r"^\s*\*"),              # JSDoc/JavaDoc continuation
    re.compile(r"^\s*/\*"),             # C-style start
    re.compile(r"^\s*<!--"),            # HTML/Markdown
)

# Generic negation phrases — if found in the same line as a keyword match,
# discount the match. Tuned to minimize false negatives (ie don't be too
# aggressive about skipping legitimate evidence).
NEGATION_RE = re.compile(
    r"\b(?:"
    r"not\s+(?:yet\s+)?(?:implemented|supported|available|done|present|wired|enabled)"
    r"|(?:don'?t|doesn'?t|do\s+not|does\s+not)\s+(?:have|implement|support|use|do|provide)"
    r"|missing"
    r"|lack(?:s|ing)?"
    r"|absent"
    r"|future\s+work"
    r"|planned\s+for"
    r"|would\s+like\s+to"
    r"|need(?:s|ed)?\s+to\s+(?:add|implement|introduce|build)"
    r"|consider\s+(?:adding|using|implementing|introducing)"
    r"|N/?A"
    r"|TBD"
    r"|coming\s+soon"
    r")\b",
    re.IGNORECASE,
)

# Manifest parsers — return set of dependency package names
PYPI_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
GEM_RE = re.compile(r"""gem\s+['"]([^'"]+)['"]""")
GO_REQUIRE_RE = re.compile(r"^\s*([\w./-]+)\s+v[\w.+-]+", re.MULTILINE)
CARGO_DEP_RE = re.compile(r'^\s*([\w-]+)\s*=', re.MULTILINE)
TOML_PROJECT_DEP_RE = re.compile(
    r'^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)', re.MULTILINE,
)


# Import-detection regex per language. Each returns a set of imported
# top-level module names.
PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))",
    re.MULTILINE,
)
JS_IMPORT_RE = re.compile(
    r"""(?:^|\s)(?:import\s+(?:[\w*{}\s,]+from\s+)?|require\s*\(\s*)['"]([^'"\n]+)['"]""",
    re.MULTILINE,
)
GO_IMPORT_RE = re.compile(
    r"""(?:^|\s)import\s+(?:\(\s*((?:[^)]|\n)+?)\)|"([^"]+)")""",
    re.MULTILINE,
)
RUBY_IMPORT_RE = re.compile(
    r"""^\s*require(?:_relative)?\s+['"]([^'"\n]+)['"]""",
    re.MULTILINE,
)


# ------------------------- Data types -------------------------

@dataclass
class Evidence:
    signal_type: str       # 'manifest', 'import', 'test_path', 'named_path',
                           # 'code_term', 'config_term', 'doc_term', 'comment'
    file: str              # repo-relative path
    weight: float
    detail: str            # what was matched
    line: Optional[int] = None


WEIGHTS = {
    "manifest": 5.0,
    "import": 4.0,
    "test_path": 3.0,
    "named_path": 2.5,
    "code_term": 2.0,
    "config_term": 1.5,
    "doc_term": 1.0,
    "comment": 0.5,
}

# Cap on number of hits counted toward weight per (control, signal_type)
# to prevent broad path patterns or repetitive doc mentions from
# overwhelming a multi-signal Compliant judgment.
WEIGHT_CAP_PER_SIGNAL = 5

# Signal tiers — used by the classifier to differentiate "explicit
# capability declaration" (manifest/import) from "circumstantial mention"
# (doc/comment). Multiple strong-tier hits count as much as multi-tier
# evidence for "Compliant" status.
STRONG_SIGNALS = {"manifest", "import"}
MEDIUM_SIGNALS = {"test_path", "named_path", "code_term"}
WEAK_SIGNALS = {"config_term", "doc_term", "comment"}


# ---------------------- Manifest parsing ----------------------

def _read_text(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return None
        with open(path, "rb") as f:
            data = f.read()
        if b"\x00" in data[:8192]:
            return None
        return data.decode("utf-8", errors="replace")
    except (OSError, IOError):
        return None


def parse_manifests(root: str) -> Dict[str, List[str]]:
    """Walk the repo finding dependency manifests. Return
    {package_name_lower: [file_path, ...]}"""
    deps: Dict[str, List[str]] = defaultdict(list)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            base = fn.lower()

            try:
                if base in ("package.json", "package-lock.json"):
                    text = _read_text(full)
                    if not text:
                        continue
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    for key in ("dependencies", "devDependencies",
                                "peerDependencies", "optionalDependencies"):
                        d = data.get(key) or {}
                        if isinstance(d, dict):
                            for pkg in d.keys():
                                deps[pkg.lower()].append(rel)
                    # package-lock.json packages
                    if "packages" in data and isinstance(data["packages"], dict):
                        for pkg_path in data["packages"].keys():
                            if pkg_path.startswith("node_modules/"):
                                pkg = pkg_path.split("node_modules/", 1)[-1]
                                pkg = pkg.split("/node_modules/")[-1]
                                deps[pkg.lower()].append(rel)

                elif base == "requirements.txt" or base.endswith(".requirements.txt"):
                    text = _read_text(full)
                    if not text:
                        continue
                    for line in text.splitlines():
                        line = line.split("#", 1)[0].strip()
                        if not line or line.startswith("-"):
                            continue
                        m = PYPI_NAME_RE.match(line)
                        if m:
                            deps[m.group(1).lower()].append(rel)

                elif base in ("pyproject.toml", "pipfile"):
                    text = _read_text(full)
                    if not text:
                        continue
                    # Capture both PEP 621 array form and tool.poetry form
                    # PEP 621: dependencies = ["foo>=1.0", "bar"]
                    arr_block = re.search(
                        r'dependencies\s*=\s*\[(.*?)\]', text, re.DOTALL,
                    )
                    if arr_block:
                        for m in TOML_PROJECT_DEP_RE.finditer(arr_block.group(1)):
                            deps[m.group(1).lower()].append(rel)
                    # tool.poetry / [project.optional-dependencies]
                    for sect in re.finditer(
                        r"\[(?:tool\.poetry\.dependencies"
                        r"|tool\.poetry\.dev-dependencies"
                        r"|project\.optional-dependencies"
                        r"|packages)\](.*?)(?=\n\[|\Z)",
                        text, re.DOTALL,
                    ):
                        for line in sect.group(1).splitlines():
                            m = re.match(r"\s*([A-Za-z0-9][\w.-]*)\s*=", line)
                            if m and m.group(1).lower() != "python":
                                deps[m.group(1).lower()].append(rel)

                elif base == "go.mod":
                    text = _read_text(full)
                    if not text:
                        continue
                    for m in GO_REQUIRE_RE.finditer(text):
                        # Use last path segment as the canonical name
                        mod = m.group(1)
                        deps[mod.lower()].append(rel)
                        # Also register the last path component
                        last = mod.rsplit("/", 1)[-1].lower()
                        if last != mod.lower():
                            deps[last].append(rel)

                elif base == "cargo.toml":
                    text = _read_text(full)
                    if not text:
                        continue
                    for sect in re.finditer(
                        r"\[(?:dependencies|dev-dependencies|build-dependencies)\](.*?)(?=\n\[|\Z)",
                        text, re.DOTALL,
                    ):
                        for m in CARGO_DEP_RE.finditer(sect.group(1)):
                            deps[m.group(1).lower()].append(rel)

                elif base == "gemfile" or base == "gemfile.lock":
                    text = _read_text(full)
                    if not text:
                        continue
                    for m in GEM_RE.finditer(text):
                        deps[m.group(1).lower()].append(rel)

                elif base == "composer.json":
                    text = _read_text(full)
                    if not text:
                        continue
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    for key in ("require", "require-dev"):
                        d = data.get(key) or {}
                        if isinstance(d, dict):
                            for pkg in d.keys():
                                deps[pkg.lower()].append(rel)
            except Exception:
                continue

    return dict(deps)


# ---------------------- Import detection ----------------------

def detect_imports(content: str, lang: str) -> Set[str]:
    """Return set of imported top-level module/package names (lowercased)."""
    mods: Set[str] = set()

    if lang == "python":
        for m in PY_IMPORT_RE.finditer(content):
            from_part = m.group(1)
            import_part = m.group(2)
            if from_part:
                mods.add(from_part.split(".")[0].lower())
            if import_part:
                for piece in import_part.split(","):
                    piece = piece.strip().split(" as ")[0].strip()
                    if piece:
                        mods.add(piece.split(".")[0].lower())

    elif lang in ("js", "ts"):
        for m in JS_IMPORT_RE.finditer(content):
            spec = m.group(1).strip()
            # Skip relative imports
            if spec.startswith(".") or spec.startswith("/"):
                continue
            # Scoped package "@scope/name" or plain "name/sub"
            if spec.startswith("@"):
                parts = spec.split("/", 2)
                mods.add("/".join(parts[:2]).lower())
            else:
                mods.add(spec.split("/", 1)[0].lower())

    elif lang == "go":
        for m in GO_IMPORT_RE.finditer(content):
            block = m.group(1) or ""
            single = m.group(2) or ""
            for raw in re.findall(r'"([^"]+)"', block) + ([single] if single else []):
                mods.add(raw.lower())
                last = raw.rsplit("/", 1)[-1].lower()
                if last != raw.lower():
                    mods.add(last)

    elif lang == "ruby":
        for m in RUBY_IMPORT_RE.finditer(content):
            mods.add(m.group(1).split("/")[0].lower())

    return mods


# ---------------------- File walking ----------------------

def gather_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            base = os.path.basename(fn)
            ext = os.path.splitext(fn)[1].lower()
            stem = os.path.splitext(base)[0].upper()
            if ext in SCAN_EXTS or stem in NAMED_FILES:
                yield full


def file_kind(rel_path: str) -> str:
    ext = os.path.splitext(rel_path)[1].lower()
    if ext in CODE_EXTS:
        return "code"
    if ext in CONFIG_EXTS:
        return "config"
    if ext in DOC_EXTS:
        return "doc"
    base = os.path.basename(rel_path).upper()
    if base in NAMED_FILES:
        return "doc" if base in {"README", "LICENSE", "NOTICE"} else "config"
    return "other"


# ---------------------- Path matching ----------------------

def path_match(rel_path: str, name_lower: str, patterns: List[str]) -> bool:
    rel_lower = rel_path.lower()
    for pat in patterns:
        pat_lower = pat.lower()
        if fnmatch.fnmatch(rel_lower, pat_lower):
            return True
        if fnmatch.fnmatch(name_lower, pat_lower):
            return True
    return False


def is_test_path(rel_path: str) -> bool:
    return bool(TEST_PATH_RE.search(rel_path))


# ---------------------- Term matching ----------------------

def build_keyword_pattern(keywords: List[str]) -> Optional[re.Pattern]:
    if not keywords:
        return None
    escaped = [re.escape(k) for k in keywords]
    pattern = (
        r"(?i)(?<![A-Za-z0-9_])("
        + "|".join(escaped)
        + r")(?![A-Za-z0-9_])"
    )
    return re.compile(pattern)


def is_comment_line(line: str) -> bool:
    for cre in COMMENT_LEADERS:
        if cre.match(line):
            return True
    return False


def is_negated_context(line: str, match_start: int) -> bool:
    snippet_start = max(0, match_start - 60)
    snippet_end = min(len(line), match_start + 60)
    return bool(NEGATION_RE.search(line[snippet_start:snippet_end]))


# ---------------------- Scan core ----------------------

def scan(
    root: str,
    rules: Dict[str, dict],
    quiet: bool = False,
) -> Tuple[Dict[str, List[Evidence]], Dict[str, List[str]]]:
    """Run the scan. Return (evidence_per_control, manifest_deps)."""
    if not quiet:
        sys.stderr.write("Phase 1: parsing dependency manifests...\n")
    manifest_deps = parse_manifests(root)
    if not quiet and manifest_deps:
        sys.stderr.write(f"  Found {len(manifest_deps)} unique dependencies\n")

    if not quiet:
        sys.stderr.write("Phase 2: walking the file tree...\n")
    files = list(gather_files(root))
    if not quiet:
        sys.stderr.write(f"  {len(files)} candidate files\n")

    if not quiet:
        sys.stderr.write("Phase 3: matching evidence per control...\n")

    # Pre-compile keyword regex per control
    code_term_re: Dict[str, re.Pattern] = {}
    for cid, rule in rules.items():
        # Aggregate all term lists into one regex per control
        terms = []
        for k in ("code_terms", "doc_terms", "config_terms", "keywords"):
            terms.extend(rule.get(k, []))
        # Deduplicate, preserve order
        seen = set()
        dedup_terms = []
        for t in terms:
            if t.lower() not in seen:
                seen.add(t.lower())
                dedup_terms.append(t)
        pat = build_keyword_pattern(dedup_terms)
        if pat is not None:
            code_term_re[cid] = pat

    evidence: Dict[str, List[Evidence]] = {cid: [] for cid in rules.keys()}

    # ---- Phase 4: manifest-based evidence ----
    for cid, rule in rules.items():
        libs = [l.lower() for l in rule.get("libraries", [])]
        seen_libs: Set[str] = set()
        for lib in libs:
            if lib in manifest_deps and lib not in seen_libs:
                seen_libs.add(lib)
                src = manifest_deps[lib][0]
                evidence[cid].append(Evidence(
                    signal_type="manifest",
                    file=src,
                    weight=WEIGHTS["manifest"],
                    detail=f"library: {lib}",
                ))

    # ---- Phase 5: per-file evidence ----
    for filepath in files:
        norm = filepath.replace("\\", "/")
        if any(norm.endswith(suf) for suf in SKIP_FILE_SUFFIXES):
            continue

        content = _read_text(filepath)
        if content is None:
            continue

        rel = os.path.relpath(filepath, root).replace("\\", "/")
        rel_lower = rel.lower()
        name_lower = os.path.basename(rel).lower()
        ext = os.path.splitext(rel)[1].lower()
        kind = file_kind(rel)
        lang = LANG_BY_EXT.get(ext)
        is_test = is_test_path(rel)

        # Detect imports once per file
        imports: Set[str] = detect_imports(content, lang) if lang else set()

        for cid, rule in rules.items():
            # ---- import-based ----
            for imp in rule.get("imports", []):
                imp_lower = imp.lower()
                if imp_lower in imports:
                    evidence[cid].append(Evidence(
                        signal_type="import",
                        file=rel,
                        weight=WEIGHTS["import"],
                        detail=f"import: {imp_lower}",
                    ))

            # Also catch library names appearing as imports (covers the
            # common case where the package name == import name)
            for lib in rule.get("libraries", []):
                key = lib.lower().replace("-", "_")
                if key in imports and key != lib.lower():
                    pass  # already counted by exact-match below
                if lib.lower() in imports or key in imports:
                    # Avoid double-counting if the library was already
                    # matched in the manifest (manifest evidence is enough)
                    has_manifest = any(
                        e.signal_type == "manifest" and lib.lower() in e.detail
                        for e in evidence[cid]
                    )
                    if not has_manifest:
                        evidence[cid].append(Evidence(
                            signal_type="import",
                            file=rel,
                            weight=WEIGHTS["import"],
                            detail=f"import: {lib.lower()}",
                        ))

            # ---- path-based ----
            paths = rule.get("paths", [])
            test_paths = rule.get("test_paths", [])
            if paths and path_match(rel_lower, name_lower, paths):
                if is_test:
                    evidence[cid].append(Evidence(
                        signal_type="test_path",
                        file=rel,
                        weight=WEIGHTS["test_path"],
                        detail="test path match",
                    ))
                else:
                    evidence[cid].append(Evidence(
                        signal_type="named_path",
                        file=rel,
                        weight=WEIGHTS["named_path"],
                        detail="path match",
                    ))
            elif test_paths and path_match(rel_lower, name_lower, test_paths):
                evidence[cid].append(Evidence(
                    signal_type="test_path",
                    file=rel,
                    weight=WEIGHTS["test_path"],
                    detail="test path match",
                ))

            # ---- term-based ----
            pat = code_term_re.get(cid)
            if pat is None:
                continue
            kw_hits_for_file = 0
            for m in pat.finditer(content):
                if kw_hits_for_file >= 5:
                    break
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.end())
                if line_end == -1:
                    line_end = len(content)
                line = content[line_start:line_end]
                rel_pos = m.start() - line_start

                if is_negated_context(line, rel_pos):
                    continue

                line_num = content.count("\n", 0, m.start()) + 1
                term = m.group(0)

                if is_comment_line(line):
                    sig = "comment"
                elif kind == "code":
                    sig = "code_term"
                elif kind == "config":
                    sig = "config_term"
                elif kind == "doc":
                    sig = "doc_term"
                else:
                    sig = "doc_term"

                evidence[cid].append(Evidence(
                    signal_type=sig,
                    file=rel,
                    weight=WEIGHTS[sig],
                    detail=f"`{term}`",
                    line=line_num,
                ))
                kw_hits_for_file += 1

    return evidence, manifest_deps


# ---------------------- Classification ----------------------

def classify(control: dict, ev_list: List[Evidence]) -> Tuple[str, bool]:
    """Return (status, external_attestation_required).

    Classification rules:
      Compliant requires either
        (a) ≥ 2 strong-tier hits (manifest/import) AND weight ≥ 8, or
        (b) strong + (medium or weak) tier mix AND weight ≥ 8, or
        (c) ≥ 3 distinct signal types AND weight ≥ 10.
      Partial requires either
        (a) ≥ 1 strong-tier hit, or
        (b) weight ≥ 3 (Yes-bucket) / 4 (Partial-bucket) with ≥ 2 types.
      Partial (limited evidence) is reserved for Partial-bucket controls
      with weight ≥ 2 but below the full-Partial threshold.
      Otherwise Not Compliant.
    """
    bucket = control["code_testable"]
    if not ev_list:
        if bucket == "Yes":
            return "Not Compliant", False
        if bucket == "Partial":
            return "Not Compliant", True
        return "N/A", False

    # Group evidence by signal type and cap each type's contribution.
    by_type: Dict[str, List[Evidence]] = defaultdict(list)
    for e in ev_list:
        by_type[e.signal_type].append(e)

    weight = 0.0
    n_strong = 0
    n_medium = 0
    n_weak = 0
    for sig, items in by_type.items():
        items_sorted = sorted(items, key=lambda e: -e.weight)
        kept = items_sorted[:WEIGHT_CAP_PER_SIGNAL]
        weight += sum(e.weight for e in kept)
        cnt = len(kept)
        if sig in STRONG_SIGNALS:
            n_strong += cnt
        elif sig in MEDIUM_SIGNALS:
            n_medium += cnt
        else:
            n_weak += cnt

    n_types = len(by_type)
    weak_only = set(by_type.keys()).issubset(WEAK_SIGNALS)

    if bucket == "Yes":
        # Compliant: any of three paths to clear evidence
        if n_strong >= 2 and weight >= 8.0:
            return "Compliant", False
        if n_strong >= 1 and (n_medium >= 1 or n_weak >= 1) and weight >= 8.0:
            return "Compliant", False
        if not weak_only and n_types >= 3 and weight >= 10.0:
            return "Compliant", False
        # Partial: any strong signal, or weight >= 3
        if n_strong >= 1 or weight >= 3.0:
            return "Partial", False
        return "Not Compliant", False

    if bucket == "Partial":
        # Code can never make a Partial-bucket control "Compliant".
        if n_strong >= 2 and weight >= 6.0:
            return "Partial", True
        if n_strong >= 1 and (n_medium >= 1 or n_weak >= 1) and weight >= 6.0:
            return "Partial", True
        if not weak_only and n_types >= 3 and weight >= 8.0:
            return "Partial", True
        if n_strong >= 1 or weight >= 2.0:
            return "Partial (limited evidence)", True
        return "Not Compliant", True

    return "N/A", False


# ---------------------- Loading ----------------------

def load_controls(xlsx_path: str) -> List[dict]:
    wb = openpyxl.load_workbook(xlsx_path, read_only=True)
    ws = wb["Sheet1"]
    controls = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        padded = list(row) + [None] * (6 - len(row))
        cid, family, desc, text, risks, ct = padded[:6]
        if not cid:
            continue
        cid = cid.strip() if isinstance(cid, str) else cid
        if cid == "GV-4.3--001":
            cid = "GV-4.3-001"
        controls.append({
            "id": cid,
            "family": family,
            "description": desc,
            "text": text,
            "risks": risks,
            "code_testable": ct,
        })
    return controls


# ---------------------- Reports ----------------------

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_summary(statuses, evidence, manifest_deps):
    counts = Counter(b for b, _ in statuses.values())
    total = sum(counts.values())
    needs_ext = sum(1 for _, ne in statuses.values() if ne)

    print()
    print(f"{BOLD}NIST AI 600-1 Compliance Scan{RESET}")
    print(f"  {total} testable controls scanned "
          f"(67 also need external attestation)")
    print(f"  {len(manifest_deps)} unique dependencies found in manifests")
    print()

    bar_width = 40
    for status in ["Compliant", "Partial",
                   "Partial (limited evidence)", "Not Compliant"]:
        n = counts.get(status, 0)
        if status == "Compliant":
            color = GREEN
        elif status.startswith("Partial"):
            color = YELLOW
        else:
            color = RED
        bar_len = int(round(bar_width * n / total)) if total else 0
        bar = "#" * bar_len
        print(f"  {color}{bar:<{bar_width}}{RESET} {n:3d}  {status}")
    print()

    cov = (counts.get("Compliant", 0)
           + counts.get("Partial", 0)
           + counts.get("Partial (limited evidence)", 0))
    pct = 100.0 * cov / total if total else 0.0
    print(f"  Coverage: {GREEN}{counts.get('Compliant', 0)}{RESET} compliant "
          f"+ {YELLOW}{counts.get('Partial', 0) + counts.get('Partial (limited evidence)', 0)}"
          f"{RESET} partial = {cov}/{total} ({pct:.0f}%)")
    print()


def write_md(controls, rules, evidence, statuses, out_path, root):
    lines = []
    lines.append("# NIST AI 600-1 Compliance Attestation")
    lines.append("")
    lines.append(f"- **Repository:** `{root}`")
    lines.append(f"- **Scan time:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- **Scanner:** agentic-security/nist-ai-600-1 v0.2 (multi-signal)")
    lines.append(f"- **Catalog:** `NIST AI 600-1.xlsx` "
                 f"(212 controls; 122 code-testable)")
    lines.append("")
    lines.append("> This attestation reports only evidence detectable from "
                 "source code, dependency manifests, configuration, "
                 "documentation files, and CI in this repository. The 90 "
                 "controls flagged `Code Testable = No` (column F) are "
                 "inherently organizational and must be attested separately. "
                 "Controls flagged `Code Testable = Partial` are listed "
                 "below with code evidence found, but full compliance "
                 "additionally requires external attestation (signed policy / "
                 "training records / vendor agreements / etc.).")
    lines.append("")
    lines.append("**Signal types and weights:**")
    lines.append("")
    lines.append("| Signal | Weight | What it means |")
    lines.append("|---|---:|---|")
    lines.append("| `manifest` | 5.0 | A library known to satisfy this control "
                 "appears as a dependency in package.json, requirements.txt, "
                 "pyproject.toml, go.mod, Cargo.toml, Gemfile, composer.json. |")
    lines.append("| `import` | 4.0 | Code in this repo imports a library known "
                 "to satisfy this control. |")
    lines.append("| `test_path` | 3.0 | A file in a tests/ directory matches a "
                 "control-specific path pattern. |")
    lines.append("| `named_path` | 2.5 | A non-test file matches a "
                 "control-specific path pattern. |")
    lines.append("| `code_term` | 2.0 | A control-specific term appears in a "
                 "code file (.py/.ts/.go/etc.) outside a comment. |")
    lines.append("| `config_term` | 1.5 | Term appears in a config file "
                 "(YAML/TOML/JSON). |")
    lines.append("| `doc_term` | 1.0 | Term appears in a documentation file "
                 "(.md/.rst). |")
    lines.append("| `comment` | 0.5 | Term appears inside a code comment. |")
    lines.append("")
    lines.append("**Signals are tiered:** strong = `manifest` + `import`; "
                 "medium = `test_path` + `named_path` + `code_term`; "
                 "weak = `config_term` + `doc_term` + `comment`. Weight is "
                 "capped at 5 hits per signal type per control to prevent "
                 "broad patterns from over-inflating the score.")
    lines.append("")
    lines.append("**Status thresholds (Yes-bucket controls):**")
    lines.append("")
    lines.append("- **Compliant** — ≥ 2 strong-tier hits AND weight ≥ 8, "
                 "OR strong + medium/weak mix AND weight ≥ 8, "
                 "OR ≥ 3 distinct signal types AND weight ≥ 10.")
    lines.append("- **Partial** — at least 1 strong-tier hit, OR weight ≥ 3.")
    lines.append("- **Not Compliant** — otherwise.")
    lines.append("")
    lines.append("**Status thresholds (Partial-bucket controls — code can never "
                 "achieve Compliant on its own):**")
    lines.append("")
    lines.append("- **Partial** — same evidence threshold as Yes-Compliant, "
                 "but always tagged `External Attestation Required`.")
    lines.append("- **Partial (limited evidence)** — at least 1 strong-tier "
                 "hit, OR weight ≥ 2.")
    lines.append("- **Not Compliant** — otherwise; external attestation required.")
    lines.append("")
    lines.append("Matches inside negation contexts (\"we don't yet implement…\", "
                 "\"future work\", \"missing\", \"planned for\") are filtered out.")
    lines.append("")

    counts = Counter(b for b, _ in statuses.values())
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count | % of 122 |")
    lines.append("|---|---:|---:|")
    total = len(statuses)
    for status in ["Compliant", "Partial",
                   "Partial (limited evidence)", "Not Compliant", "N/A"]:
        n = counts.get(status, 0)
        if n == 0:
            continue
        pct = (100.0 * n / total) if total else 0
        lines.append(f"| {status} | {n} | {pct:.1f}% |")
    lines.append("")

    lines.append("## By family")
    lines.append("")
    fam_table = {}
    for c in controls:
        cid = c["id"]
        if cid not in statuses:
            continue
        fam = cid.split("-")[0]
        base, _ = statuses[cid]
        fam_table.setdefault(fam, Counter())[base] += 1
    lines.append("| Family | Total | Compliant | Partial | Not Compliant |")
    lines.append("|---|---:|---:|---:|---:|")
    fam_names = {"GV": "Govern", "MP": "Map", "MS": "Measure", "MG": "Manage"}
    for fam in ["GV", "MP", "MS", "MG"]:
        cc = fam_table.get(fam, Counter())
        compliant = cc.get("Compliant", 0)
        partial = (cc.get("Partial", 0)
                   + cc.get("Partial (limited evidence)", 0))
        not_c = cc.get("Not Compliant", 0)
        total_fam = compliant + partial + not_c
        lines.append(f"| {fam} ({fam_names[fam]}) | {total_fam} | "
                     f"{compliant} | {partial} | {not_c} |")
    lines.append("")

    lines.append("## Per-control evidence")
    lines.append("")
    for c in controls:
        cid = c["id"]
        if cid not in statuses:
            continue
        rule = rules[cid]
        base, needs_ext = statuses[cid]
        ev = evidence[cid]

        marker = ("[OK]" if base == "Compliant" else
                  ("[~]" if base.startswith("Partial") else "[X]"))
        title = f"{marker} {cid} — {base}"
        if needs_ext:
            title += " (External Attestation Required)"
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"**Looking for:** {rule.get('summary', '')}")
        lines.append("")

        # Score breakdown
        weight = sum(e.weight for e in ev)
        sig_counts = Counter(e.signal_type for e in ev)
        if ev:
            breakdown = ", ".join(f"{n}×{t}" for t, n in sig_counts.most_common())
            lines.append(f"**Score:** {weight:.1f} ({breakdown}; "
                         f"{len(sig_counts)} signal types)")
        else:
            lines.append("**Score:** 0.0")
        lines.append("")
        lines.append(f"- Source classification: `{c['code_testable']}` (column F)")
        lines.append(f"- Family: {c['family']}")
        if c.get("text"):
            t = c["text"].replace("\n", " ").strip()
            lines.append(f"- Control text: {t}")
        if c.get("risks"):
            lines.append(f"- GAI risks: {c['risks']}")
        lines.append("")

        if ev:
            # Group by signal type for readability
            by_type: Dict[str, List[Evidence]] = defaultdict(list)
            for e in ev:
                by_type[e.signal_type].append(e)
            ordered_types = ["manifest", "import", "test_path", "named_path",
                             "code_term", "config_term", "doc_term", "comment"]
            for sig in ordered_types:
                items = by_type.get(sig, [])
                if not items:
                    continue
                lines.append(f"**{sig}** ({len(items)}):")
                lines.append("")
                for e in items[:8]:
                    line_str = f" (line {e.line})" if e.line else ""
                    lines.append(f"- `{e.file}` — {e.detail}{line_str}")
                if len(items) > 8:
                    lines.append(f"- _...and {len(items) - 8} more_")
                lines.append("")
        else:
            lines.append("**Evidence:** _none found_")
            lines.append("")

        if needs_ext:
            lines.append("> Requires external attestation (signed policy, "
                         "training records, vendor agreement, or other "
                         "organizational evidence) in addition to any "
                         "code evidence above.")
            lines.append("")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_csv(controls, rules, evidence, statuses, out_path):
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "Control #", "Family", "Code Testable", "Status",
            "External Attestation Required", "Score",
            "Manifest Hits", "Import Hits", "Test-Path Hits",
            "Named-Path Hits", "Code-Term Hits", "Config-Term Hits",
            "Doc-Term Hits", "Comment Hits", "Signal Types",
            "Evidence Files", "Top Evidence", "Looking For", "Control Text",
        ])
        for c in controls:
            cid = c["id"]
            if cid not in statuses:
                continue
            base, needs_ext = statuses[cid]
            ev = evidence[cid]
            sig_counts = Counter(e.signal_type for e in ev)
            score = sum(e.weight for e in ev)
            distinct_files = sorted({e.file for e in ev})
            top = "; ".join(distinct_files[:3])
            text = (c.get("text") or "").replace("\n", " ").strip()[:500]
            w.writerow([
                cid, c["family"], c["code_testable"], base,
                "Yes" if needs_ext else "No",
                f"{score:.1f}",
                sig_counts.get("manifest", 0),
                sig_counts.get("import", 0),
                sig_counts.get("test_path", 0),
                sig_counts.get("named_path", 0),
                sig_counts.get("code_term", 0),
                sig_counts.get("config_term", 0),
                sig_counts.get("doc_term", 0),
                sig_counts.get("comment", 0),
                len(sig_counts),
                len(distinct_files),
                top,
                rules[cid].get("summary", ""),
                text,
            ])


def write_json(controls, rules, evidence, statuses, manifest_deps,
               out_path, root):
    data = {
        "scanner": "agentic-security/nist-ai-600-1",
        "scanner_version": "0.2.0",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "repo": root,
        "summary": dict(Counter(b for b, _ in statuses.values())),
        "manifest_dependencies_found": len(manifest_deps),
        "controls": [],
    }
    for c in controls:
        cid = c["id"]
        if cid not in statuses:
            continue
        base, needs_ext = statuses[cid]
        ev = evidence[cid]
        sig_counts = Counter(e.signal_type for e in ev)
        data["controls"].append({
            "id": cid,
            "family": c["family"],
            "code_testable": c["code_testable"],
            "status": base,
            "external_attestation_required": needs_ext,
            "looking_for": rules[cid].get("summary", ""),
            "control_text": c.get("text", ""),
            "score": round(sum(e.weight for e in ev), 2),
            "signal_types": list(sig_counts.keys()),
            "signal_counts": dict(sig_counts),
            "evidence": [asdict(e) for e in ev[:30]],
        })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", nargs="?", default=".", help="Repo path to scan")
    ap.add_argument("--xlsx", default=str(DEFAULT_XLSX),
                    help="Path to NIST AI 600-1.xlsx")
    ap.add_argument("--rules", default=str(DEFAULT_RULES),
                    help="Path to evidence-rules.json")
    ap.add_argument("--md-out", default="nist-ai-600-1-attestation.md")
    ap.add_argument("--csv-out", default="nist-ai-600-1-attestation.csv")
    ap.add_argument("--json-out", default="nist-ai-600-1-attestation.json")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress console summary")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    quiet = args.quiet

    if not quiet:
        sys.stderr.write(f"Loading control catalog from {args.xlsx}...\n")
    controls = load_controls(args.xlsx)

    if not quiet:
        sys.stderr.write(f"Loading evidence rules from {args.rules}...\n")
    with open(args.rules, "r", encoding="utf-8") as f:
        rules = json.load(f)

    testable = [c for c in controls if c["code_testable"] in ("Yes", "Partial")]
    rules_for = {cid: rules[cid] for cid in (c["id"] for c in testable)
                 if cid in rules}
    missing = [c["id"] for c in testable if c["id"] not in rules]
    if missing and not quiet:
        sys.stderr.write(
            f"NOTE: {len(missing)} testable controls have no rule "
            f"(skipped): {', '.join(missing[:5])}"
            f"{'...' if len(missing) > 5 else ''}\n"
        )

    if not quiet:
        sys.stderr.write(f"Scanning {root} for {len(rules_for)} controls...\n")
    evidence, manifest_deps = scan(root, rules_for, quiet=quiet)

    statuses = {}
    for c in testable:
        if c["id"] not in rules_for:
            continue
        statuses[c["id"]] = classify(c, evidence[c["id"]])

    write_md(testable, rules_for, evidence, statuses,
             args.md_out, root)
    write_csv(testable, rules_for, evidence, statuses, args.csv_out)
    write_json(testable, rules_for, evidence, statuses,
               manifest_deps, args.json_out, root)

    if not quiet:
        print_summary(statuses, evidence, manifest_deps)
        print(f"Attestation written to:")
        print(f"  - {args.md_out}")
        print(f"  - {args.csv_out}")
        print(f"  - {args.json_out}")


if __name__ == "__main__":
    main()
