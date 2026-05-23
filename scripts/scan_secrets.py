"""Scan project for hardcoded secrets (excludes .venv by default)."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SKIP_DIRS = {".venv", "__pycache__", ".git", "node_modules"}
TEXT_EXT = {".py", ".env", ".json", ".yml", ".yaml", ".ini", ".cfg", ".toml", ".md", ".txt", ".bat", ".sh"}

PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "credential assignment"),
    (r"(?i)password\s*=\s*['\"]([^'\"]{3,})['\"]", "hardcoded password"),
    (r"ghp_[a-zA-Z0-9]{20,}", "github token"),
    (r"sk-[a-zA-Z0-9]{20,}", "openai/sk key"),
    (r"AKIA[0-9A-Z]{16}", "aws access key"),
    (r"(?i)HF_TOKEN\s*=\s*['\"]([^'\"]+)['\"]", "hf token"),
    (r"(?i)SECRET_KEY\s*=\s*['\"]([^'\"]+)['\"]", "django secret"),
    (r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "private IP"),
]

PLACEHOLDER = re.compile(
    r"(your_|changeme|example\.com|xxx+|placeholder|dummy|test123|password123|<.*>|TODO|REPLACE_ME)",
    re.I,
)


def should_skip_line(line: str) -> bool:
    if PLACEHOLDER.search(line):
        return True
    low = line.lower()
    if "tokenizer" in low or "autotokenizer" in low:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan for hardcoded secrets.")
    ap.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Directory name to skip (repeatable), e.g. --exclude pygoat",
    )
    ap.add_argument("--out", type=str, default="", help="Optional report file path.")
    args = ap.parse_args()

    skip_dirs = set(DEFAULT_SKIP_DIRS) | set(args.exclude)

    hits: list[tuple[str, int, str, str]] = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() not in TEXT_EXT and p.name not in (".env", ".env.local"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(ROOT).as_posix()
        for i, line in enumerate(text.splitlines(), 1):
            if should_skip_line(line):
                continue
            for pat, kind in PATTERNS:
                if re.search(pat, line):
                    hits.append((rel, i, kind, line.strip()[:140]))
                    break

    lines = [f"{rel}:{i}\t{kind}\t{snippet}" for rel, i, kind, snippet in hits]
    lines.append(f"TOTAL\t{len(hits)}")
    report = "\n".join(lines)
    print(report)
    if args.out:
        Path(args.out).write_text(report + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
