from __future__ import annotations

import argparse
import json
from pathlib import Path

from heimdall import HeimdallCore
from heimdall.report import format_report


def main() -> int:
    p = argparse.ArgumentParser(description="Heimdall hybrid analyzer (CodeBERT + AST).")
    p.add_argument("--file", type=str, required=True, help="Path to a source code file (python recommended).")
    p.add_argument("--language", type=str, default="python", help="Language hint (default: python).")
    p.add_argument("--json", action="store_true", help="Output JSON instead of a human-readable report.")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON output (with --json).")
    args = p.parse_args()

    code = Path(args.file).read_text(encoding="utf-8", errors="replace")
    core = HeimdallCore()
    hybrid = core.analyze_code(code, language=args.language)

    if args.json:
        result = core.analyze_code_dict(code, language=args.language)
        if args.pretty:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(result, ensure_ascii=False))
        return 0

    print(format_report(hybrid))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

