from __future__ import annotations

from typing import List

from .types import HybridResult, StructuralFinding


def _bar(x: float, width: int = 24) -> str:
    x = 0.0 if x < 0.0 else 1.0 if x > 1.0 else x
    n = int(round(x * width))
    return "[" + ("#" * n) + ("-" * (width - n)) + "]"


def _fmt_path(path: List[str]) -> str:
    if not path:
        return ""
    # path elements are like "source:input@L12"
    pretty = "  -> ".join(path)
    return pretty


def _fmt_finding(f: StructuralFinding) -> str:
    loc = ""
    if f.lineno is not None:
        loc = f" (L{f.lineno})"
    sev = f"{f.severity:.2f}"
    head = f"- [{f.rule_id}] {f.title}{loc} | severity={sev}"
    lines = [head, f"  {f.message}"]
    paths = f.extra.get("paths") if isinstance(f.extra, dict) else None
    if paths:
        for i, p in enumerate(paths, start=1):
            if isinstance(p, list):
                lines.append(f"  Path {i}: {_fmt_path([str(x) for x in p])}")
            else:
                lines.append(f"  Path {i}: {p}")
    return "\n".join(lines)


def format_report(res: HybridResult) -> str:
    lines: List[str] = []
    lines.append("Heimdall Report")
    lines.append("=" * 60)
    lines.append(f"Risk Index   : {res.risk_index:.3f} {_bar(res.risk_index)}")
    lines.append(f"Semantic     : {res.semantic.score:.3f} (anchor={res.semantic.top_anchor}, sim={res.semantic.top_similarity:.3f})")
    lines.append(f"Structural   : {res.structural.score:.3f} (findings={len(res.structural.findings)})")
    lines.append(f"Weights      : semantic={res.weights.get('semantic')}, structural={res.weights.get('structural')}")
    if res.notes:
        lines.append("")
        lines.append("Notes")
        lines.append("-" * 60)
        for n in res.notes:
            lines.append(f"- {n}")

    lines.append("")
    lines.append("Findings (Structural Evidence)")
    lines.append("-" * 60)
    if not res.structural.findings:
        lines.append("- No structural findings.")
        return "\n".join(lines)

    # Sort: highest severity first, then location.
    findings = sorted(
        res.structural.findings,
        key=lambda f: (-(f.severity or 0.0), f.lineno if f.lineno is not None else 10**9),
    )
    for f in findings:
        lines.append(_fmt_finding(f))
    return "\n".join(lines)

