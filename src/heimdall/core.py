from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Optional

from .engines.semantic import SemanticEngine
from .engines.structural import StructuralEngine
from .types import HybridResult
from .utils.scoring import hybrid_risk


class HeimdallCore:
    """
    Heimdall Core orchestrates semantic + structural engines and produces
    a final "risk index" with supporting evidence.

    Philosophy:
    - Semantic: "what does this code *intend* to do?"
    - Structural: "how does the code *actually* flow and where are the sinks?"
    - Hybrid: "combine both signals; trust neither alone."
    """

    def __init__(
        self,
        *,
        semantic: Optional[SemanticEngine] = None,
        structural: Optional[StructuralEngine] = None,
        w_sem: float = 0.55,
        w_str: float = 0.45,
    ) -> None:
        self.semantic = semantic or SemanticEngine()
        self.structural = structural or StructuralEngine()
        self.w_sem = float(w_sem)
        self.w_str = float(w_str)

    def analyze_code(self, code: str, *, language: str = "python") -> HybridResult:
        if language.lower() != "python":
            # Semantic engine is language-agnostic-ish; structural engine is Python AST-only for now.
            notes = [f"StructuralEngine currently supports python only; got language={language!r}."]
            sem = self.semantic.score(code)
            st = self.structural.analyze("")  # no structural findings
            risk = hybrid_risk(sem.score, st.score, w_sem=self.w_sem, w_str=self.w_str)
            return HybridResult(
                risk_index=risk,
                semantic=sem,
                structural=st,
                weights={"semantic": self.w_sem, "structural": self.w_str},
                notes=notes,
            )

        sem = self.semantic.score(code)
        st = self.structural.analyze(code)

        notes = []
        if sem.score > 0.70 and st.score < 0.20:
            notes.append("Semantic signal is high but structural findings are limited; could be a false positive or obfuscated flow.")
        if st.score > 0.70 and sem.score < 0.20:
            notes.append("Structural signal is high but semantic proximity to anchors is low; could be uncommon code patterns or benign usage of risky APIs.")

        risk = hybrid_risk(sem.score, st.score, w_sem=self.w_sem, w_str=self.w_str)
        return HybridResult(
            risk_index=risk,
            semantic=sem,
            structural=st,
            weights={"semantic": self.w_sem, "structural": self.w_str},
            notes=notes,
        )

    def analyze_code_dict(self, code: str, *, language: str = "python") -> Dict[str, Any]:
        """
        Convenience wrapper for CLI / JSON output.
        """
        res = self.analyze_code(code, language=language)
        return asdict(res)

