from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SemanticResult:
    score: float  # 0..1
    top_anchor: str
    top_similarity: float
    similarities: Dict[str, float]  # anchor -> similarity
    model_name: str


@dataclass(frozen=True)
class StructuralFinding:
    rule_id: str
    title: str
    severity: float  # 0..1
    lineno: Optional[int]
    col_offset: Optional[int]
    message: str
    extra: Dict[str, Any]


@dataclass(frozen=True)
class StructuralResult:
    score: float  # 0..1
    findings: List[StructuralFinding]


@dataclass(frozen=True)
class HybridResult:
    risk_index: float  # 0..1
    semantic: SemanticResult
    structural: StructuralResult
    weights: Dict[str, float]
    notes: List[str]

