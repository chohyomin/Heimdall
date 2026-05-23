from __future__ import annotations

import math


def clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def hybrid_risk(semantic_score: float, structural_score: float, *, w_sem: float, w_str: float) -> float:
    """
    Combine two bounded scores (0..1) into a final risk index (0..1).

    - Weighted sum into logit space for smoother tails
    - Synergy bonus when both signals are high
    """
    sem = clamp01(semantic_score)
    st = clamp01(structural_score)

    base = (w_sem * sem) + (w_str * st)
    synergy = 0.20 * (sem * st)

    # Map to logit-ish range then sigmoid back.
    logit = 5.0 * (base + synergy - 0.5)
    return clamp01(sigmoid(logit))

