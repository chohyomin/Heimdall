from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

from ..types import SemanticResult
from ..utils.scoring import clamp01


@dataclass(frozen=True)
class Anchor:
    key: str
    text: str


DEFAULT_ANCHORS: List[Anchor] = [
    Anchor("cmd_injection", "User-controlled input reaches OS command execution (os.system/subprocess)."),
    Anchor("code_exec", "Dynamic code execution via eval/exec or function compilation from input."),
    Anchor("sql_injection", "SQL query string built from untrusted input and executed."),
    Anchor("path_traversal", "File path built from user input leading to arbitrary file read/write."),
    Anchor("unsafe_deserialization", "Untrusted data deserialized via pickle/yaml leading to code execution."),
    Anchor("ssrf", "Server-side request forgery: URL from user input used in HTTP request."),
    Anchor("xss", "HTML/JS output built from user input without proper escaping."),
]


def _mean_pool(last_hidden_state: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
    mask = attention_mask.unsqueeze(-1).type_as(last_hidden_state)
    summed = (last_hidden_state * mask).sum(dim=1)
    denom = mask.sum(dim=1).clamp(min=1e-6)
    return summed / denom


class SemanticEngine:
    """
    Semantic risk scoring using CodeBERT-style embeddings.

    Note: This is NOT a fine-tuned vulnerability classifier.
    Instead, it embeds code and compares it to a small set of "risk anchors"
    (threat scenarios) to estimate contextual proximity to risky intent.
    """

    def __init__(
        self,
        *,
        model_name: str = "microsoft/codebert-base",
        device: Optional[str] = None,
        anchors: Optional[Iterable[Anchor]] = None,
        max_length: int = 256,
    ) -> None:
        self.model_name = model_name
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()

        self.max_length = max_length
        self.anchors: List[Anchor] = list(anchors) if anchors is not None else list(DEFAULT_ANCHORS)
        self._anchor_matrix: Optional[torch.Tensor] = None
        self._anchor_keys: List[str] = []

    @torch.inference_mode()
    def embed_texts(self, texts: List[str]) -> torch.Tensor:
        enc = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        enc = {k: v.to(self.device) for k, v in enc.items()}
        out = self.model(**enc)

        if hasattr(out, "pooler_output") and out.pooler_output is not None:
            emb = out.pooler_output
        else:
            emb = _mean_pool(out.last_hidden_state, enc["attention_mask"])

        emb = torch.nn.functional.normalize(emb, p=2, dim=-1)
        return emb

    def _ensure_anchors(self) -> Tuple[torch.Tensor, List[str]]:
        if self._anchor_matrix is not None and self._anchor_keys:
            return self._anchor_matrix, self._anchor_keys

        keys = [a.key for a in self.anchors]
        texts = [a.text for a in self.anchors]
        mat = self.embed_texts(texts)
        self._anchor_matrix = mat
        self._anchor_keys = keys
        return mat, keys

    @torch.inference_mode()
    def score(self, code: str) -> SemanticResult:
        code = code or ""
        anchors_mat, anchor_keys = self._ensure_anchors()

        code_vec = self.embed_texts([code])[0:1, :]
        sims = (code_vec @ anchors_mat.T).squeeze(0)  # cosine similarity due to normalization

        sims_np = sims.detach().float().cpu().numpy()
        sim_by_key: Dict[str, float] = {k: float(v) for k, v in zip(anchor_keys, sims_np)}

        best_idx = int(np.argmax(sims_np)) if sims_np.size else 0
        top_anchor = anchor_keys[best_idx] if anchor_keys else "none"
        top_sim = float(sims_np[best_idx]) if sims_np.size else 0.0

        # Convert similarity (-1..1) to a bounded risk proxy.
        # Shift to [0..1] then sharpen slightly to emphasize strong alignment.
        shifted = clamp01((top_sim + 1.0) / 2.0)
        score = clamp01(shifted ** 2.0)

        return SemanticResult(
            score=score,
            top_anchor=top_anchor,
            top_similarity=top_sim,
            similarities=sim_by_key,
            model_name=self.model_name,
        )

