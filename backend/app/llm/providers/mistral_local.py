from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

try:
    from llama_cpp import Llama
except ImportError:  # pragma: no cover - optional dependency
    Llama = None  # type: ignore[assignment]

from app.core.config import get_settings
from app.llm.providers.base import LLMProvider


class LocalMistralProvider(LLMProvider):
    def __init__(self, model_path: Optional[str] = None, max_tokens: int = 512) -> None:
        settings = get_settings()
        self.model_path = model_path or settings.llm_model_path
        if Llama is None:
            raise RuntimeError("llama-cpp-python is not installed; disable LLM or install the dependency")
        if not self.model_path:
            raise RuntimeError("LLM model path must be configured via LLM_MODEL_PATH")
        self._llama = Llama(model_path=self.model_path, n_gpu_layers=0, n_ctx=4096)
        self.max_tokens = max_tokens

    async def generate(self, findings: List[Dict[str, Any]]) -> str:
        payload = {
            "risk_summary": [
                {
                    "rule_id": f["rule_id"],
                    "severity": f["severity"],
                    "risk_category": f["evidence"].get("message") or f["rule_id"],
                }
                for f in findings
            ]
        }
        prompt = (
            "You are AWS SecureScope, a security assistant. "
            "Create concise Markdown with sections: Why it matters, Remediation steps (CLI + Console), "
            "Blast radius, and Regression tests."
        )
        combined = f"{prompt}\nContext: {json.dumps(payload)}"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self._llama(
                combined,
                max_tokens=self.max_tokens,
                temperature=0.2,
                top_p=0.9,
                stop=["</s>"]
            ),
        )
        return result["choices"][0]["text"].strip()
