from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, findings: List[Dict[str, Any]]) -> str:
        raise NotImplementedError
