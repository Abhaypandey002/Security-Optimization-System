from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass
class Rule:
    id: str
    service: str
    title: str
    severity: str
    rationale: str
    evaluation: Dict[str, Any]
    references: List[Dict[str, str]]
    auto_remediation_possible: bool

    def dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "service": self.service,
            "title": self.title,
            "severity": self.severity,
            "rationale": self.rationale,
            "evaluation": self.evaluation,
            "references": self.references,
            "autoRemediationPossible": self.auto_remediation_possible,
        }


class PolicyEngine:
    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self.rules_dir = rules_dir or RULES_DIR
        self._rules_cache: Dict[str, List[Rule]] = {}

    def load_rules(self, service: Optional[str] = None) -> List[Rule]:
        if service:
            key = service.lower()
            if key not in self._rules_cache:
                self._rules_cache[key] = self._load_rules_from_file(f"{key}.yaml")
            return self._rules_cache[key]
        all_rules: List[Rule] = []
        for path in self.rules_dir.glob("*.yaml"):
            all_rules.extend(self._load_rules_from_file(path.name))
        return all_rules

    def _load_rules_from_file(self, filename: str) -> List[Rule]:
        path = self.rules_dir / filename
        if not path.exists():
            return []
        data = _load_rules(path.read_text())
        rules: List[Rule] = []
        for item in data:
            rules.append(
                Rule(
                    id=item["id"],
                    service=item["service"],
                    title=item["title"],
                    severity=item["severity"],
                    rationale=item["rationale"],
                    evaluation=item.get("evaluation", {}),
                    references=item.get("references", []),
                    auto_remediation_possible=item.get("autoRemediationPossible", False),
                )
            )
        return rules

    def evaluate(self, service: str, resources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rules = self.load_rules(service)
        findings: List[Dict[str, Any]] = []
        for rule in rules:
            evaluator = rule.evaluation.get("evaluator")
            if not evaluator:
                continue
            module_name, func_name = evaluator.rsplit(".", 1)
            module = import_module(f"app.services.rules.{module_name}")
            func = getattr(module, func_name)
            findings.extend(func(rule=rule, resources=resources))
        return findings


def _load_rules(text: str) -> List[Dict[str, Any]]:
    lines = text.splitlines()
    tokens = []
    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        tokens.append((indent, line.strip()))

    def parse_value(raw: str) -> Any:
        if raw == "":
            return None
        lowered = raw.lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
        if lowered == "null":
            return None
        if raw.startswith("[") and raw.endswith("]"):
            inner = raw[1:-1].strip()
            if not inner:
                return []
            return [parse_value(item.strip()) for item in inner.split(",")]
        if (raw.startswith("\"") and raw.endswith("\"")) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]
        try:
            return int(raw)
        except ValueError:
            return raw

    root: List[Any] = []
    stack: List[tuple[int, Any]] = [(-1, root)]

    def next_non_empty_index(start: int) -> Optional[str]:
        for idx in range(start, len(tokens)):
            if tokens[idx][1]:
                return tokens[idx][1]
        return None

    i = 0
    while i < len(tokens):
        indent, content = tokens[i]
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if content.startswith("- "):
            value_part = content[2:]
            if isinstance(parent, list):
                container_parent = parent
            else:
                raise ValueError("Invalid YAML structure")
            if ":" in value_part:
                key, value = value_part.split(":", 1)
                item: Dict[str, Any] = {}
                container_parent.append(item)
                key = key.strip()
                value = value.strip()
                if value:
                    item[key] = parse_value(value)
                    stack.append((indent, item))
                else:
                    next_line = next_non_empty_index(i + 1)
                    if next_line and next_line.startswith("- "):
                        item[key] = []
                    else:
                        item[key] = {}
                    stack.append((indent, item[key]))
            else:
                container_parent.append(parse_value(value_part.strip()))
        else:
            if ":" not in content:
                raise ValueError(f"Invalid line: {content}")
            key, value = content.split(":", 1)
            key = key.strip()
            value = value.strip()
            if isinstance(parent, list):
                if not parent:
                    parent.append({})
                container = parent[-1]
            else:
                container = parent
            if value:
                container[key] = parse_value(value)
            else:
                next_line = next_non_empty_index(i + 1)
                if next_line and next_line.startswith("- "):
                    container[key] = []
                else:
                    container[key] = {}
                stack.append((indent, container[key]))
        i += 1

    return root
