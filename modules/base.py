from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    title: str
    severity: str  # one of: critical, high, medium, low, info
    detail: str
    recommendation: str = ""
    module: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class AnalysisResult:
    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def worst_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: f.severity_rank).severity


class BaseAnalyzer(ABC):
    name: str = ""

    @abstractmethod
    async def analyze(self, target: Any) -> AnalysisResult:
        ...
