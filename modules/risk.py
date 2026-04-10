from .base import AnalysisResult, Finding

# Points deducted per finding at each severity level
PENALTY: dict[str, int] = {
    "critical": 30,
    "high": 15,
    "medium": 7,
    "low": 2,
    "info": 0,
}

GRADE_SCALE: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (55, "C"),
    (35, "D"),
    (0,  "F"),
]

GRADE_COLOR: dict[str, str] = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}


def _letter_grade(score: int) -> str:
    for threshold, letter in GRADE_SCALE:
        if score >= threshold:
            return letter
    return "F"


class RiskScorer:
    def __init__(self, results: dict[str, AnalysisResult]):
        self.results = results

    def score(self) -> AnalysisResult:
        all_findings: list[Finding] = []
        for key, result in self.results.items():
            if hasattr(result, "findings"):
                all_findings.extend(result.findings)

        penalty = sum(PENALTY.get(f.severity, 0) for f in all_findings)
        raw_score = max(0, 100 - penalty)
        grade = _letter_grade(raw_score)

        counts: dict[str, int] = {}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        # Flatten all findings with module attribution, sorted by severity
        flat: list[dict] = []
        for f in sorted(all_findings, key=lambda x: x.severity_rank):
            module = f.module or next(
                (k for k, r in self.results.items() if hasattr(r, "findings") and f in r.findings),
                "unknown",
            )
            flat.append({
                "title": f.title,
                "severity": f.severity,
                "detail": f.detail,
                "recommendation": f.recommendation,
                "module": module,
            })

        # Identify the first result's target
        target_raw = ""
        for r in self.results.values():
            if hasattr(r, "target"):
                target_raw = r.target
                break

        return AnalysisResult(
            module="risk",
            target=target_raw,
            findings=[],
            data={
                "score": raw_score,
                "grade": grade,
                "grade_color": GRADE_COLOR.get(grade, "#6b7280"),
                "total_findings": len(all_findings),
                "counts": counts,
                "all_findings": flat,
            },
        )
