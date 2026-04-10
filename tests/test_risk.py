# tests for risk scorer - grade boundaries, penalty math, finding aggregation

import sys
import os

# make sure imports resolve from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from modules.base import AnalysisResult, Finding
from modules.risk import RiskScorer, _letter_grade, PENALTY, GRADE_SCALE


# helpers

def make_result(module: str, findings: list[Finding], error: str = None) -> AnalysisResult:
    return AnalysisResult(module=module, target="example.com", findings=findings, error=error)


def make_finding(severity: str, module: str = "recon") -> Finding:
    return Finding(
        title=f"Test finding ({severity})",
        severity=severity,
        detail="detail",
        recommendation="fix it",
        module=module,
    )


# Attack 1 - grade boundary off-by-one

class TestGradeBoundaries:
    """Each threshold value must land on exactly the right letter grade."""

    def test_score_90_is_A_not_B(self):
        assert _letter_grade(90) == "A"

    def test_score_89_is_B_not_A(self):
        assert _letter_grade(89) == "B"

    def test_score_75_is_B_not_C(self):
        assert _letter_grade(75) == "B"

    def test_score_74_is_C_not_B(self):
        assert _letter_grade(74) == "C"

    def test_score_55_is_C_not_D(self):
        assert _letter_grade(55) == "C"

    def test_score_54_is_D_not_C(self):
        assert _letter_grade(54) == "D"

    def test_score_35_is_D_not_F(self):
        assert _letter_grade(35) == "D"

    def test_score_34_is_F_not_D(self):
        assert _letter_grade(34) == "F"

    def test_score_0_is_F(self):
        assert _letter_grade(0) == "F"

    def test_score_100_is_A(self):
        assert _letter_grade(100) == "A"


# Attack 2 - empty module string triggers wrong fallback

class TestModuleAttribution:
    """Findings with module='' (falsy) must still be attributed correctly."""

    def test_finding_with_empty_module_string_gets_attributed(self):
        f = Finding(title="no module", severity="high", detail="d", recommendation="r", module="")
        result = make_result("recon", [f])
        scored = RiskScorer({"recon": result}).score()
        flat = scored.data["all_findings"]
        assert len(flat) == 1
        # should not fall back to "unknown", the lookup should resolve it to "recon"
        assert flat[0]["module"] == "recon"

    def test_finding_with_explicit_module_is_not_overridden(self):
        f = make_finding("medium", module="tls")
        result = make_result("tls", [f])
        scored = RiskScorer({"tls": result}).score()
        flat = scored.data["all_findings"]
        assert flat[0]["module"] == "tls"


# Attack 3 - score floor, must never go negative

class TestScoreFloor:
    """Penalty can exceed 100. Score must floor at 0, never go negative."""

    def test_four_critical_findings_floors_at_zero(self):
        # 4 * 30 = 120 penalty > 100
        findings = [make_finding("critical") for _ in range(4)]
        result = make_result("recon", findings)
        scored = RiskScorer({"recon": result}).score()
        assert scored.data["score"] == 0

    def test_score_at_floor_still_grades_F(self):
        findings = [make_finding("critical") for _ in range(10)]
        result = make_result("recon", findings)
        scored = RiskScorer({"recon": result}).score()
        assert scored.data["grade"] == "F"
        assert scored.data["score"] == 0

    def test_single_critical_deducts_exactly_30(self):
        result = make_result("recon", [make_finding("critical")])
        scored = RiskScorer({"recon": result}).score()
        assert scored.data["score"] == 70

    def test_clean_scan_scores_100_grade_A(self):
        result = make_result("recon", [])
        scored = RiskScorer({"recon": result}).score()
        assert scored.data["score"] == 100
        assert scored.data["grade"] == "A"


# Gap 1 - unknown severity scores 0 penalty but still shows in counts

class TestUnknownSeverity:
    """A finding with an unrecognized severity must not crash and must appear in counts."""

    def test_unknown_severity_does_not_crash(self):
        f = Finding(title="weird", severity="catastrophic", detail="d", recommendation="r", module="recon")
        result = make_result("recon", [f])
        scored = RiskScorer({"recon": result}).score()
        assert scored.data["score"] == 100  # 0 penalty for unknown

    def test_unknown_severity_appears_in_counts(self):
        f = Finding(title="weird", severity="catastrophic", detail="d", recommendation="r", module="recon")
        result = make_result("recon", [f])
        scored = RiskScorer({"recon": result}).score()
        assert "catastrophic" in scored.data["counts"]

    def test_unknown_severity_appears_in_all_findings(self):
        f = Finding(title="weird", severity="catastrophic", detail="d", recommendation="r", module="recon")
        result = make_result("recon", [f])
        scored = RiskScorer({"recon": result}).score()
        assert len(scored.data["all_findings"]) == 1


# Gap 2 - empty results dict must not crash

class TestEmptyResults:
    """Scorer receives no modules, must return a valid zero-finding result."""

    def test_empty_results_does_not_crash(self):
        scored = RiskScorer({}).score()
        assert scored.data["score"] == 100
        assert scored.data["grade"] == "A"
        assert scored.data["total_findings"] == 0

    def test_empty_results_target_is_empty_string(self):
        scored = RiskScorer({}).score()
        assert scored.target == ""


# Gap 3 - errored module should contribute zero findings to score

class TestErroredModules:
    """A module that failed (error set, findings=[]) must not affect the score."""

    def test_errored_module_contributes_zero_findings(self):
        errored = make_result("tls", findings=[], error="connection refused")
        scored = RiskScorer({"tls": errored}).score()
        assert scored.data["total_findings"] == 0
        assert scored.data["score"] == 100

    def test_mixed_errored_and_good_module_counts_only_good_findings(self):
        good = make_result("recon", [make_finding("high")])
        bad = make_result("tls", findings=[], error="timeout")
        scored = RiskScorer({"recon": good, "tls": bad}).score()
        assert scored.data["total_findings"] == 1
        assert scored.data["score"] == 85  # 100 - 15


# Gap A - multi-module scoring must not double-count

class TestMultiModuleScoring:
    """Findings from multiple modules must be aggregated, not duplicated."""

    def test_two_modules_each_one_high_costs_30_not_15(self):
        r1 = make_result("recon", [make_finding("high", module="recon")])
        r2 = make_result("tls",   [make_finding("high", module="tls")])
        scored = RiskScorer({"recon": r1, "tls": r2}).score()
        assert scored.data["score"] == 70   # 100 - 15 - 15
        assert scored.data["total_findings"] == 2

    def test_five_modules_finding_counts_sum_correctly(self):
        modules = {
            "recon":   make_result("recon",   [make_finding("critical", "recon")]),
            "tls":     make_result("tls",     [make_finding("high", "tls")]),
            "headers": make_result("headers", [make_finding("medium", "headers")]),
            "dns":     make_result("dns",     [make_finding("low", "dns")]),
            "vuln":    make_result("vuln",    [make_finding("info", "vuln")]),
        }
        scored = RiskScorer(modules).score()
        assert scored.data["total_findings"] == 5
        assert scored.data["score"] == max(0, 100 - 30 - 15 - 7 - 2 - 0)


# Gap B - all_findings must be sorted critical to info

class TestFindingsSortOrder:
    """all_findings in the report must be sorted by severity, worst first."""

    def test_findings_sorted_critical_before_high(self):
        findings = [
            make_finding("high", "recon"),
            make_finding("critical", "recon"),
            make_finding("medium", "recon"),
        ]
        scored = RiskScorer({"recon": make_result("recon", findings)}).score()
        severities = [f["severity"] for f in scored.data["all_findings"]]
        assert severities == ["critical", "high", "medium"]

    def test_findings_sorted_all_five_levels(self):
        findings = [make_finding(s, "recon") for s in ["info", "low", "medium", "high", "critical"]]
        scored = RiskScorer({"recon": make_result("recon", findings)}).score()
        severities = [f["severity"] for f in scored.data["all_findings"]]
        assert severities == ["critical", "high", "medium", "low", "info"]


# Gap C - counts dict must match total_findings

class TestCountsConsistency:
    """Sum of counts by severity must equal total_findings, they drive the report summary cards."""

    def test_counts_sum_equals_total_findings(self):
        findings = [
            make_finding("critical", "recon"),
            make_finding("critical", "recon"),
            make_finding("high", "tls"),
            make_finding("medium", "headers"),
        ]
        scored = RiskScorer({"recon": make_result("recon", findings[:2]),
                             "tls":   make_result("tls",   findings[2:3]),
                             "headers": make_result("headers", findings[3:])}).score()
        counts = scored.data["counts"]
        assert sum(counts.values()) == scored.data["total_findings"]

    def test_counts_keys_match_severities_present(self):
        findings = [make_finding("high", "recon"), make_finding("low", "tls")]
        scored = RiskScorer({
            "recon": make_result("recon", findings[:1]),
            "tls":   make_result("tls",   findings[1:]),
        }).score()
        assert "high" in scored.data["counts"]
        assert "low" in scored.data["counts"]
        assert "critical" not in scored.data["counts"]
