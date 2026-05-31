import re
import unicodedata
from pathlib import Path
import yaml

from app.schemas.security import SecurityVerdict
from app.security.inspectors.base import BaseInspector
from app.security.policy import resolve_action

PATTERNS_DIR = Path(__file__).resolve().parent.parent / "patterns"
ZERO_WIDTH_RE = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]')
CONTROL_RE = re.compile(r'[\u202a-\u202e\u2066-\u2069]')

def _normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    text = CONTROL_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text

def _load_yaml_file(file_path: Path) -> dict:
    with file_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_manifest(file_name: str) -> dict:
    return _load_yaml_file(PATTERNS_DIR / file_name)


def _load_category_patterns(directory_name: str, category: str) -> list[dict]:
    file_path = PATTERNS_DIR / directory_name / f"{category}.yaml"
    data = _load_yaml_file(file_path)

    file_category = data.get("category", category)
    patterns = data.get("patterns", [])

    normalized_patterns = []
    for item in patterns:
        normalized_patterns.append(
            {
                "id": item.get("id", "unknown"),
                "pattern": item["pattern"],
                "description": item.get("description", "Matched security rule"),
                "severity": item.get("severity", 5),
                "category": item.get("category", file_category),
                "source_file": file_path.name,
            }
        )

    return normalized_patterns


def _load_patterns_for_stage(manifest_name: str) -> list[dict]:
    manifest = _load_manifest(manifest_name)
    all_patterns = []

    for category in manifest.get("shared_categories", []):
        all_patterns.extend(_load_category_patterns("shared", category))

    for category in manifest.get("stage_categories", []):
        if "input" in manifest_name:
            all_patterns.extend(_load_category_patterns("input", category))
        else:
            all_patterns.extend(_load_category_patterns("output", category))

    return all_patterns


def _scan_patterns(text: str, patterns: list[dict]) -> tuple[list[str], list[str], int]:
    matched_rules = []
    reasons = []
    max_severity = 0

    for item in patterns:
        pattern = item["pattern"]
        description = item["description"]
        severity = item["severity"]
        category = item["category"]
        rule_id = item.get("id", "unknown")

        try:
            if re.search(pattern, text):
                matched_rules.append(f"{category}:{rule_id}")
                reasons.append(description)
                max_severity = max(max_severity, severity)
        except re.error:
            raise

    return matched_rules, reasons, max_severity


def _build_verdict_from_matches(
    *,
    inspector_used: str,
    matched_rules: list[str],
    reasons: list[str],
    max_severity: int,
    no_match_reason: str,
) -> SecurityVerdict:
    if matched_rules:
        allowed, action = resolve_action(max_severity)
        return SecurityVerdict(
            allowed=allowed,
            action=action,
            risk_score=max_severity,
            reasons=reasons,
            matched_rules=matched_rules,
            inspector_used=inspector_used,
        )

    return SecurityVerdict(
        allowed=True,
        action="allow",
        risk_score=1,
        reasons=[no_match_reason],
        matched_rules=[],
        inspector_used=inspector_used,
    )


INPUT_PATTERNS = _load_patterns_for_stage("input_manifest.yaml")
OUTPUT_PATTERNS = _load_patterns_for_stage("output_manifest.yaml")


class RuleInspector(BaseInspector):
    def inspect_input(self, text: str) -> SecurityVerdict:
        normalized_text = _normalize_text(text)
        matched_rules, reasons, max_severity = _scan_patterns(normalized_text, INPUT_PATTERNS)

        return _build_verdict_from_matches(
            inspector_used="rule_inspector",
            matched_rules=matched_rules,
            reasons=reasons,
            max_severity=max_severity,
            no_match_reason="No known unsafe input patterns detected",
        )

    def inspect_output(self, text: str) -> SecurityVerdict:
        normalized_text = _normalize_text(text)
        matched_rules, reasons, max_severity = _scan_patterns(normalized_text, OUTPUT_PATTERNS)

        return _build_verdict_from_matches(
            inspector_used="rule_inspector",
            matched_rules=matched_rules,
            reasons=reasons,
            max_severity=max_severity,
            no_match_reason="No known unsafe output patterns detected",
        )