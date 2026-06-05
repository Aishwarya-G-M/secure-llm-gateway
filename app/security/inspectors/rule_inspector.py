import re
import unicodedata
from pathlib import Path

import yaml

from app.exceptions.policy import RuleInspectorError
from app.models.inspection_context import InspectionContext
from app.schemas.security_verdict import PolicyAction, SecurityVerdict
from app.security.inspectors.base import BaseInspector
from app.security.policy import resolve_action

PATTERNS_DIR = Path(__file__).resolve().parent.parent / "patterns"
ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
CONTROL_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
MAX_PROMPT_CHARS = 8_000
MAX_SYSTEM_PROMPT_CHARS = 4_000

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


def _scan_patterns(text: str, patterns: list[dict]) -> tuple[list[str], list[str], int, list[dict]]:
    matched_rules = []
    reasons = []
    max_severity = 0
    match_details = []

    for item in patterns:
        pattern = item["pattern"]
        description = item["description"]
        severity = item["severity"]
        category = item["category"]
        rule_id = item.get("id", "unknown")
        source_file = item.get("source_file")

        try:
            if re.search(pattern, text):
                matched_rules.append(f"{category}:{rule_id}")
                reasons.append(description)
                max_severity = max(max_severity, severity)
                match_details.append(
                    {
                        "rule_id": rule_id,
                        "category": category,
                        "severity": severity,
                        "description": description,
                        "source_file": source_file,
                    }
                )
        except re.error:
            raise

    return matched_rules, reasons, max_severity, match_details


def _build_verdict_from_matches(
    *,
    inspector_used: str,
    stage: str,
    matched_rules: list[str],
    reasons: list[str],
    max_severity: int,
    no_match_reason: str,
    match_details: list[dict],
    context: InspectionContext | None = None,
) -> SecurityVerdict:
    if matched_rules:
        allowed, action = resolve_action(max_severity)
        return SecurityVerdict(
            allowed=allowed,
            action=action,
            risk_score=float(max_severity),
            reasons=reasons,
            matched_rules=matched_rules,
            inspector_used=inspector_used,
            metadata={
                "provider": "custom_rules",
                "stage": stage,
                "match_count": len(matched_rules),
                "matches": match_details,
                "route": context.route if context else None,
                "model_name": context.model_name if context else None,
                "request_id": context.request_id if context else None,
                "trace_id": context.trace_id if context else None,
            },
        )

    return SecurityVerdict(
        allowed=True,
        action=PolicyAction.ALLOW,
        risk_score=1.0,
        reasons=[no_match_reason],
        matched_rules=[],
        inspector_used=inspector_used,
        metadata={
            "provider": "custom_rules",
            "stage": stage,
            "match_count": 0,
            "route": context.route if context else None,
            "model_name": context.model_name if context else None,
        },
    )

def _build_size_limit_verdict(
    *,
    field_name: str,
    actual_chars: int,
    max_chars: int,
    rule_id: str,
    context: InspectionContext | None = None,
) -> SecurityVerdict:
    return SecurityVerdict(
        allowed=False,
        action=PolicyAction.BLOCK,
        risk_score=8.0,
        reasons=[f"{field_name} exceeds maximum length of {max_chars} characters"],
        matched_rules=[rule_id],
        inspector_used="rule_inspector",
        metadata={
            "provider": "custom_rules",
            "stage": "input",
            "route": context.route if context else None,
            "model_name": context.model_name if context else None,
            "request_id": context.request_id if context else None,
            "trace_id": context.trace_id if context else None,
            "field_name": field_name,
            "actual_chars": actual_chars,
            "max_chars": max_chars,
        },
    )

INPUT_PATTERNS = _load_patterns_for_stage("input_manifest.yaml")
OUTPUT_PATTERNS = _load_patterns_for_stage("output_manifest.yaml")

class RuleInspector(BaseInspector):
    def inspect_input(
        self,
        text: str,
        context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        try:
            if len(text) > MAX_PROMPT_CHARS:
                return _build_size_limit_verdict(
                    field_name="prompt",
                    actual_chars=len(text),
                    max_chars=MAX_PROMPT_CHARS,
                    rule_id="input_size:prompt_too_long",
                    context=context,
                )
            system_prompt = None
            if context is not None:
                system_prompt = context.metadata.get("system_prompt")

            if system_prompt and len(system_prompt) > MAX_SYSTEM_PROMPT_CHARS:
                return _build_size_limit_verdict(
                    field_name="system_prompt",
                    actual_chars=len(system_prompt),
                    max_chars=MAX_SYSTEM_PROMPT_CHARS,
                    rule_id="input_size:system_prompt_too_long",
                    context=context,
                )

            normalized_text = _normalize_text(text)
            matched_rules, reasons, max_severity, match_details = _scan_patterns(
                normalized_text,
                INPUT_PATTERNS,
            )

            return _build_verdict_from_matches(
                inspector_used="rule_inspector",
                stage="input",
                matched_rules=matched_rules,
                reasons=reasons,
                max_severity=max_severity,
                no_match_reason="No known unsafe input patterns detected",
                match_details=match_details,
                context=context,
            )
        except Exception as exc:
            raise RuleInspectorError("Failed to inspect input") from exc

    def inspect_output(
        self,
        text: str,
        context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        try:
            normalized_text = _normalize_text(text)
            matched_rules, reasons, max_severity, match_details = _scan_patterns(
                normalized_text,
                OUTPUT_PATTERNS,
            )

            return _build_verdict_from_matches(
                inspector_used="rule_inspector",
                stage="output",
                matched_rules=matched_rules,
                reasons=reasons,
                max_severity=max_severity,
                no_match_reason="No known unsafe output patterns detected",
                match_details=match_details,
                context=context,
            )
        except Exception as exc:
            raise RuleInspectorError("Failed to inspect output") from exc
