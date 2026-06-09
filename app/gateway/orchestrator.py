from typing import Any

from fastapi import Path

from app.clients.llm_protocol import LlmClientProtocol
from app.exceptions.gateway import GatewayInspectionError, GatewayExecutionError
from app.exceptions.llm import LLMError
from app.exceptions.policy import PolicyError
from app.models.inspection_context import InspectionContext
from app.schemas.gateway import GatewayResponse, GatewayRequest
from app.schemas.llm import LLMRequest
from app.schemas.security_verdict import PolicyAction, SecurityVerdict
from app.security.inspectors.base import BaseInspector

def _build_context(
    request: GatewayRequest,
    *,
    route: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    model_name: str | None = None,
    user_id: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> InspectionContext:
    metadata = { }

    if extra_metadata:
        metadata.update(extra_metadata)

    return InspectionContext(
        prompt=request.prompt,
        user_id=user_id,
        route=route,
        model_name=model_name,
        request_id=request_id,
        trace_id=trace_id,
        metadata=metadata,
    )

def _merge_allow_verdicts(
        *verdicts: SecurityVerdict,
    inspector_name: str = "gateway_inspector",
) -> SecurityVerdict:
    return SecurityVerdict(
        allowed=True,
        action=PolicyAction.ALLOW,
        risk_score=max((verdict.risk_score for verdict in verdicts), default=0.0),
        reasons=[reason for verdict in verdicts for reason in verdict.reasons],
        matched_rules=[
            rule for verdict in verdicts for rule in verdict.matched_rules
        ],
        inspector_used=inspector_name,
        metadata={
            "merged_from": [verdict.inspector_used for verdict in verdicts],
            "request_id": next(
                (verdict.metadata.get("request_id") for verdict in verdicts if verdict.metadata.get("request_id")),
                None,
            ),
            "trace_id": next(
                (verdict.metadata.get("trace_id") for verdict in verdicts if verdict.metadata.get("trace_id")),
                None,
            ),
        }
    )


class GatewayOrchestrator:
    def __init__(
        self,
        rule_inspector: BaseInspector,
        llm_guard_inspector: BaseInspector,
        llm_client: LlmClientProtocol,
        system_prompt: str,
    ) -> None:
        self.rule_inspector = rule_inspector
        self.llm_guard_inspector = llm_guard_inspector
        self.llm_client = llm_client
        self.system_prompt = system_prompt

    def process_input(
            self,
            request: GatewayRequest,
            request_id: str | None = None,
            trace_id: str | None = None,
    ) -> SecurityVerdict:
        try:
            context = _build_context(request,route="/chat",request_id=request_id,trace_id=trace_id)

            rule_verdict = self.rule_inspector.inspect_input(
                request.prompt,
                context=context,
            )
            if rule_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return rule_verdict

            llm_guard_verdict = self.llm_guard_inspector.inspect_input(
                request.prompt,
                context=context,
            )
            if llm_guard_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return llm_guard_verdict

            return _merge_allow_verdicts(rule_verdict, llm_guard_verdict)

        except PolicyError as exc:
            raise GatewayInspectionError("Failed to inspect gateway input") from exc
        except Exception as exc:
            raise GatewayInspectionError("Unexpected error during gateway input inspection") from exc

    def process_llm_output(
            self,
            llm_output: str,
            request: GatewayRequest,
            request_id: str | None = None,
            trace_id: str | None = None,
    ) -> SecurityVerdict:
        try:
            context = _build_context(request,route="/chat",request_id=request_id,trace_id=trace_id)

            rule_verdict = self.rule_inspector.inspect_output(
                llm_output,
                context=context,
            )
            if rule_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return rule_verdict

            llm_guard_verdict = self.llm_guard_inspector.inspect_output(
                llm_output,
                context=context,
            )
            if llm_guard_verdict.action in {
                PolicyAction.BLOCK,
                PolicyAction.REVIEW,
                PolicyAction.REDACT,
            }:
                return llm_guard_verdict

            return _merge_allow_verdicts(rule_verdict, llm_guard_verdict)

        except PolicyError as exc:
            raise GatewayInspectionError("Failed to inspect gateway output") from exc
        except Exception as exc:
            raise GatewayInspectionError("Unexpected error during gateway output inspection") from exc

    def process_chat_input(
            self,
            prompt_request: GatewayRequest,
            request_id: str | None = None,
            trace_id: str | None = None,
    ) -> GatewayResponse:
        try:
            input_security_verdict = self.process_input(
                prompt_request,
                request_id=request_id,
                trace_id=trace_id,
            )

            if input_security_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=None,
                    llm_output=None,
                )

            llm_request = LLMRequest(
                prompt=prompt_request.prompt,
                system_prompt=self.system_prompt,
            )

            llm_response = self.llm_client.generate(llm_request)
            output_security_verdict = self.process_llm_output(
                llm_response.content,
                prompt_request,
                request_id=request_id,
                trace_id=trace_id,
            )

            if output_security_verdict.action == PolicyAction.ALLOW:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=output_security_verdict,
                    llm_output=llm_response.content,
                )

            if output_security_verdict.action == PolicyAction.REDACT:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=output_security_verdict,
                    llm_output=output_security_verdict.sanitized_text
                               or "Response redacted by safety policy",
                )

            if output_security_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=output_security_verdict,
                    llm_output="Response withheld by safety policy",
                )

            return GatewayResponse(
                input_verdict=input_security_verdict,
                output_verdict=output_security_verdict,
                llm_output=llm_response.content,
            )

        except (GatewayInspectionError, LLMError) as exc:
            raise GatewayExecutionError("Failed to process secure chat request") from exc
        except Exception as exc:
            raise GatewayExecutionError("Unexpected error during secure chat processing") from exc