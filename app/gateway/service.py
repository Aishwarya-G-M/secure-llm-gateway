from app.clients.llm_protocol import LlmClientProtocol
from app.models.security_models import InspectionContext
from app.schemas.api import PromptRequest
from app.schemas.gateway import GatewayResponse
from app.schemas.llm import LLMRequest
from app.schemas.security import PolicyAction, SecurityVerdict
from app.security.inspectors.base import BaseInspector


class GatewayInspector:
    def __init__(
        self,
        rule_inspector: BaseInspector,
        llm_guard_inspector: BaseInspector,
        llm_client: LlmClientProtocol,
    ) -> None:
        self.rule_inspector = rule_inspector
        self.llm_guard_inspector = llm_guard_inspector
        self.llm_client = llm_client

    def _build_context(self, request: PromptRequest) -> InspectionContext:
        return InspectionContext(
            prompt=request.prompt,
            route="/chat",
            metadata={
                "system_prompt": request.system_prompt,
            },
        )

    def _merge_allow_verdicts(
        self,
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
            },
        )

    def process_input(self, request: PromptRequest) -> SecurityVerdict:
        context = self._build_context(request)

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

        return self._merge_allow_verdicts(rule_verdict, llm_guard_verdict)

    def process_llm_output(
        self,
        llm_output: str,
        request: PromptRequest,
    ) -> SecurityVerdict:
        context = self._build_context(request)

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
        if llm_guard_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW, PolicyAction.REDACT}:
            return llm_guard_verdict

        return self._merge_allow_verdicts(rule_verdict, llm_guard_verdict)

    def process_chat_input(self, prompt_request: PromptRequest) -> GatewayResponse:
        input_security_verdict = self.process_input(prompt_request)

        if input_security_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
            return GatewayResponse(
                input_verdict=input_security_verdict,
                output_verdict=None,
                llm_output=None,
            )

        llm_request = LLMRequest(
            prompt=prompt_request.prompt,
            system_prompt=prompt_request.system_prompt or "You are a helpful assistant.",
        )

        llm_response = self.llm_client.generate(llm_request)
        output_security_verdict = self.process_llm_output(
            llm_response.content,
            prompt_request,
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
                llm_output=output_security_verdict.sanitized_text or "Response redacted by safety policy",
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