from app.clients.llm_protocol import LlmClientProtocol
from app.schemas.api import PromptRequest
from app.schemas.gateway import GatewayResponse
from app.schemas.security import SecurityVerdict, PolicyAction
from app.security.inspectors.llm_guard_inspector import LLMGuardInspector
from app.security.inspectors.rule_inspector import RuleInspector
from app.schemas.llm import LLMRequest

class GatewayInspector:
    def __init__(
            self,
            rule_inspector: RuleInspector,
            llm_guard_inspector: LLMGuardInspector,
            llm_client: LlmClientProtocol,
    ) -> None:
        self.rule_inspector = rule_inspector
        self.llm_guard_inspector = llm_guard_inspector
        self.llm_client = llm_client

    def process_input(self, request: PromptRequest) -> SecurityVerdict:
        rule_verdict = self.rule_inspector.inspect_input(request.prompt)

        if rule_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
            return rule_verdict

        llm_guard_verdict = self.llm_guard_inspector.inspect_input(request.prompt)

        if llm_guard_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
            return llm_guard_verdict

        return rule_verdict

    def process_llm_output(self, llm_output: str) -> SecurityVerdict:
        return self.rule_inspector.inspect_output(llm_output)

    def process_chat_input(self, prompt_request: PromptRequest) -> GatewayResponse | None:
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
        output_security_verdict = self.process_llm_output(llm_response.content)

        if output_security_verdict.action == PolicyAction.ALLOW:
            return GatewayResponse(
                input_verdict=input_security_verdict,
                output_verdict=output_security_verdict,
                llm_output=llm_response.content,
            )

        if output_security_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW, PolicyAction.REDACT}:
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