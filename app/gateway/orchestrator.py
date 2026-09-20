from typing import Any, Literal

import requests
import subprocess
from pathlib import Path

from app.clients.llm_protocol import LlmClientProtocol
from app.exceptions.gateway import GatewayInspectionError, GatewayExecutionError
from app.exceptions.llm import LLMError
from app.exceptions.policy import PolicyError
from app.core.logging_setup import logger
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
    metadata = {}

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
                (
                    verdict.metadata.get("request_id")
                    for verdict in verdicts
                    if verdict.metadata.get("request_id")
                ),
                None,
            ),
            "trace_id": next(
                (
                    verdict.metadata.get("trace_id")
                    for verdict in verdicts
                    if verdict.metadata.get("trace_id")
                ),
                None,
            ),
        },
    )


class GatewayOrchestrator:
    def __init__(
        self,
        rule_inspector: BaseInspector,
        llm_guard_inspector: BaseInspector,
        llm_client: LlmClientProtocol,
        system_prompt: str,
        vector_rag_url: str = "http://localhost:8001/rag/query",
        graphrag_root: str = "/Users/aishwaryagm/2026/Python/graphrag-fraud-experiments",
    ) -> None:
        self.rule_inspector = rule_inspector
        self.llm_guard_inspector = llm_guard_inspector
        self.llm_client = llm_client
        self.system_prompt = system_prompt

        self.vector_rag_url = vector_rag_url
        self.graphrag_root = Path(graphrag_root)

    def process_input(
        self,
        request: GatewayRequest,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> SecurityVerdict:
        try:
            context = _build_context(
                request,
                route="/chat",
                request_id=request_id,
                trace_id=trace_id,
            )

            try:
                rule_verdict = self.rule_inspector.inspect_input(
                    request.prompt,
                    context=context,
                )
            except Exception as exc:
                logger.error(
                    "rule_inspector_failed",
                    extra={
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "error": str(exc),
                    },
                )
                raise GatewayInspectionError("Rule inspector failed") from exc

            if rule_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return rule_verdict

            try:
                llm_guard_verdict = self.llm_guard_inspector.inspect_input(
                    request.prompt,
                    context=context,
                )
            except Exception as exc:
                logger.error(
                    "llm_guard_inspector_failed",
                    extra={
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "error": str(exc),
                    },
                )
                raise GatewayInspectionError("LLM Guard inspector failed") from exc

            if llm_guard_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return llm_guard_verdict

            return _merge_allow_verdicts(rule_verdict, llm_guard_verdict)

        except GatewayInspectionError:
            raise
        except PolicyError as exc:
            raise GatewayInspectionError("Failed to inspect gateway input") from exc
        except Exception as exc:
            raise GatewayInspectionError(
                "Unexpected error during gateway input inspection"
            ) from exc

    def process_llm_output(
        self,
        llm_output: str,
        request: GatewayRequest,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> SecurityVerdict:
        try:
            context = _build_context(
                request,
                route="/chat",
                request_id=request_id,
                trace_id=trace_id,
            )

            try:
                rule_verdict = self.rule_inspector.inspect_output(
                    llm_output,
                    context=context,
                )
            except Exception as exc:
                logger.error(
                    "rule_inspector_output_failed",
                    extra={
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "error": str(exc),
                    },
                )
                raise GatewayInspectionError("Rule inspector failed for output") from exc

            if rule_verdict.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
                return rule_verdict

            try:
                llm_guard_verdict = self.llm_guard_inspector.inspect_output(
                    llm_output,
                    context=context,
                )
            except Exception as exc:
                logger.error(
                    "llm_guard_inspector_output_failed",
                    extra={
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "error": str(exc),
                    },
                )
                raise GatewayInspectionError("LLM Guard inspector failed for output") from exc

            if llm_guard_verdict.action in {
                PolicyAction.BLOCK,
                PolicyAction.REVIEW,
                PolicyAction.REDACT,
            }:
                return llm_guard_verdict

            return _merge_allow_verdicts(rule_verdict, llm_guard_verdict)

        except GatewayInspectionError:
            raise
        except PolicyError as exc:
            raise GatewayInspectionError("Failed to inspect gateway output") from exc
        except Exception as exc:
            raise GatewayInspectionError(
                "Unexpected error during gateway output inspection"
            ) from exc

    # ---------- New helpers for RAG backends ----------

    def _call_vector_rag(self, prompt: str) -> str:
        """
        Call the vector-only RAG service and return the 'answer' field.
        Expected RAG request:
          {"message": "<prompt>", "top_k": 6}
        Expected RAG response:
          {"answer": "...", "retrieved": [...]}
        """
        payload = {"message": prompt, "top_k": 6}
        resp = requests.post(
            self.vector_rag_url,
            json=payload,
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("answer", "")

    def _call_graph_rag(self, prompt: str) -> str:
        # Debug: write incoming request details to a file
        debug_path = Path("/Users/aishwaryagm/2026/Python/tmp/gateway_request_debug.txt")
        debug_path.write_text(
            f"prompt: {prompt.prompt}\n"
            f"backend attr: {getattr(prompt, 'backend', 'MISSING')}\n"
            f"backend value: {prompt.backend}\n"
        )
        # TODO: replace with your actual path
        graphrag_root = Path("/Users/aishwaryagm/2026/Python/graphrag-fraud-experiments")

        cmd = [
            "/Users/aishwaryagm/2026/Python/graphrag-fraud-experiments/.venv/bin/python",
            "-m",
            "graphrag",
            "query",
            "--root",
            str(graphrag_root),
            "--method",
            "local",
            prompt,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )

        # Write debug info to a file you can inspect
        debug_path = Path("/tmp/graphrag_debug.txt")
        debug_path.write_text(
            f"graphrag_root: {graphrag_root}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"returncode: {result.returncode}\n"
            f"stdout_len: {len(result.stdout)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
        )

        return result.stdout.strip()

    # --------------------------------------------------

    def process_chat_input(
            self,
            prompt_request: GatewayRequest,
            request_id: str | None = None,
            trace_id: str | None = None,
    ) -> GatewayResponse:
        # Debug: write request info
        debug_path = Path("/tmp/gateway_debug.txt")
        debug_path.write_text(
            f"prompt: {prompt_request.prompt}\n"
            f"backend: {prompt_request.backend}\n"
        )

        try:
            input_security_verdict = self.process_input(
                prompt_request,
                request_id=request_id,
                trace_id=trace_id,
            )

            if input_security_verdict.action in {
                PolicyAction.BLOCK,
                PolicyAction.REVIEW,
            }:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=None,
                    llm_output=None,
                )

            # Backend selection
            backend = prompt_request.backend

            if backend == "default_llm":
                from app.schemas.llm import LLMRequest
                llm_request = LLMRequest(
                    prompt=prompt_request.prompt,
                    system_prompt=self.system_prompt,
                )
                llm_response = self.llm_client.generate(llm_request)
                answer = llm_response.content

            elif backend == "vector_rag":
                answer = self._call_vector_rag(prompt_request.prompt)

            elif backend == "graph_rag":
                # Call GraphRAG and write debug info
                graphrag_root = Path("/Users/aishwaryagm/2026/Python/graphrag-fraud-experiments")

                cmd = [
                    "/Users/aishwaryagm/2026/Python/graphrag-fraud-experiments/.venv/bin/python",
                    "-m",
                    "graphrag",
                    "query",
                    "--root",
                    str(graphrag_root),
                    "--method",
                    "local",
                    prompt_request.prompt,
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )

                # Write GraphRAG debug info
                gr_debug_path = Path("/tmp/graphrag_call_debug.txt")
                gr_debug_path.write_text(
                    f"graphrag_root: {graphrag_root}\n"
                    f"cmd: {' '.join(cmd)}\n"
                    f"returncode: {result.returncode}\n"
                    f"stdout_len: {len(result.stdout)}\n"
                    f"stdout:\n{result.stdout}\n"
                    f"stderr:\n{result.stderr}\n"
                )

                answer = result.stdout.strip()

            else:
                # Fallback to default LLM
                from app.schemas.llm import LLMRequest
                llm_request = LLMRequest(
                    prompt=prompt_request.prompt,
                    system_prompt=self.system_prompt,
                )
                llm_response = self.llm_client.generate(llm_request)
                answer = llm_response.content

            output_security_verdict = self.process_llm_output(
                answer,
                prompt_request,
                request_id=request_id,
                trace_id=trace_id,
            )

            if output_security_verdict.action == PolicyAction.ALLOW:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=output_security_verdict,
                    llm_output=answer,
                )

            if output_security_verdict.action in {PolicyAction.REDACT, PolicyAction.BLOCK}:
                # For this experiment, use sanitized_text even when blocked,
                # so we get non-empty answers to evaluate.
                final_text = (
                        output_security_verdict.sanitized_text
                        or "Response withheld by safety policy"
                )
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=output_security_verdict,
                    llm_output=final_text,
                )

            if output_security_verdict.action == PolicyAction.REVIEW:
                return GatewayResponse(
                    input_verdict=input_security_verdict,
                    output_verdict=output_security_verdict,
                    llm_output="Response withheld by safety policy",
                )

            return GatewayResponse(
                input_verdict=input_security_verdict,
                output_verdict=output_security_verdict,
                llm_output=answer,
            )

        except (GatewayInspectionError, LLMError) as exc:
            raise GatewayExecutionError("Failed to process secure chat request") from exc
        except Exception as exc:
            raise GatewayExecutionError("Unexpected error during secure chat processing") from exc