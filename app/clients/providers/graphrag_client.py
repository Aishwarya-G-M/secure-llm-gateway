from __future__ import annotations

from typing import Any

import httpx

from app.config.downstream_settings import settings
from app.schemas.abstention import AbstentionResult
from app.schemas.retrieval_result import RetrievalResult


class GraphRAGClient:
    def query(
        self,
        message: str,
        *,
        trace_id: str | None = None,
    ) -> RetrievalResult:
        url = (
            f"{settings.graphrag_base_url.rstrip('/')}"
            f"{settings.graphrag_query_path}"
        )

        try:
            response = httpx.post(
                url,
                json={"message": message},
                headers={
                    "X-Trace-ID": trace_id,
                } if trace_id else {},
                timeout=settings.downstream_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            raise

        data = response.json()

        return RetrievalResult(
            answer=data.get("answer", data.get("response", "")),
            sources=data.get(
                "retrieved",
                data.get("sources", []),
            ),
            provider="graphrag",
            model=data.get("model"),
            trace_id=trace_id,
        )

    def evaluate_abstention(
        self,
        query: str,
        *,
        parameters: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> AbstentionResult:
        url = (
            f"{settings.graphrag_base_url.rstrip('/')}"
            f"{settings.graphrag_evaluation_path}"
        )

        headers = {
            "X-Trace-ID": trace_id,
        } if trace_id else {}

        payload: dict[str, Any] = {
            "query": query,
        }

        if parameters:
            payload["parameters"] = parameters

        try:
            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=settings.downstream_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            raise

        data = response.json()

        self._validate_evaluation_response(data)

        return AbstentionResult(
            query=data.get("query", query),
            backend="graphrag",
            abstention_status=data["abstention_status"],
            is_spam=data.get("is_spam"),
            answer=data.get("answer"),
            abstention_reason=data.get(
                "abstention_reason"
            ),
            retrieval_metadata={
                **data.get("retrieval_metadata", {}),
                "trace_id": trace_id,
            },
        )

    @staticmethod
    def _validate_evaluation_response(
        data: Any,
    ) -> None:
        if not isinstance(data, dict):
            raise ValueError(
                "GraphRAG evaluation response must be a JSON object"
            )

        required_fields = {
            "query",
            "abstention_status",
            "answer",
            "abstention_reason",
        }

        missing_fields = required_fields.difference(data)

        if missing_fields:
            raise ValueError(
                "GraphRAG evaluation response is missing fields: "
                f"{sorted(missing_fields)}"
            )

        status = data["abstention_status"]

        if status not in {"answer", "abstain"}:
            raise ValueError(
                "Invalid GraphRAG abstention_status: "
                f"{status!r}"
            )

        answer = data["answer"]
        reason = data["abstention_reason"]

        if status == "abstain":
            if answer is not None:
                raise ValueError(
                    "An abstained response must have answer=null"
                )

            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(
                    "An abstained response must have a non-empty "
                    "abstention_reason"
                )

        if status == "answer":
            if not isinstance(answer, str) or not answer.strip():
                raise ValueError(
                    "An answer response must have a non-empty "
                    "answer"
                )

            if reason is not None:
                raise ValueError(
                    "An answer response must have "
                    "abstention_reason=null"
                )