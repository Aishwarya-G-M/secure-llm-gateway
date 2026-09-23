import httpx

from app.config.downstream_settings import settings
from app.schemas.retrieval_result import RetrievalResult


class GraphRagClient:
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

        response = httpx.post(
            url,
            json={"message": message},
            headers={"X-Trace-ID": trace_id} if trace_id else {},
            timeout=settings.downstream_timeout_seconds,
        )
        response.raise_for_status()

        data = response.json()

        return RetrievalResult(
            answer=data["answer"],
            sources=data.get("sources", []),
            provider=data.get("provider", "graphrag"),
            model=data.get("model"),
            trace_id=trace_id,
        )