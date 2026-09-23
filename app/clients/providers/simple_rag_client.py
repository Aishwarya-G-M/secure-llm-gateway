import httpx
import logging

from app.config.downstream_settings import settings
from app.schemas.retrieval_result import RetrievalResult

logger = logging.getLogger(__name__)

class SimpleRagClient:
    def query(self, message: str, *, trace_id: str | None = None) -> RetrievalResult:
        url = (
            f"{settings.simple_rag_base_url.rstrip('/')}"
            f"{settings.simple_rag_query_path}"
        )

        try:
            response = httpx.post(
                url,
                json={"message": message, "top_k": 6},
                headers={"X-Trace-ID": trace_id} if trace_id else {},
                timeout=settings.downstream_timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            logger.exception(
                "Simple RAG request failed: url=%s trace_id=%s",
                url,
                trace_id,
            )
            raise

        data = response.json()

        return RetrievalResult(
            answer=data["answer"],
            sources=data.get("retrieved", data.get("sources", [])),
            provider="simple-rag",
            model=data.get("model"),
            trace_id=trace_id,
        )