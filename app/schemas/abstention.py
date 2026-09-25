from typing import Any, Literal
from pydantic import BaseModel, Field


class AbstentionRequest(BaseModel):
    query: str
    backend: Literal["vector_rag", "graphrag"]
    top_k: int | None = Field(default=None, ge=1, le=100)
    parameters: dict[str, Any] = Field(default_factory=dict)

class AbstentionResult(BaseModel):
    query: str
    backend: str
    abstention_status: Literal["answer", "abstain"]
    is_spam: bool | None = None
    answer: str | None = None
    abstention_reason: str | None = None
    retrieval_metadata: dict[str, Any] = Field(
        default_factory=dict
    )
    trace_id: str | None = None