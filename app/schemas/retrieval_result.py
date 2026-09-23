from pydantic import BaseModel, Field

class RetrievalResult(BaseModel):
    answer: str
    sources: list[dict] = Field(default_factory=list)
    provider: str
    model: str | None = None
    trace_id: str | None = None