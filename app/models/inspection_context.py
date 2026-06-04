from pydantic import BaseModel, Field
from typing import Any

class InspectionContext(BaseModel):
    prompt: str | None = None
    user_id: str | None = None
    route: str | None = None
    model_name: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)