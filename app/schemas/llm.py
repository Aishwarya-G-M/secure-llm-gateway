from typing import Optional

from pydantic import BaseModel, Field

class LLMMetadata(BaseModel):
    request_id: Optional[str] = Field(default=None)
    provider: str
    model: str
    latency_ms: int = Field(ge=0)


class LLMRequest(BaseModel):
    prompt: str = Field(min_length=1)
    system_prompt: str = "You are a helpful assistant."


class LLMResponse(BaseModel):
    content: str
    metadata: LLMMetadata
    input_tokens: Optional[int] = Field(default=None, ge=0)
    output_tokens: Optional[int] = Field(default=None, ge=0)
    total_tokens: Optional[int] = Field(default=None, ge=0)