from pydantic import BaseModel, ConfigDict
from typing import Literal

from app.schemas.security_verdict import SecurityVerdict

class GatewayRequest(BaseModel):
    prompt: str
    model_config = ConfigDict(extra="forbid")
    backend: Literal["default_llm", "vector_rag", "graph_rag"] = "default_llm"

class GatewayResponse(BaseModel):
    input_verdict: SecurityVerdict
    output_verdict: SecurityVerdict | None = None
    llm_output: str | None = None