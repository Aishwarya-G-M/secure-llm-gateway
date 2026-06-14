from pydantic import BaseModel, ConfigDict

from app.schemas.security_verdict import SecurityVerdict

class GatewayRequest(BaseModel):
    prompt: str
    model_config = ConfigDict(extra="forbid")

class GatewayResponse(BaseModel):
    input_verdict: SecurityVerdict
    output_verdict: SecurityVerdict | None = None
    llm_output: str | None = None