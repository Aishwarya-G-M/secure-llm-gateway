from pydantic import BaseModel

from app.schemas.security_verdict import SecurityVerdict

class GatewayRequest(BaseModel):
    prompt: str
    system_prompt: str | None = None

class GatewayResponse(BaseModel):
    input_verdict: SecurityVerdict
    output_verdict: SecurityVerdict | None = None
    llm_output: str | None = None