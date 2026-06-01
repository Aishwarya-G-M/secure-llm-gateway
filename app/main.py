from app.gateway.orchestrator import GatewayOrchestrator
from app.schemas.gateway import GatewayResponse, GatewayRequest
from app.clients.llm_client import get_llm_client
from app.schemas.security_verdict import PolicyAction
from app.security.inspectors.llm_guard_inspector import LLMGuardInspector
from app.security.inspectors.rule_inspector import RuleInspector
from fastapi import FastAPI, HTTPException, Depends
from app.exceptions.llm_error_exceptions import (
    LLMConfigurationError,
    LLMProviderError,
    LLMTimeoutError,
)

app = FastAPI(
    title="Secure LLM Gateway",
    version="0.3.0",
    description="A secure LLM gateway for “LLM hacking” defense: inspecting, testing, and protecting AI interactions end‑to‑end."
)

def get_gateway_inspector() -> GatewayOrchestrator:
    rule_inspector = RuleInspector()
    llm_guard_inspector = LLMGuardInspector(
        threshold=0.5,
        entity_types=["PERSON", "EMAIL"],
        output_violation_action=PolicyAction.BLOCK,
    )
    llm_client = get_llm_client()

    return GatewayOrchestrator(
        rule_inspector=rule_inspector,
        llm_guard_inspector=llm_guard_inspector,
        llm_client=llm_client,
    )

# --- Routes ---
@app.get("/")
def read_root():
    return {"message": "API is running"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/chat", response_model=GatewayResponse, response_model_exclude_none=True)
async def chat(
    request: GatewayRequest,
    gateway: GatewayOrchestrator = Depends(get_gateway_inspector),
):
    try:
        return gateway.process_chat_input(request)
    except LLMConfigurationError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except LLMTimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except LLMProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))