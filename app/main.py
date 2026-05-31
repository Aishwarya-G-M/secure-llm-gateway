from app.gateway.service import GatewayInspector
from app.schemas.api import PromptRequest, AttackRunRequest
from app.schemas.gateway import GatewayResponse
from app.clients.llm_client import get_llm_client
from app.schemas.llm import LLMRequest
from app.schemas.security import SecurityVerdict, PolicyAction
from app.security.inspectors.llm_guard_inspector import LLMGuardInspector
from app.security.inspectors.rule_inspector import RuleInspector
from app.security.logger import log_request, get_logs
from fastapi import FastAPI, HTTPException, Depends
from app.security.attack_catalog import ATTACK_PROMPTS
from app.exceptions.llm_error_exceptions import (
    LLMConfigurationError,
    LLMProviderError,
    LLMTimeoutError,
)

app = FastAPI(
    title="Secure LLM Gateway",
    version="0.2.0",
    description="A secure gateway for inspecting, testing, and protecting LLM interactions"
)

def get_gateway_inspector() -> GatewayInspector:
    rule_inspector = RuleInspector()
    llm_client = get_llm_client()
    return GatewayInspector(
        rule_inspector=rule_inspector,
        llm_guard_inspector=LLMGuardInspector(),
        llm_client=llm_client,
    )

# --- Routes ---
@app.get("/")
def read_root():
    return {"message": "API is running"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/analyze", response_model=SecurityVerdict)
async def analyze_prompt(
    request: PromptRequest,
    gateway: GatewayInspector = Depends(get_gateway_inspector),
):
    return gateway.process_input(request)

@app.post("/chat", response_model=GatewayResponse, response_model_exclude_none=True)
async def chat(
    request: PromptRequest,
    gateway: GatewayInspector = Depends(get_gateway_inspector),
):
    try:
        return gateway.process_chat_input(request)
    except LLMConfigurationError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except LLMTimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except LLMProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.get("/logs")
async def fetch_logs():
    return {"logs": get_logs(), "total": len(get_logs())}


@app.get("/attacks")
async def get_attacks(category: str = None, context: str = None, severity: str = None):
    """
    Returns the curated attack prompt library.
    Optional filters: category, context
    """
    results = ATTACK_PROMPTS

    if category:
        results = [a for a in results if a.get("category").lower() == category.lower()]
    if context:
        results = [a for a in results if a.get("context").lower() == context.lower()]
    if severity:
        results = [a for a in results if a.get("severity", "").lower() == severity.lower()]

    return {"attacks": results, "total": len(results)}

@app.get("/attacks/{attack_id}")
async def get_attack_by_id(attack_id: str):
    attack = next(
        (item for item in ATTACK_PROMPTS if item.get("id", "").lower() == attack_id.lower()),
        None
    )
    if not attack:
        raise HTTPException(status_code=404, detail="Attack scenario not found")
    return attack

@app.post("/attacks/run")
async def run_attack(
    request: AttackRunRequest,
    gateway: GatewayInspector = Depends(get_gateway_inspector),
):
    attack = next((item for item in ATTACK_PROMPTS if item.get("id") == request.id), None)

    if not attack:
        raise HTTPException(status_code=404, detail="Attack scenario not found")

    prompt_request = PromptRequest(
        prompt=attack["prompt"],
        system_prompt="You are a helpful assistant.",
    )

    inspection = gateway.process_input(prompt_request)

    if inspection.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}:
        log_request(
            endpoint="/attacks/run",
            prompt=attack["prompt"],
            is_safe=False,
            reason=", ".join(inspection.reasons) if inspection.reasons else "Blocked by policy",
        )
        return {
            "id": attack["id"],
            "category": attack["category"],
            "context": attack.get("context"),
            "severity": attack.get("severity"),
            "owasp_ref": attack.get("owasp_ref"),
            "blocked": True,
            "reason": inspection.reasons,
            "response": None,
        }

    try:
        llm_request = LLMRequest(
            prompt=attack["prompt"],
            system_prompt="You are a helpful assistant.",
        )
        llm_response = gateway.llm_client.generate(llm_request)
    except LLMConfigurationError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except LLMTimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except LLMProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))

    log_request(
        endpoint="/attacks/run",
        prompt=attack["prompt"],
        is_safe=True,
        reason=", ".join(inspection.reasons) if inspection.reasons else "Allowed",
        response=llm_response.content,
    )

    return {
        "id": attack["id"],
        "category": attack["category"],
        "context": attack.get("context"),
        "severity": attack.get("severity"),
        "owasp_ref": attack.get("owasp_ref"),
        "blocked": False,
        "reason": inspection.reasons,
        "response": llm_response.content,
    }