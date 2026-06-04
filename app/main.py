from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request

from app.clients.llm_client import get_llm_client
from app.core.resources import create_app_resources
from app.exceptions.gateway import GatewayInspectionError, GatewayExecutionError
from app.exceptions.llm import (
    LLMConfigurationError,
    LLMProviderError,
    LLMTimeoutError,
)
from app.gateway.orchestrator import GatewayOrchestrator
from app.schemas.gateway import GatewayRequest, GatewayResponse
from app.security.inspectors.rule_inspector import RuleInspector


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.resources = create_app_resources()
    yield


app = FastAPI(
    title="Secure LLM Gateway",
    version="0.4.0",
    description="A secure LLM gateway for “LLM hacking” defense: inspecting, testing, and protecting AI interactions end‑to‑end.",
    lifespan=lifespan,
)


def get_gateway_inspector(request: Request) -> GatewayOrchestrator:
    resources = request.app.state.resources
    llm_client = get_llm_client()

    return GatewayOrchestrator(
        rule_inspector=RuleInspector(),
        llm_guard_inspector=resources.llm_guard_inspector,
        llm_client=llm_client,
    )


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

    except GatewayInspectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    except GatewayExecutionError as exc:
        cause = exc.__cause__

        if isinstance(cause, LLMConfigurationError):
            raise HTTPException(status_code=503, detail=str(cause)) from exc

        if isinstance(cause, LLMTimeoutError):
            raise HTTPException(status_code=504, detail=str(cause)) from exc

        if isinstance(cause, LLMProviderError):
            raise HTTPException(status_code=502, detail=str(cause)) from exc

        raise HTTPException(status_code=500, detail=str(exc)) from exc