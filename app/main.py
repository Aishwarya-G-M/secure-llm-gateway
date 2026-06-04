import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from app.clients.llm_client import get_llm_client
from app.core.logging_setup import configure_logging
from app.core.resources import create_app_resources
from app.exceptions.gateway import GatewayInspectionError, GatewayExecutionError
from app.exceptions.llm import (
    LLMConfigurationError,
    LLMProviderError,
    LLMTimeoutError,
)
from app.gateway.orchestrator import GatewayOrchestrator
from app.middleware.request_context import RequestContext
from app.schemas.gateway import GatewayRequest, GatewayResponse
from app.security.inspectors.rule_inspector import RuleInspector

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.resources = create_app_resources()
    yield

app = FastAPI(
    title="Secure LLM Gateway",
    version="0.5.0",
    description="A secure LLM gateway for “LLM hacking” defense: inspecting, testing, and protecting AI interactions end‑to‑end.",
    lifespan=lifespan,
)
configure_logging()
app.add_middleware(RequestContext)

logger = logging.getLogger(__name__)

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


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
        request: Request,
    gateway_request: GatewayRequest,
    gateway: GatewayOrchestrator = Depends(get_gateway_inspector),
):
    logger.info(
        "chat_request_completed",
        extra={
            "request_id": request.state.request_id,
            "trace_id": request.state.trace_id,
            "route": "/chat"
        },
    )
    try:
        response = gateway.process_chat_input(gateway_request)
        output_allowed = (
            response.output_verdict.allowed
            if response.output_verdict is not None
            else None
        )
        input_verdict = (
            response.input_verdict.allowed
            if response.input_verdict is not None
            else None
        )
        logger.info(
            "chat_request_completed",
            extra={
                "request_id": request.state.request_id,
                "trace_id": request.state.trace_id,
                "route": "/chat",
                "input_verdict":input_verdict,
                "output_allowed":output_allowed
            },
        )
        return response

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