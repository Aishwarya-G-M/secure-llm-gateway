import os
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request, APIRouter

from app.config.prompts import load_prompt_version
from app.core.logging_setup import logger

from app.clients.llm_client import get_llm_client
from app.core.logging_setup import configure_logging
from app.core.redis import initialise_redis, close_redis
from app.core.resources import create_app_resources
from app.exceptions.gateway import GatewayInspectionError, GatewayExecutionError

from app.gateway.orchestrator import GatewayOrchestrator
from app.schemas.gateway import GatewayRequest, GatewayResponse
from app.api.error_handlers import (
    gateway_execution_error_handler,
    gateway_inspection_error_handler,
)

@asynccontextmanager
async def lifespan(application: FastAPI):
    redis_enabled = os.getenv("REDIS_ENABLED", "false").lower() == "true"
    application.state.resources = create_app_resources()
    application.state.start_time = time.time()
    application.state.redis_enabled = redis_enabled
    application.state.redis_healthy = False

    if redis_enabled:
        redis_url = os.getenv("REDIS_URL")

        if not redis_enabled:
            raise RuntimeError("REDIS_URL must be configured when REDIS_ENABLED=true")

        await initialise_redis(
            redis_url=redis_url,
            connect_timeout=float(
                os.getenv("REDIS_CONNECT_TIMEOUT_SECONDS", "1.0")
            ),
            socket_timeout=float(
                os.getenv("REDIS_SOCKET_TIMEOUT_SECONDS", "1.0")
            ),
        )

    try:
        yield
    finally:
        if redis_enabled:
            await close_redis()

app = FastAPI(
    title="Secure LLM Gateway",
    version="0.6.0",
    description="A secure LLM gateway for “LLM hacking” defense: inspecting, testing, and protecting AI interactions end‑to‑end.",
    lifespan=lifespan,
)
ops_router = APIRouter(tags=["ops"])
configure_logging()
from app.middleware.api_key_auth import ApiKeyMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_context import RequestContext

app.add_middleware(
    RateLimitMiddleware,
    default_max_requests=int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100")),
    default_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
    path_limits={
        "/chat": {
            "max_requests": int(os.getenv("CHAT_RATE_LIMIT_MAX_REQUESTS", "10")),
            "window_seconds": int(os.getenv("CHAT_RATE_LIMIT_WINDOW_SECONDS", "60")),
        }
    },
    excluded_paths={"/health","/metrics", "/docs", "/redoc", "/openapi.json"},
)
app.add_middleware(ApiKeyMiddleware, excluded_paths={"/health","/metrics", "/docs", "/redoc", "/openapi.json"})
app.add_middleware(RequestContext)
app.add_exception_handler(GatewayInspectionError, gateway_inspection_error_handler)
app.add_exception_handler(GatewayExecutionError, gateway_execution_error_handler)

router = APIRouter()
SYSTEM_PROMPT_VERSION = "v1"

def get_gateway_inspector(request: Request) -> GatewayOrchestrator:
    resources = request.app.state.resources

    return GatewayOrchestrator(
        rule_inspector=resources.rule_inspector,
        llm_guard_inspector=resources.llm_guard_inspector,
        llm_client=get_llm_client(),
        system_prompt=resources.system_prompt,
    )

@app.get("/")
def read_root():
    return {"message": "API is running"}

@ops_router.get("/health")
def health(request: Request):
    uptime_seconds = int(time.time() - request.app.state.start_time)
    return {
        "status": "ok",
        "uptime_seconds": uptime_seconds,
        "version": request.app.version,
        "system_prompt_version": load_prompt_version("chat"),
        "inspector": {"status": "ok"},
    }

@ops_router.get("/metrics")
async def metrics(request: Request):
    return request.app.state.resources.metrics.snapshot()

@app.post("/chat", response_model=GatewayResponse, response_model_exclude_none=True)
async def chat(
    request: Request,
    gateway_request: GatewayRequest,
    gateway: GatewayOrchestrator = Depends(get_gateway_inspector),
):
    request_metrics = request.app.state.resources.metrics
    started_at = time.perf_counter()

    response = gateway.process_chat_input(
        gateway_request,
        request_id=request.state.request_id,
        trace_id=request.state.trace_id,
    )

    final_action = (
        response.output_verdict.action.value
        if response.output_verdict
        else response.input_verdict.action.value
        if response.input_verdict
        else "unknown"
    )

    request_metrics.record_request(final_action)

    latency_ms = round((time.perf_counter() - started_at) * 1000, 2)

    logger.info(
        "chat_request_completed",
        extra={
            "request_id": request.state.request_id,
            "trace_id": request.state.trace_id,
            "route": "/chat",
            "input_action": response.input_verdict.action.value if response.input_verdict else None,
            "output_action": response.output_verdict.action.value if response.output_verdict else None,
            "final_action": final_action,
            "latency_ms": latency_ms,
        },
    )

    return response

app.include_router(ops_router)