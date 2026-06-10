from fastapi import Request
from fastapi.responses import JSONResponse

from app.exceptions.gateway import GatewayExecutionError, GatewayInspectionError
from app.exceptions.llm import (
    LLMConfigurationError,
    LLMProviderError,
    LLMTimeoutError,
)
from app.schemas.error import ErrorResponse


def _error_response(
    request: Request,
    status_code: int,
    error_code: str,
    detail: str,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            error_code=error_code,
            detail=detail,
            request_id=getattr(request.state, "request_id", None),
            trace_id=getattr(request.state, "trace_id", None),
        ).model_dump(),
    )


async def gateway_inspection_error_handler(
    request: Request, exc: GatewayInspectionError
) -> JSONResponse:
    return _error_response(
        request,
        status_code=500,
        error_code="inspection_failed",
        detail=str(exc),
    )


async def gateway_execution_error_handler(
    request: Request, exc: GatewayExecutionError
) -> JSONResponse:
    cause = exc.__cause__

    if isinstance(cause, LLMConfigurationError):
        return _error_response(
            request,
            status_code=503,
            error_code="llm_configuration_error",
            detail=str(cause),
        )
    if isinstance(cause, LLMTimeoutError):
        return _error_response(
            request,
            status_code=504,
            error_code="llm_timeout",
            detail=str(cause),
        )
    if isinstance(cause, LLMProviderError):
        return _error_response(
            request,
            status_code=502,
            error_code="llm_provider_error",
            detail=str(cause),
        )

    return _error_response(
        request,
        status_code=500,
        error_code="gateway_execution_failed",
        detail=str(exc),
    )