import os

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from app.schemas.error import ErrorResponse
from dotenv import load_dotenv

load_dotenv()

def _load_api_keys() -> frozenset[str]:
    raw = os.getenv("API_KEYS", "")
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    return frozenset(keys)

VALID_API_KEYS = _load_api_keys()

class ApiKeyMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        excluded_paths: set[str] | None = None,
        api_keys: frozenset[str] | None = None,
    ):
        super().__init__(app)
        self.excluded_paths = excluded_paths or {"/health"}
        self.api_keys = api_keys if api_keys is not None else VALID_API_KEYS

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return JSONResponse(
                status_code=401,
                content=ErrorResponse(
                    error_code="missing_api_key",
                    detail="X-API-Key header is required",
                    request_id=getattr(request.state, "request_id", None),
                    trace_id=getattr(request.state, "trace_id", None),
                ).model_dump(),
            )

        if api_key not in self.api_keys:
            return JSONResponse(
                status_code=403,
                content=ErrorResponse(
                    error_code="invalid_api_key",
                    detail="Provided API key is not valid",
                    request_id=getattr(request.state, "request_id", None),
                    trace_id=getattr(request.state, "trace_id", None),
                ).model_dump(),
            )

        request.state.api_key = api_key
        return await call_next(request)