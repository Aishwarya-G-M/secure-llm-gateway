import time
from collections import defaultdict, deque
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from app.schemas.error import ErrorResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        default_max_requests: int = 100,
        default_window_seconds: int = 60,
        path_limits: dict[str, dict[str, int]] | None = None,
        excluded_paths: set[str] | None = None,
    ):
        super().__init__(app)
        self.default_max_requests = default_max_requests
        self.default_window_seconds = default_window_seconds
        self.path_limits = path_limits or {}
        self.excluded_paths = excluded_paths or set()
        self.requests = defaultdict(deque)

    async def dispatch(self, request, call_next):
        path = request.url.path
        limit_config = self._get_limit_config(path)

        if limit_config is None:
            return await call_next(request)

        max_requests, window_seconds = limit_config

        client_ip = request.client.host if request.client else "unknown"
        api_key = getattr(request.state, "api_key", None)
        identity = api_key if api_key else client_ip
        key = f"{identity}:{path}"

        now = time.time()
        bucket = self.requests[key]

        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

        if len(bucket) >= max_requests:
            return JSONResponse(
                status_code=429,
                content=ErrorResponse(
                    error_code="rate_limit_exceeded",
                    detail="Rate limit exceeded",
                    request_id=getattr(request.state, "request_id", None),
                    trace_id=getattr(request.state, "trace_id", None),
                ).model_dump(),
            )

        bucket.append(now)
        return await call_next(request)

    def _get_limit_config(self, path: str) -> tuple[int, int] | None:
        if path in self.excluded_paths:
            return None

        if path in self.path_limits:
            config = self.path_limits[path]
            return config["max_requests"], config["window_seconds"]

        return self.default_max_requests, self.default_window_seconds