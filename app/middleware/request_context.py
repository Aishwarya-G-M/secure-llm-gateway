import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

REQUEST_ID_HEADER = "x-request-id"
TRACE_ID_HEADER = "x-trace-id"

class RequestContext(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        trace_id = request.headers.get(TRACE_ID_HEADER) or request_id

        request.state.request_id = request_id
        request.state.trace_id = trace_id

        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        response.headers[TRACE_ID_HEADER] = trace_id
        return response