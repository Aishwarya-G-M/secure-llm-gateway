from pydantic import BaseModel

class ErrorResponse(BaseModel):
    error_code: str
    detail: str
    request_id: str | None = None
    trace_id: str | None = None