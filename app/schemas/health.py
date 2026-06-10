from pydantic import BaseModel


class InspectorStatus(BaseModel):
    name: str
    status: str


class HealthResponse(BaseModel):
    status: str
    uptime_seconds: float
    system_prompt_version: str
    inspectors: list[InspectorStatus]
