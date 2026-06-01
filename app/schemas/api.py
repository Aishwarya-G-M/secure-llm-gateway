from pydantic import BaseModel

class PromptRequest(BaseModel):
    prompt: str
    system_prompt: str | None = None

class AttackRunRequest(BaseModel):
    id: str