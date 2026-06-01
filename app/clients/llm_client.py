import os

from app.clients.llm_protocol import LlmClientProtocol
from app.clients.providers.groq_client import GroqLlmClient
from app.exceptions.llm import LLMConfigurationError


def get_llm_client() -> LlmClientProtocol:
    provider = os.getenv("LLM_PROVIDER", "groq").lower()

    if provider == "groq":
        return GroqLlmClient()

    raise LLMConfigurationError(f"Unsupported LLM provider configured: {provider}")