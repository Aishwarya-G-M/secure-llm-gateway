from app.exceptions.base import AppError


class LLMError(AppError):
    """Base exception for all LLM-related failures."""
    pass


class LLMConfigurationError(LLMError):
    """Raised when LLM provider configuration is invalid or missing."""
    pass


class LLMTimeoutError(LLMError):
    """Raised when an LLM request times out."""
    pass


class LLMProviderError(LLMError):
    """Raised when an LLM provider returns an error or unexpected failure."""
    pass