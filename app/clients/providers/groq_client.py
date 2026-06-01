import os
import time

from dotenv import load_dotenv
from groq.types.chat import ChatCompletionMessageParam

from app.exceptions.llm import (
    LLMConfigurationError,
    LLMProviderError,
    LLMTimeoutError,
)
from app.schemas.llm import LLMMetadata, LLMRequest, LLMResponse
from groq import Groq, APITimeoutError, APIConnectionError, APIStatusError

load_dotenv()


class GroqLlmClient:
    def __init__(self) -> None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise LLMConfigurationError(
                "GROQ_API_KEY is not configured. Add it to your .env file or environment variables."
            )

        self.client = Groq(api_key=api_key)
        self.model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        self.provider = "groq"

    def generate(self, request: LLMRequest) -> LLMResponse:
        messages: list[ChatCompletionMessageParam] = [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.prompt},
        ]

        start = time.perf_counter()

        try:
            chat_completion = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
            )
        except APITimeoutError as e:
            raise LLMTimeoutError("LLM provider request timed out.") from e
        except APIConnectionError as e:
            raise LLMProviderError("Failed to connect to the LLM provider.") from e
        except APIStatusError as e:
            raise LLMProviderError(
                f"LLM provider returned an error status: {e.status_code}"
            ) from e
        except Exception as e:
            raise LLMProviderError("Unexpected LLM provider error.") from e

        latency_ms = int((time.perf_counter() - start) * 1000)
        usage = getattr(chat_completion, "usage", None)

        return LLMResponse(
            content=chat_completion.choices[0].message.content or "",
            metadata=LLMMetadata(
                request_id=getattr(chat_completion, "id", None),
                provider=self.provider,
                model=self.model,
                latency_ms=latency_ms,
            ),
            input_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            output_tokens=getattr(usage, "completion_tokens", None) if usage else None,
            total_tokens=getattr(usage, "total_tokens", None) if usage else None,
        )