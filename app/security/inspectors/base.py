from abc import ABC, abstractmethod
from typing import Any

from app.schemas.security import SecurityVerdict

class BaseInspector(ABC):
    @abstractmethod
    def inspect_input(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> SecurityVerdict:
        """Inspect inbound user input before the LLM call."""
        pass

    @abstractmethod
    def inspect_output(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> SecurityVerdict:
        """Inspect outbound model output before returning it to the caller."""
        pass