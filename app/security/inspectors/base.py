from abc import ABC, abstractmethod

from app.models.inspection_context import InspectionContext
from app.schemas.security_verdict import SecurityVerdict

class BaseInspector(ABC):
    @abstractmethod
    def inspect_input(
        self,
        text: str,
        context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        """Inspect inbound user input before the LLM call."""

    @abstractmethod
    def inspect_output(
        self,
        text: str,
        context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        """Inspect outbound model output before returning it to the caller."""