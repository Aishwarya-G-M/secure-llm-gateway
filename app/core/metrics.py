from dataclasses import dataclass, field
from threading import Lock


@dataclass
class GatewayMetrics:
    requests_total: int = 0
    requests_allowed: int = 0
    requests_blocked: int = 0
    requests_redacted: int = 0
    requests_reviewed: int = 0
    llm_errors_total: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def record_request(self, final_action: str) -> None:
        with self._lock:
            self.requests_total += 1
            if final_action == "allow":
                self.requests_allowed += 1
            elif final_action == "block":
                self.requests_blocked += 1
            elif final_action == "redact":
                self.requests_redacted += 1
            elif final_action == "review":
                self.requests_reviewed += 1

    def record_llm_error(self) -> None:
        with self._lock:
            self.llm_errors_total += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "requests_total": self.requests_total,
                "requests_allowed": self.requests_allowed,
                "requests_blocked": self.requests_blocked,
                "requests_redacted": self.requests_redacted,
                "requests_reviewed": self.requests_reviewed,
                "llm_errors_total": self.llm_errors_total,
            }


gateway_metrics = GatewayMetrics()