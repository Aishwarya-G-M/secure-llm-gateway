from dataclasses import dataclass

@dataclass
class GatewayMetrics:
    requests_total: int = 0
    requests_allowed: int = 0
    requests_blocked: int = 0
    requests_redacted: int = 0
    requests_reviewed: int = 0
    llm_errors_total: int = 0

    def record_request(self, action: str) -> None:
        self.requests_total += 1

        if action == "allow":
            self.requests_allowed += 1
        elif action == "block":
            self.requests_blocked += 1
        elif action == "redact":
            self.requests_redacted += 1
        elif action == "review":
            self.requests_reviewed += 1

    def record_llm_error(self) -> None:
        self.llm_errors_total += 1

    def snapshot(self) -> dict[str, int]:
        return {
            "requests_total": self.requests_total,
            "requests_allowed": self.requests_allowed,
            "requests_blocked": self.requests_blocked,
            "requests_redacted": self.requests_redacted,
            "requests_reviewed": self.requests_reviewed,
            "llm_errors_total": self.llm_errors_total,
        }


gateway_metrics = GatewayMetrics()