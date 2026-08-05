from app.exceptions.base import AppError

class PolicyError(AppError):
    pass


class PolicyEvaluationError(PolicyError):
    """Raised when a policy decision cannot be computed."""
    pass


class RuleInspectorError(PolicyEvaluationError):
    """Raised when the rule inspector fails."""
    pass


class LLMGuardInspectorError(PolicyEvaluationError):
    """Raised when the LLM guard inspector fails."""
    pass