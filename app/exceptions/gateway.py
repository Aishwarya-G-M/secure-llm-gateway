from app.exceptions.base import AppError


class GatewayError(AppError):
    pass

class GatewayInspectionError(GatewayError):
    """Raised when the gateway cannot complete the inspection flow."""
    pass


class GatewayExecutionError(GatewayError):
    """Raised when the gateway fails while orchestrating request processing."""
    pass