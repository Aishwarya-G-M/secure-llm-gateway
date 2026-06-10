import json
import logging
import sys
from datetime import datetime, timezone

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


logger = get_logger("app")
audit_logger = get_logger("audit")

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for field in [
            "request_id",
            "trace_id",
            "route",
            "final_action",
            "input_allowed",
            "output_allowed",
        ]:
            value = getattr(record, field, None)
            if value is not None:
                log_data[field] = value

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)

def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)