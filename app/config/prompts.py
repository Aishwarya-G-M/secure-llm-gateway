from pathlib import Path

import yaml

PROMPTS_PATH = Path(__file__).resolve().parent / "prompts.yaml"


def load_system_prompt(route: str = "chat") -> str:
    with PROMPTS_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    route_config = data.get(route)

    if route_config is None:
        raise ValueError(f"No system prompt configured for route: '{route}'")

    system_prompt = route_config.get("system_prompt")

    if not system_prompt:
        raise ValueError(f"system_prompt is empty for route: '{route}'")

    return system_prompt.strip()


def load_prompt_version(route: str = "chat") -> str:
    with PROMPTS_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data.get(route, {}).get("version", "unknown")