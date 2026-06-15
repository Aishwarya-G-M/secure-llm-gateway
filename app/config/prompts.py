from pathlib import Path
from typing import Any

import yaml

PROMPTS_PATH = Path(__file__).resolve().parent / "prompts.yaml"


def load_prompt_config(prompt_name: str = "chat") -> dict[str, Any]:
    with PROMPTS_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    prompt_config = data.get(prompt_name)

    if not isinstance(data, dict):
        raise ValueError("prompts.yaml must contain a top-level mapping")

    if prompt_config is None:
        raise ValueError(f"No system prompt configured for route: '{prompt_name}'")
    return prompt_config

def load_system_prompt(prompt_name: str = "chat") -> str:
    config = load_prompt_config(prompt_name)
    system_prompt = config.get("system_prompt")

    if not system_prompt:
        raise ValueError(f"system_prompt is empty for route: '{prompt_name}'")
    return system_prompt.strip()


def load_prompt_version(prompt_name: str = "chat") -> str:
    config = load_prompt_config(prompt_name)
    version = config.get("version","unknown")

    if not isinstance(version, str):
        raise ValueError(f"version must be a string for: '{prompt_name}'")

    return version