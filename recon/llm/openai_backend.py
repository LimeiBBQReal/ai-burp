"""
Recon Pipeline V3 - OpenAI Backend (Production)

Reads configuration from environment variables or .env file.
Supports OpenAI, DeepSeek, and any OpenAI-compatible API.
"""
import json
import os
from typing import Optional
from pathlib import Path

from .base import BaseLLM, LLMResponse


def load_env_file(env_path: str = ".env") -> dict:
    """
    Load key-value pairs from .env file

    Returns dict of {key: value}
    """
    config = {}
    path = Path(env_path)

    if not path.exists():
        # Try parent directory
        path = Path("..") / env_path

    if not path.exists():
        return config

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()

    return config


class OpenAIBackend(BaseLLM):
    """
    OpenAI-compatible API Backend

    Configuration priority:
    1. Constructor parameters
    2. Environment variables
    3. .env file

    Supports:
    - OpenAI GPT-4/4o
    - DeepSeek
    - Any OpenAI-compatible service
    """

    def __init__(self, api_key: str = None, model: str = None,
                 base_url: str = None):
        # Load .env first
        env_config = load_env_file()

        # Priority: param > env var > .env file
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or env_config.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("AIBURP_LLM_MODEL") or env_config.get("AIBURP_LLM_MODEL", "gpt-4o")
        self.base_url = (
            base_url
            or os.environ.get("OPENAI_API_BASE")
            or os.environ.get("OPENAI_BASE_URL")
            or env_config.get("OPENAI_API_BASE")
            or env_config.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        )

        self._call_count = 0

    @property
    def name(self) -> str:
        return f"OpenAI-{self.model}"

    @property
    def max_tokens(self) -> int:
        return 4096

    def call(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.3) -> LLMResponse:
        """Call OpenAI-compatible API"""
        self._call_count += 1

        if not self.api_key:
            return LLMResponse(
                success=False,
                error="API Key not configured. Set OPENAI_API_KEY in .env or environment.",
            )

        try:
            import requests

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": temperature,
                "max_tokens": self.max_tokens,
                "response_format": {"type": "json_object"},
            }

            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=120,
            )

            if resp.status_code != 200:
                return LLMResponse(
                    success=False,
                    error=f"API error: {resp.status_code} {resp.text[:500]}",
                )

            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            # Parse JSON
            try:
                structured = json.loads(content)
            except json.JSONDecodeError:
                structured = {"raw": content}

            return LLMResponse(
                success=True,
                content=content,
                structured_data=structured,
                confidence=structured.get("confidence", 0.8),
                reasoning=structured.get("reasoning", ""),
            )

        except Exception as e:
            return LLMResponse(
                success=False,
                error=str(e),
            )

    @property
    def call_count(self) -> int:
        return self._call_count
