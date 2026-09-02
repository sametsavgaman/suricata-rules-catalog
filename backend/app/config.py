from functools import lru_cache
from urllib.parse import urlparse
import socket

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AliasChoices, Field, model_validator


class Settings(BaseSettings):
    app_name: str = "Suricata Rule Classification Agent"
    database_url: str = "sqlite:///./suricata_rules.db"
    openai_api_key: str | None = None
    openai_model: str | None = None
    ai_provider: str = "openai"
    gemini_api_key: str | None = None
    gemini_model: str | None = None
    gemini_input_cost_per_million: float | None = Field(default=None, validation_alias=AliasChoices("GEMINI_INPUT_COST_PER_MILLION", "GEMINI_INPUT_COST_PER_1M"))
    gemini_output_cost_per_million: float | None = Field(default=None, validation_alias=AliasChoices("GEMINI_OUTPUT_COST_PER_MILLION", "GEMINI_OUTPUT_COST_PER_1M"))
    ai_max_retries: int = 3
    classifier_version: str = "v1"
    max_tool_calls_per_rule: int = 3
    agent_auto_finalize_confidence: float = 0.92
    agent_tool_trigger_confidence: float = 0.80
    agent_min_accept_confidence: float = 0.70
    frontend_origin: str = "http://localhost:5173"
    max_agent_contents: int = 20
    max_agent_content_chars: int = 4000
    openai_input_cost_per_million: float | None = None
    openai_output_cost_per_million: float | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)

    @model_validator(mode="after")
    def local_database_fallback(self):
        """Use the bundled SQLite DB when Docker's `db` host is unavailable locally."""
        parsed = urlparse(self.database_url)
        if parsed.hostname == "db":
            try:
                socket.gethostbyname("db")
            except OSError:
                self.database_url = "sqlite:///./suricata_rules.db"
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
