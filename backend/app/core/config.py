from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    api_prefix: str = "/api"
    app_name: str = "AWS SecureScope"
    database_url: str = Field(..., env="DATABASE_URL")
    redis_url: str = Field(..., env="REDIS_URL")
    llm_endpoint: Optional[str] = Field(None, env="LLM_ENDPOINT")
    llm_model_path: Optional[str] = Field(None, env="LLM_MODEL_PATH")
    celery_broker_url: Optional[str] = Field(None, env="CELERY_BROKER_URL")
    celery_result_backend: Optional[str] = Field(None, env="CELERY_RESULT_BACKEND")
    feature_flags: List[str] = Field(default_factory=list, env="FEATURE_FLAGS")
    enforce_https: bool = Field(default=True, env="ENFORCE_HTTPS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("feature_flags", pre=True)
    def split_feature_flags(cls, value: Optional[str]) -> List[str]:
        if not value:
            return []
        if isinstance(value, list):
            return value
        return [flag.strip() for flag in value.split(",") if flag.strip()]

    @property
    def celery_config(self) -> dict[str, str]:
        broker = self.celery_broker_url or self.redis_url
        backend = self.celery_result_backend or self.redis_url
        return {"broker_url": broker, "result_backend": backend}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
