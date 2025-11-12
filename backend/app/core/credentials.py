from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional

import redis

from app.core.config import get_settings


@dataclass
class EphemeralCredential:
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    expires_at: float = 0.0


class CredentialVault:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._redis: Optional[redis.Redis] = None
        try:
            self._redis = redis.Redis.from_url(self.settings.redis_url, decode_responses=False)
            self._redis.ping()
        except Exception:
            self._redis = None
        self._memory: Dict[str, EphemeralCredential] = {}

    def store(self, cred: EphemeralCredential, ttl: int = 900) -> str:
        key = secrets.token_urlsafe(16)
        cred.expires_at = time.time() + ttl
        if self._redis:
            payload = {
                "access_key_id": cred.access_key_id,
                "secret_access_key": cred.secret_access_key,
            }
            if cred.session_token:
                payload["session_token"] = cred.session_token
            if cred.role_arn:
                payload["role_arn"] = cred.role_arn
            if cred.external_id:
                payload["external_id"] = cred.external_id
            self._redis.hset(key, mapping=payload)
            self._redis.expire(key, ttl)
        else:
            self._memory[key] = cred
        return key

    def retrieve(self, key: str) -> Optional[EphemeralCredential]:
        if self._redis:
            values = self._redis.hgetall(key)
            if not values:
                return None
            data = {k.decode(): v.decode() for k, v in values.items()}
            return EphemeralCredential(
                access_key_id=data["access_key_id"],
                secret_access_key=data["secret_access_key"],
                session_token=data.get("session_token"),
                role_arn=data.get("role_arn"),
                external_id=data.get("external_id"),
                expires_at=time.time(),
            )
        cred = self._memory.get(key)
        if cred and cred.expires_at >= time.time():
            return cred
        if cred:
            del self._memory[key]
        return None

    def revoke(self, key: str) -> None:
        if self._redis:
            self._redis.delete(key)
        else:
            self._memory.pop(key, None)


vault = CredentialVault()
