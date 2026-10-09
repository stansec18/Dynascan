"""Authentication handlers for authenticated scans."""
from __future__ import annotations

from typing import Any

from .base import AuthHandler, AuthError
from .form_login import FormLoginAuth
from .token import BearerAuth, ApiKeyAuth, HeadersAuth, TokenLoginAuth


def build_auth(cfg: dict[str, Any] | None) -> AuthHandler | None:
    """Create an auth handler from a config dict. ``None``/empty means unauthenticated."""
    if not cfg:
        return None
    kind = (cfg.get("type") or "").lower()
    if kind in ("form", "form_login"):
        return FormLoginAuth(**{k: v for k, v in cfg.items() if k != "type"})
    if kind == "bearer":
        return BearerAuth(**{k: v for k, v in cfg.items() if k != "type"})
    if kind in ("apikey", "api_key"):
        return ApiKeyAuth(**{k: v for k, v in cfg.items() if k != "type"})
    if kind == "headers":
        return HeadersAuth(**{k: v for k, v in cfg.items() if k != "type"})
    if kind in ("token_login", "json_login"):
        return TokenLoginAuth(**{k: v for k, v in cfg.items() if k != "type"})
    raise AuthError(f"unknown auth type: {kind!r}")


__all__ = [
    "AuthHandler", "AuthError", "FormLoginAuth", "BearerAuth", "ApiKeyAuth",
    "HeadersAuth", "TokenLoginAuth", "build_auth",
]
