"""Importing this package registers every check."""
from .base import REGISTRY, Check, CheckContext, register  # noqa: F401
from . import passive, active  # noqa: F401  (side effect: registration)


def all_checks(only: list[str] | None = None, skip: list[str] | None = None) -> list[Check]:
    """Return registered checks, optionally filtered by id prefix."""
    out = []
    for c in REGISTRY:
        if only and not any(c.id.startswith(o) for o in only):
            continue
        if skip and any(c.id.startswith(s) for s in skip):
            continue
        out.append(c)
    return out
