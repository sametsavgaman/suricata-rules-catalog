"""Short-lived read cache for the Rule Explorer dashboard."""
from __future__ import annotations

from copy import deepcopy
from threading import Lock
from time import monotonic

from sqlalchemy.orm import Session

_CACHE_SECONDS = 60.0
_CACHE: dict[tuple[str, object, str], tuple[float, object]] = {}
_LOCK = Lock()


def get_dashboard_cache(db: Session, namespace: str, key: str = "") -> object | None:
    cache_key = (namespace, db.get_bind(), key)
    now = monotonic()
    with _LOCK:
        cached = _CACHE.get(cache_key)
        if not cached or now - cached[0] >= _CACHE_SECONDS:
            return None
        return deepcopy(cached[1])


def set_dashboard_cache(db: Session, namespace: str, value: object, key: str = "") -> None:
    cache_key = (namespace, db.get_bind(), key)
    with _LOCK:
        _CACHE[cache_key] = (monotonic(), deepcopy(value))


def clear_dashboard_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def warm_dashboard_cache() -> None:
    """Prepare dashboard counters and selectors without delaying API startup."""
    from app.api.catalog import catalog_stats
    from app.api.rules import classification_filters, warm_rule_explorer
    from app.api.stats import get_stats
    from app.database.session import SessionLocal

    with SessionLocal() as db:
        get_stats(db)
        catalog_stats(db)
        classification_filters(db)
        warm_rule_explorer(db)
