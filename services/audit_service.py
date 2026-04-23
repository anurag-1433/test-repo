"""
services/audit_service.py
--------------------------
Lightweight helper to write structured entries into the audit_logs table.
Keeps audit logging a single-line call from any service or worker.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models

logger = logging.getLogger(__name__)


from sqlalchemy.orm import Session as SyncSession


async def _resolve_actor_id(db: AsyncSession, actor_user_id: UUID | str | None) -> UUID | None:
    """Resolve a Supabase JWT sub (supabase_user_id) to the app's users.id UUID.

    The audit_logs.actor_user_id FK references users.id (app UUID), but callers
    typically pass the Supabase JWT 'sub' stored in users.supabase_user_id.
    Returns None if not found so audit events are never silently dropped.
    """
    if actor_user_id is None:
        return None
    try:
        stmt = select(models.User.id).where(
            models.User.supabase_user_id == str(actor_user_id)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    except Exception as exc:
        logger.warning("audit_service: could not resolve actor_user_id %s: %s", actor_user_id, exc)
        return None


async def log_event(
    db: AsyncSession,
    *,
    action: str,
    entity_type: str,
    entity_id: UUID | str | None = None,
    tenant_id: UUID | str | None = None,
    actor_user_id: UUID | str | None = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write a single audit log entry (Async).
    """
    try:
        resolved_actor_id = await _resolve_actor_id(db, actor_user_id)
        entry = models.AuditLog(
            tenant_id=tenant_id,
            actor_user_id=resolved_actor_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata_json=metadata or {},
        )
        db.add(entry)
        await db.flush()

    except Exception as exc:
        logger.error("audit_service.log_event error: %s", exc, exc_info=True)


def log_event_sync(
    db: SyncSession,
    *,
    action: str,
    entity_type: str,
    entity_id: UUID | str | None = None,
    tenant_id: UUID | str | None = None,
    actor_user_id: UUID | str | None = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write a single audit log entry (Sync).
    """
    try:
        entry = models.AuditLog(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata_json=metadata or {},
        )
        db.add(entry)
        db.flush()

    except Exception as exc:
        logger.error("audit_service.log_event_sync error: %s", exc, exc_info=True)
