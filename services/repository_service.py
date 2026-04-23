"""
Repository service — repository CRUD, settings, and automation management.

Handles repository registration, provider configuration,
strictness settings, and merge blocking automation.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models

logger = logging.getLogger(__name__)


class RepositoryService:
    """
    Manages repository lifecycle: creation, settings, automation config.
    All queries are tenant-scoped.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_repositories(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict:
        """List all repositories for a tenant with pagination."""
        base = select(models.Repository).where(
            models.Repository.tenant_id == tenant_id,
            models.Repository.deleted_at.is_(None),
        )

        total_stmt = select(func.count()).select_from(base.subquery())
        total = await self.db.scalar(total_stmt)

        result = await self.db.execute(
            base.order_by(models.Repository.name)
            .limit(limit)
            .offset(offset)
        )
        repos = result.scalars().all()

        return {
            "items": [self._serialize(r) for r in repos],
            "total": total or 0,
            "limit": limit,
            "offset": offset,
        }

    async def get_repository(self, repo_id: str, tenant_id: str) -> Optional[Dict]:
        """Get repository details including settings and automation."""
        stmt = select(models.Repository).where(
            models.Repository.id == repo_id,
            models.Repository.tenant_id == tenant_id,
            models.Repository.deleted_at.is_(None),
        )
        try:
            result = await self.db.execute(stmt)
        except DBAPIError:
            # Invalid UUID format — treat as not found
            return None
        repo = result.scalar_one_or_none()

        if not repo:
            return None

        data = self._serialize(repo)

        # Load settings
        settings_stmt = select(models.RepositorySettings).where(
            models.RepositorySettings.repository_id == repo_id
        )
        settings_result = await self.db.execute(settings_stmt)
        settings = settings_result.scalar_one_or_none()
        data["settings"] = self._serialize_settings(settings) if settings else None

        # Load automation
        automation_stmt = select(models.RepositoryAutomation).where(
            models.RepositoryAutomation.repository_id == repo_id
        )
        automation_result = await self.db.execute(automation_stmt)
        automation = automation_result.scalar_one_or_none()
        data["automation"] = self._serialize_automation(automation) if automation else None

        return data

    async def create_repository(
        self,
        tenant_id: str,
        name: str,
        provider: str = "github",
        external_id: Optional[str] = None,
        default_branch: str = "main",
        primary_language: Optional[str] = None,
    ) -> Dict:
        """Register a new repository and create default settings."""
        repo = models.Repository(
            tenant_id=tenant_id,
            name=name,
            provider=provider,
            external_id=external_id,
            default_branch=default_branch,
            primary_language=primary_language,
        )
        self.db.add(repo)
        await self.db.flush()

        # Create default settings
        settings = models.RepositorySettings(
            repository_id=repo.id,
            enabled_categories=["security", "performance", "maintainability", "style"],
        )
        self.db.add(settings)

        # Create default automation
        automation = models.RepositoryAutomation(
            repository_id=repo.id,
        )
        self.db.add(automation)

        await self.db.commit()
        await self.db.refresh(repo)
        return self._serialize(repo)

    async def update_repository(
        self, repo_id: str, tenant_id: str, updates: Dict
    ) -> Optional[Dict]:
        """Update repository metadata."""
        stmt = select(models.Repository).where(
            models.Repository.id == repo_id,
            models.Repository.tenant_id == tenant_id,
            models.Repository.deleted_at.is_(None),
        )
        result = await self.db.execute(stmt)
        repo = result.scalar_one_or_none()

        if not repo:
            return None

        for key in ("name", "default_branch", "primary_language"):
            if key in updates:
                setattr(repo, key, updates[key])

        await self.db.commit()
        await self.db.refresh(repo)
        return self._serialize(repo)

    async def delete_repository(self, repo_id: str, tenant_id: str) -> bool:
        """Soft-delete a repository."""
        stmt = select(models.Repository).where(
            models.Repository.id == repo_id,
            models.Repository.tenant_id == tenant_id,
            models.Repository.deleted_at.is_(None),
        )
        result = await self.db.execute(stmt)
        repo = result.scalar_one_or_none()

        if not repo:
            return False

        repo.deleted_at = datetime.now(timezone.utc)
        await self.db.commit()
        return True

    async def update_settings(
        self, repo_id: str, tenant_id: str, updates: Dict
    ) -> Optional[Dict]:
        """Update repository analysis settings (strictness, categories, token overrides)."""
        # Verify ownership
        repo_stmt = select(models.Repository).where(
            models.Repository.id == repo_id,
            models.Repository.tenant_id == tenant_id,
        )
        repo_result = await self.db.execute(repo_stmt)
        repo = repo_result.scalar_one_or_none()

        if not repo:
            return None

        settings_stmt = select(models.RepositorySettings).where(
            models.RepositorySettings.repository_id == repo_id
        )
        settings_result = await self.db.execute(settings_stmt)
        settings = settings_result.scalar_one_or_none()

        if not settings:
            settings = models.RepositorySettings(repository_id=repo_id)
            self.db.add(settings)

        if "strictness_level" in updates:
            settings.strictness_level = updates["strictness_level"]
        if "enabled_categories" in updates:
            settings.enabled_categories = updates["enabled_categories"]
        if "max_tokens_override" in updates:
            settings.max_tokens_override = updates["max_tokens_override"]

        await self.db.commit()
        await self.db.refresh(settings)
        return self._serialize_settings(settings)

    async def update_automation(
        self, repo_id: str, tenant_id: str, updates: Dict
    ) -> Optional[Dict]:
        """Update repository automation settings (auto-review, merge blocking)."""
        repo_stmt = select(models.Repository).where(
            models.Repository.id == repo_id,
            models.Repository.tenant_id == tenant_id,
        )
        repo_result = await self.db.execute(repo_stmt)
        repo = repo_result.scalar_one_or_none()

        if not repo:
            return None

        automation_stmt = select(models.RepositoryAutomation).where(
            models.RepositoryAutomation.repository_id == repo_id
        )
        automation_result = await self.db.execute(automation_stmt)
        automation = automation_result.scalar_one_or_none()

        if not automation:
            automation = models.RepositoryAutomation(repository_id=repo_id)
            self.db.add(automation)

        for key in (
            "auto_review_on_push",
            "review_pull_requests",
            "merge_blocking_enabled",
            "confidence_threshold",
        ):
            if key in updates:
                setattr(automation, key, updates[key])

        if "min_severity" in updates:
            automation.min_severity = updates["min_severity"]

        await self.db.commit()
        await self.db.refresh(automation)
        return self._serialize_automation(automation)

    def _serialize(self, repo: models.Repository) -> Dict:
        if repo.updated_at:
            updated_at = repo.updated_at.isoformat()
        elif repo.created_at:
            updated_at = repo.created_at.isoformat()
        else:
            updated_at = None
        return {
            "id": str(repo.id),
            "tenant_id": str(repo.tenant_id) if repo.tenant_id else None,
            "name": repo.name,
            "provider": repo.provider.value if repo.provider else None,
            "external_id": repo.external_id,
            "primary_language": repo.primary_language,
            "default_branch": repo.default_branch,
            "size_kb": repo.size_kb,
            "created_at": repo.created_at.isoformat() if repo.created_at else None,
            "updated_at": updated_at,
        }

    def _serialize_settings(self, s: models.RepositorySettings) -> Dict:
        return {
            "strictness_level": s.strictness_level.value if s.strictness_level else "balanced",
            "enabled_categories": s.enabled_categories,
            "max_tokens_override": s.max_tokens_override,
        }

    def _serialize_automation(self, a: models.RepositoryAutomation) -> Dict:
        return {
            "auto_review_on_push": a.auto_review_on_push,
            "review_pull_requests": a.review_pull_requests,
            "merge_blocking_enabled": a.merge_blocking_enabled,
            "min_severity": a.min_severity.value if a.min_severity else "major",
            "confidence_threshold": a.confidence_threshold,
        }
