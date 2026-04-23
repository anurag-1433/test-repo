"""
Service layer for GitHub operations.
Orchestrates fetching repos and importing them into the tenant's workspace.
"""
import logging
from typing import List, Dict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import db.models as models
from integrations.github.repo_fetcher import fetch_user_repositories

logger = logging.getLogger(__name__)


class GitHubService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_github_repos(self, access_token: str) -> List[Dict]:
        """Fetch the user's GitHub repos (not yet imported)."""
        return fetch_user_repositories(access_token)

    async def import_github_repo(
        self,
        repo_data: Dict,
        tenant_id: str,
    ) -> models.Repository:
        """
        Import a single GitHub repository into the tenant's workspace.

        PRECONDITION: caller MUST have validated that tenant_id exists
        in the tenants table before calling this method. Tenant provisioning
        is the responsibility of the API layer (/auth/sync or the import route).
        """
        logger.info(
            "Importing repo: tenant=%s name=%s external_id=%s",
            tenant_id, repo_data.get("full_name"), repo_data.get("external_id"),
        )

        # Check if already imported
        stmt = select(models.Repository).where(
            models.Repository.external_id == repo_data["external_id"],
            models.Repository.tenant_id == tenant_id,
        )
        result = await self.db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            logger.info(
                "Repo already imported: repo_id=%s name=%s",
                existing.id, existing.name,
            )
            return existing

        new_repo = models.Repository(
            name=repo_data["full_name"],
            external_id=repo_data["external_id"],
            tenant_id=tenant_id,
            primary_language=repo_data.get("language"),
            default_branch=repo_data.get("default_branch", "main"),
            size_kb=repo_data.get("size_kb", 0),
        )

        self.db.add(new_repo)
        await self.db.commit()
        await self.db.refresh(new_repo)

        logger.info(
            "Repo imported: repo_id=%s tenant=%s name=%s",
            new_repo.id, tenant_id, new_repo.name,
        )
        return new_repo
