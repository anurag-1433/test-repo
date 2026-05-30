"""
Review service — high-level review management and entry points.
Refactored to be an async service with dependency injection.
"""

import logging
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models
from db.models import ReviewStatus, ReviewStage
from services.github_service import GitHubService
from services.repository_service import RepositoryService

logger = logging.getLogger(__name__)


class ReviewService:
    """
    Main orchestration service for AutoCritic reviews.
    Manages review lifecycle in the database and dispatches jobs.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_review(self, review_id: str, tenant_id: str) -> Optional[models.Review]:
        """Fetch a review with its repository details."""
        stmt = (
            select(models.Review)
            .options(joinedload(models.Review.repository))
            .where(
                models.Review.id == review_id,
                models.Review.tenant_id == tenant_id
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_reviews(
        self, tenant_id: str, limit: int = 50, offset: int = 0
    ) -> Dict:
        """List reviews for a tenant with pagination."""
        from sqlalchemy import func
        
        base = (
            select(models.Review)
            .options(joinedload(models.Review.repository))
            .where(
                models.Review.tenant_id == tenant_id,
                models.Review.repository_id.isnot(None),
            )
            .order_by(models.Review.created_at.desc())
        )

        total_stmt = select(func.count()).select_from(base.subquery())
        total = await self.db.scalar(total_stmt)

        result = await self.db.execute(base.limit(limit).offset(offset))
        reviews = result.scalars().all()

        return {
            "items": reviews,
            "total": total,
            "limit": limit,
            "offset": offset
        }

    async def create_review(
        self, 
        repository_id: str, 
        tenant_id: str, 
        trigger: str = "manual",
        branch: str = "main",
        commit_sha: str = "HEAD",
        pr_number: Optional[int] = None,
        pr_url: Optional[str] = None
    ) -> models.Review:
        """Create a new review record in the pending state."""
        review = models.Review(
            repository_id=repository_id,
            tenant_id=tenant_id,
            status=ReviewStatus.pending,
            stage=ReviewStage.initializing,
            trigger=trigger,
            branch=branch,
            commit_sha=commit_sha,
            pr_number=pr_number,
            pr_url=pr_url
        )
        self.db.add(review)
        await self.db.commit()
        await self.db.refresh(review)
        return review

    @staticmethod
    def dispatch(review_id: str) -> str:
        """
        Dispatch an async review job via Celery.
        This remains static as it's the entry point to the distributed system.
        """
        try:
            from workers.review_worker import process_review
            result = process_review.delay(review_id)
            return result.id  # Celery task ID
        except Exception as exc:
            # Celery or Redis not available — run in a background thread
            import threading
            logger.warning(
                "Celery unavailable (%s), running review %s in background thread",
                exc, review_id
            )

            def _run():
                import asyncio
                from services.review_pipeline import ReviewPipeline
                from db.database import AsyncSessionLocal
                
                async def run_async():
                    async with AsyncSessionLocal() as db:
                        # Since we are in a thread, we need a fresh session
                        pipeline = ReviewPipeline(db)
                        try:
                            # Start the pipeline
                            dispatch_data = await pipeline.run_dispatch(review_id)
                            files = dispatch_data.get("files", {})
                            tenant_id = dispatch_data.get("tenant_id")
                            
                            if not files:
                                await pipeline.run_finalize([], review_id, tenant_id)
                                return

                            # For thread-fallback, we might not have a full worker group,
                            # so we run sequentially or use a local group (simplified here).
                            results = []
                            for file_path, lines in files.items():
                                res = await pipeline.scan_file(
                                    review_id, 
                                    dispatch_data["repo"], 
                                    dispatch_data["commit_sha"], 
                                    file_path, 
                                    lines
                                )
                                results.append(res)
                            
                            await pipeline.run_finalize(results, review_id, tenant_id)
                        except Exception as e:
                            logger.exception("Background execution failed: %s", e)
                            await pipeline.mark_failed(review_id, str(e))

                asyncio.run(run_async())

            t = threading.Thread(target=_run, daemon=True, name=f"review-{review_id}")
            t.start()
            return f"thread-{t.ident}"
