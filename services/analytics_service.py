"""
Analytics service — post-review aggregation into precomputed snapshot tables.
Ensures dashboard reads are O(1) via tenant_daily_metrics and repository_daily_metrics.
"""
import logging
from datetime import date, datetime, timezone, timedelta
from typing import Dict, Optional, List
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import db.models as models

logger = logging.getLogger(__name__)


class AnalyticsService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def recompute_after_review(self, review_id: str, tenant_id: str):
        """Called after review completion. Updates all aggregate tables."""
        stmt = select(models.Review).where(models.Review.id == review_id)
        result = await self.db.execute(stmt)
        review = result.scalar_one_or_none()
        
        if not review:
            return
            
        await self._update_repo_daily(str(review.repository_id), tenant_id)
        await self._update_tenant_daily(tenant_id)
        await self.db.commit()
        logger.info("Analytics recomputed for review=%s", review_id)

    async def get_tenant_overview(self, tenant_id: str) -> Dict:
        """Fetch high-level aggregate metrics for a tenant."""
        repos_stmt = select(func.count()).select_from(models.Repository).where(
            models.Repository.tenant_id == tenant_id, 
            models.Repository.deleted_at.is_(None)
        )
        repos = await self.db.scalar(repos_stmt)
        
        reviews_stmt = select(func.count()).select_from(models.Review).where(
            models.Review.tenant_id == tenant_id
        )
        reviews = await self.db.scalar(reviews_stmt)
        
        issues_stmt = select(
            func.count().label("total"),
            func.count().filter(models.Issue.severity == models.IssueSeverity.critical).label("critical"),
            func.count().filter(models.Issue.severity == models.IssueSeverity.major).label("major"),
            func.count().filter(models.Issue.severity == models.IssueSeverity.minor).label("minor"),
        ).where(models.Issue.tenant_id == tenant_id)
        issues_result = await self.db.execute(issues_stmt)
        issues = issues_result.one()
        
        avg_score_stmt = select(func.avg(models.Review.quality_score)).where(
            models.Review.tenant_id == tenant_id, 
            models.Review.quality_score.isnot(None)
        )
        avg_score = await self.db.scalar(avg_score_stmt)
        
        return {
            "total_repositories": repos or 0, 
            "total_reviews": reviews or 0,
            "total_issues": issues.total or 0, 
            "critical_count": issues.critical or 0,
            "major_count": issues.major or 0, 
            "minor_count": issues.minor or 0,
            "avg_quality_score": round(avg_score, 1) if avg_score else None,
        }

    async def get_trend(self, tenant_id: str, days: int = 30) -> List[Dict]:
        """Fetch daily metrics trend for a tenant."""
        cutoff = date.today() - timedelta(days=days)
        stmt = select(models.TenantDailyMetrics).where(
            models.TenantDailyMetrics.tenant_id == tenant_id,
            models.TenantDailyMetrics.date >= cutoff,
        ).order_by(models.TenantDailyMetrics.date)
        
        result = await self.db.execute(stmt)
        snapshots = result.scalars().all()
        
        return [
            {
                "date": s.date.isoformat(), 
                "quality_score": s.quality_score,
                "open_issues": s.open_issues, 
                "critical": s.critical
            } for s in snapshots
        ]

    async def _update_repo_daily(self, repository_id: str, _tenant_id: str):
        """Update daily metrics for a specific repository."""
        today = date.today()
        
        issues_stmt = select(models.Issue).where(
            models.Issue.repository_id == repository_id,
            models.Issue.status == models.IssueStatus.open
        )
        issues_result = await self.db.execute(issues_stmt)
        issues = issues_result.scalars().all()

        c = sum(1 for i in issues if i.severity == models.IssueSeverity.critical)
        m = sum(1 for i in issues if i.severity == models.IssueSeverity.major)
        n = sum(1 for i in issues if i.severity == models.IssueSeverity.minor)
        
        latest_stmt = select(models.Review).where(
            models.Review.repository_id == repository_id,
            models.Review.quality_score.isnot(None)
        ).order_by(models.Review.completed_at.desc()).limit(1)
        latest_result = await self.db.execute(latest_stmt)
        latest = latest_result.scalar_one_or_none()
        score = latest.quality_score if latest else None

        existing_stmt = select(models.RepositoryDailyMetrics).where(
            models.RepositoryDailyMetrics.repository_id == repository_id, 
            models.RepositoryDailyMetrics.date == today
        )
        existing_result = await self.db.execute(existing_stmt)
        existing = existing_result.scalar_one_or_none()
        
        if existing:
            existing.quality_score = score
            existing.open_issues = len(issues)
            existing.critical = c
            existing.major = m
            existing.minor = n
        else:
            self.db.add(models.RepositoryDailyMetrics(
                repository_id=repository_id, 
                date=today,
                quality_score=score, 
                open_issues=len(issues), 
                critical=c, 
                major=m, 
                minor=n
            ))

    async def _update_tenant_daily(self, tenant_id: str):
        """Update daily metrics for a specific tenant."""
        today = date.today()
        
        issues_stmt = select(models.Issue).where(
            models.Issue.tenant_id == tenant_id,
            models.Issue.status == models.IssueStatus.open
        )
        issues_result = await self.db.execute(issues_stmt)
        issues = issues_result.scalars().all()

        c = sum(1 for i in issues if i.severity == models.IssueSeverity.critical)
        m = sum(1 for i in issues if i.severity == models.IssueSeverity.major)
        n = sum(1 for i in issues if i.severity == models.IssueSeverity.minor)
        
        avg_stmt = select(func.avg(models.Review.quality_score)).where(
            models.Review.tenant_id == tenant_id, 
            models.Review.quality_score.isnot(None)
        )
        avg = await self.db.scalar(avg_stmt)

        existing_stmt = select(models.TenantDailyMetrics).where(
            models.TenantDailyMetrics.tenant_id == tenant_id, 
            models.TenantDailyMetrics.date == today
        )
        existing_result = await self.db.execute(existing_stmt)
        existing = existing_result.scalar_one_or_none()
        
        if existing:
            existing.quality_score = round(avg, 1) if avg else None
            existing.open_issues = len(issues)
            existing.critical = c
            existing.major = m
            existing.minor = n
        else:
            self.db.add(models.TenantDailyMetrics(
                tenant_id=tenant_id, 
                date=today,
                quality_score=round(avg, 1) if avg else None, 
                open_issues=len(issues), 
                critical=c, 
                major=m, 
                minor=n
            ))
