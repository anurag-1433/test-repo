"""
Usage service — token accounting, quota enforcement, and overage detection.

Tracks per-tenant token usage, enforces daily/monthly limits,
and writes to the usage_ledger for billing.
"""

import logging
from datetime import datetime, timezone, date, timedelta
from typing import Dict, Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models

logger = logging.getLogger(__name__)

# Default quota limits (overridden by tenant plan)
DEFAULT_MONTHLY_TOKEN_LIMIT = 500_000
DEFAULT_MAX_REVIEWS_PER_DAY = 100
DEFAULT_MAX_TOKENS_PER_REVIEW = 50_000


class UsageService:
    """
    Manages token and review usage tracking per tenant.
    Writes to usage_ledger and enforces quotas.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_review_usage(
        self, tenant_id: str, tokens_used: int, review_id: str
    ):
        """
        Record token usage for a completed review.
        Upserts into usage_ledger for the current date.
        """
        today = date.today()

        stmt = select(models.UsageLedger).where(
            models.UsageLedger.tenant_id == tenant_id,
            models.UsageLedger.date == today,
        )
        result = await self.db.execute(stmt)
        ledger = result.scalar_one_or_none()

        if ledger:
            ledger.tokens_used = (ledger.tokens_used or 0) + tokens_used
            ledger.review_count = (ledger.review_count or 0) + 1
        else:
            ledger = models.UsageLedger(
                tenant_id=tenant_id,
                date=today,
                tokens_used=tokens_used,
                review_count=1,
            )
            self.db.add(ledger)

        await self.db.commit()
        logger.info(
            "Recorded usage: tenant=%s, tokens=%d, review=%s",
            tenant_id, tokens_used, review_id,
        )

    async def get_monthly_usage(self, tenant_id: str) -> Dict:
        """Get token usage for the current month."""
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).date()

        stmt = select(
            func.coalesce(func.sum(models.UsageLedger.tokens_used), 0),
            func.coalesce(func.sum(models.UsageLedger.review_count), 0),
        ).where(
            models.UsageLedger.tenant_id == tenant_id,
            models.UsageLedger.date >= month_start,
        )
        result = await self.db.execute(stmt)
        tokens_used, review_count = result.one()

        limit = DEFAULT_MONTHLY_TOKEN_LIMIT

        return {
            "tokens_used_this_month": tokens_used,
            "review_count_this_month": review_count,
            "monthly_token_limit": limit,
            "quota_remaining": max(0, limit - tokens_used),
            "overage_flag": tokens_used > limit,
            "usage_percent": round((tokens_used / limit * 100), 1) if limit > 0 else 0,
        }

    async def get_daily_usage(self, tenant_id: str, target_date: Optional[date] = None) -> Dict:
        """Get usage for a specific day."""
        target = target_date or date.today()

        stmt = select(models.UsageLedger).where(
            models.UsageLedger.tenant_id == tenant_id,
            models.UsageLedger.date == target,
        )
        result = await self.db.execute(stmt)
        ledger = result.scalar_one_or_none()

        return {
            "date": target.isoformat(),
            "tokens_used": ledger.tokens_used if ledger else 0,
            "review_count": ledger.review_count if ledger else 0,
        }

    async def check_quota(self, tenant_id: str, estimated_tokens: int = 0) -> Dict:
        """
        Check whether a tenant has quota remaining for a new review.

        Returns:
            {"allowed": True/False, "reason": "...", ...}
        """
        usage = await self.get_monthly_usage(tenant_id)

        # Check monthly token limit
        if usage["overage_flag"]:
            return {
                "allowed": False,
                "reason": "Monthly token quota exceeded",
                "tokens_remaining": 0,
                "usage": usage,
            }

        # Check if estimated tokens would exceed
        remaining = usage["quota_remaining"]
        if estimated_tokens > 0 and estimated_tokens > remaining:
            return {
                "allowed": True,  # Allow but may truncate
                "reason": "Review may be truncated due to budget",
                "tokens_remaining": remaining,
                "may_truncate": True,
                "usage": usage,
            }

        # Check daily review count
        daily = await self.get_daily_usage(tenant_id)
        if daily["review_count"] >= DEFAULT_MAX_REVIEWS_PER_DAY:
            return {
                "allowed": False,
                "reason": f"Daily review limit ({DEFAULT_MAX_REVIEWS_PER_DAY}) reached",
                "tokens_remaining": remaining,
                "usage": usage,
            }

        return {
            "allowed": True,
            "reason": None,
            "tokens_remaining": remaining,
            "usage": usage,
        }

    async def get_usage_trend(self, tenant_id: str, days: int = 30):
        """Get daily usage trend for the last N days."""
        cutoff = date.today() - timedelta(days=days)

        stmt = (
            select(models.UsageLedger)
            .where(
                models.UsageLedger.tenant_id == tenant_id,
                models.UsageLedger.date >= cutoff,
            )
            .order_by(models.UsageLedger.date)
        )
        result = await self.db.execute(stmt)
        entries = result.scalars().all()

        return [
            {
                "date": e.date.isoformat(),
                "tokens_used": e.tokens_used or 0,
                "review_count": e.review_count or 0,
            }
            for e in entries
        ]
