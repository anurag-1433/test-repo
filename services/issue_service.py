"""
Issue service — issue CRUD, status transitions, and dismissal handling.

Manages issue lifecycle at the instance level, including filtering,
dismissal with reason tracking, and batch operations.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models
from db.models import IssueStatus

logger = logging.getLogger(__name__)

# Valid status transitions
ALLOWED_TRANSITIONS = {
    IssueStatus.open: [IssueStatus.dismissed],
    IssueStatus.dismissed: [IssueStatus.open],
    # 'resolved' is system-controlled only
}

DISMISS_REASONS = {"false_positive", "accepted_risk", "will_fix_later"}


class IssueService:
    """
    Manages review issues: queries, filtering, status updates, and dismissals.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_issues(
        self,
        tenant_id: str,
        review_id: Optional[str] = None,
        repository_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        file_path: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict:
        """List issues with filters and pagination."""
        base = select(models.Issue).where(
            models.Issue.tenant_id == tenant_id,
        )

        if review_id:
            base = base.where(models.Issue.review_id == review_id)
        if repository_id:
            base = base.where(models.Issue.repository_id == repository_id)
        if severity:
            base = base.where(models.Issue.severity == severity)
        if category:
            base = base.where(models.Issue.category == category)
        if status:
            base = base.where(models.Issue.status == status)
        if file_path:
            base = base.where(models.Issue.file_path == file_path)

        total_stmt = select(func.count()).select_from(base.subquery())
        total = await self.db.scalar(total_stmt)

        result = await self.db.execute(
            base.order_by(
                models.Issue.severity,
                models.Issue.file_path,
                models.Issue.line_number,
            )
            .limit(limit)
            .offset(offset)
        )
        issues = result.scalars().all()

        return {
            "items": [self._serialize(i) for i in issues],
            "total": total or 0,
            "limit": limit,
            "offset": offset,
        }

    async def get_issue(self, issue_id: str, tenant_id: str) -> Optional[Dict]:
        """Get a single issue by ID."""
        stmt = select(models.Issue).where(
            models.Issue.id == issue_id,
            models.Issue.tenant_id == tenant_id,
        )
        result = await self.db.execute(stmt)
        issue = result.scalar_one_or_none()

        if not issue:
            return None

        return self._serialize(issue)

    async def update_status(
        self,
        issue_id: str,
        tenant_id: str,
        new_status: str,
        dismiss_reason: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Update issue status. Only user-controlled transitions allowed:
        - open → dismissed (with reason)
        - dismissed → open (reopen)

        'resolved' is system-controlled via fingerprint lifecycle.
        """
        stmt = select(models.Issue).where(
            models.Issue.id == issue_id,
            models.Issue.tenant_id == tenant_id,
        )
        result = await self.db.execute(stmt)
        issue = result.scalar_one_or_none()

        if not issue:
            return None

        # Validate transition
        try:
            target_status = IssueStatus(new_status)
        except ValueError:
            raise ValueError(f"Invalid status: {new_status}")

        current = issue.status
        allowed = ALLOWED_TRANSITIONS.get(current, [])
        if target_status not in allowed:
            raise ValueError(
                f"Cannot transition from {current.value} to {new_status}"
            )

        # Validate dismiss reason
        if target_status == IssueStatus.dismissed:
            if dismiss_reason and dismiss_reason not in DISMISS_REASONS:
                raise ValueError(
                    f"Invalid dismiss reason. Must be one of: {DISMISS_REASONS}"
                )
            issue.dismiss_reason = dismiss_reason or "accepted_risk"

        if target_status == IssueStatus.open:
            issue.dismiss_reason = None

        issue.status = target_status
        await self.db.commit()
        await self.db.refresh(issue)

        return self._serialize(issue)

    async def batch_dismiss(
        self,
        issue_ids: List[str],
        tenant_id: str,
        dismiss_reason: str = "accepted_risk",
    ) -> int:
        """Batch dismiss multiple issues. Returns count of dismissed issues."""
        dismissed = 0
        for issue_id in issue_ids:
            stmt = select(models.Issue).where(
                models.Issue.id == issue_id,
                models.Issue.tenant_id == tenant_id,
                models.Issue.status == IssueStatus.open,
            )
            result = await self.db.execute(stmt)
            issue = result.scalar_one_or_none()

            if issue:
                issue.status = IssueStatus.dismissed
                issue.dismiss_reason = dismiss_reason
                dismissed += 1

        await self.db.commit()
        return dismissed

    async def get_issue_summary(self, review_id: str, tenant_id: str) -> Dict:
        """Get severity summary counts for a review."""
        stmt = select(models.Issue).where(
            models.Issue.review_id == review_id,
            models.Issue.tenant_id == tenant_id,
        )
        result = await self.db.execute(stmt)
        issues = result.scalars().all()

        summary = {"critical": 0, "major": 0, "minor": 0, "total": 0}
        for issue in issues:
            severity = issue.severity.value if issue.severity else "minor"
            if severity in summary:
                summary[severity] += 1
            summary["total"] += 1

        return summary

    # -------------------------------------------------------
    # SERIALIZATION
    # -------------------------------------------------------

    def _serialize(self, issue: models.Issue) -> Dict:
        return {
            "id": str(issue.id),
            "tenant_id": str(issue.tenant_id),
            "repository_id": str(issue.repository_id) if issue.repository_id else None,
            "review_id": str(issue.review_id) if issue.review_id else None,
            "fingerprint_id": str(issue.fingerprint_id) if issue.fingerprint_id else None,
            "file_path": issue.file_path,
            "line_number": issue.line_number,
            "severity": issue.severity.value if issue.severity else None,
            "category": issue.category,
            "title": issue.title,
            "description": issue.description,
            "why_it_matters": issue.why_it_matters,
            "suggestion": issue.suggestion,
            "engine_source": issue.engine_source,
            "confidence_score": issue.confidence_score,
            "status": issue.status.value if issue.status else None,
            "dismiss_reason": issue.dismiss_reason,
            "first_seen_at": issue.first_seen_at.isoformat() if issue.first_seen_at else None,
            "created_at": issue.created_at.isoformat() if issue.created_at else None,
            "updated_at": issue.updated_at.isoformat() if issue.updated_at else None,
        }
