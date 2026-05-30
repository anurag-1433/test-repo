"""
Quality service — score recalculation and trend smoothing.
Implements the versioned scoring formula from the design spec.
"""
import math
import logging
from typing import Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import db.models as models

logger = logging.getLogger(__name__)

SCORING_MODEL_VERSION = "v3.0"
# Weights for the three canonical DB severity values only.
SEVERITY_WEIGHTS = {"critical": 8, "major": 4, "minor": 1}
STRICTNESS_MULTIPLIERS = {"relaxed": 0.7, "lenient": 0.7, "balanced": 1.0, "strict": 1.3}
DISMISSAL_MODIFIERS = {"false_positive": 1.0, "accepted_risk": 0.5, "will_fix_later": 0.3}
# Larger decay constant = gentler penalty curve.
DECAY_CONSTANT = 30.0
# Score ceiling when any critical issue is present (no perfect score with a critical).
CRITICAL_SCORE_CAP = 80
# Treat every codebase as at least this many KLOC so tiny repos aren't destroyed.
MIN_KLOC = 5.0


class QualityService:
    def __init__(self, db: AsyncSession):
        self.db = db

    def compute_review_score(self, issues: List[Dict], loc: int = 10_000, strictness: str = "balanced") -> Dict:
        """Core scoring algorithm (pure logic).

        Uses exponential decay: score = 100 × exp(−density / DECAY_CONSTANT)
        Density is penalty per KLOC, floored at MIN_KLOC so small repos
        aren't unfairly destroyed by a handful of issues.
        """
        critical_count = 0
        raw_penalty = 0.0
        for issue in issues:
            severity = issue.get("severity", "minor").lower()
            weight = SEVERITY_WEIGHTS.get(severity, 1)
            if issue.get("status") == "dismissed" and issue.get("dismiss_reason"):
                weight *= (1 - DISMISSAL_MODIFIERS.get(issue["dismiss_reason"], 0.7))
            raw_penalty += weight
            if severity == "critical":
                critical_count += 1

        # Floor at MIN_KLOC to prevent tiny-repo score collapse
        kloc = max(loc / 1000, MIN_KLOC)
        density = raw_penalty / kloc
        adjusted = density * STRICTNESS_MULTIPLIERS.get(strictness, 1.0)

        # Exponential decay — no multiplicative critical penalty (already penalised by weight)
        raw_score = 100 * math.exp(-adjusted / DECAY_CONSTANT)
        cap = CRITICAL_SCORE_CAP if critical_count > 0 else 100
        score = round(max(0, min(raw_score, cap)), 1)

        return {
            "score": score,
            "raw_penalty": round(raw_penalty, 2),
            "critical_count": critical_count,
            "scoring_model_version": SCORING_MODEL_VERSION,
        }

    def compute_smoothed_trend(self, current: float, previous: Optional[float] = None) -> float:
        """Exponential moving average for trend smoothing (pure logic)."""
        return current if previous is None else round(0.7 * previous + 0.3 * current, 1)

    async def get_previous_score(self, repository_id: str) -> Optional[float]:
        """Fetch the quality score of the most recent completed review for a repo."""
        stmt = (
            select(models.Review)
            .where(
                models.Review.repository_id == repository_id, 
                models.Review.status == models.ReviewStatus.completed,
                models.Review.quality_score.isnot(None)
            )
            .order_by(models.Review.completed_at.desc())
            .limit(1)
        )
        result = await self.db.execute(stmt)
        review = result.scalar_one_or_none()
        return review.quality_score if review else None

    async def recalculate_for_review(self, review_id: str) -> Optional[Dict]:
        """Load review data and recalculate its quality score."""
        stmt = select(models.Review).where(models.Review.id == review_id)
        result = await self.db.execute(stmt)
        review = result.scalar_one_or_none()
        
        if not review:
            return None
            
        issues_stmt = select(models.Issue).where(models.Issue.review_id == review_id)
        issues_result = await self.db.execute(issues_stmt)
        issues = issues_result.scalars().all()
        
        settings_stmt = select(models.RepositorySettings).where(
            models.RepositorySettings.repository_id == review.repository_id
        )
        settings_result = await self.db.execute(settings_stmt)
        settings = settings_result.scalar_one_or_none()
        
        strictness = settings.strictness_level.value if settings and settings.strictness_level else "balanced"
        
        issue_dicts = [
            {
                "severity": i.severity.value if i.severity else "minor", 
                "status": i.status.value if i.status else "open", 
                "dismiss_reason": i.dismiss_reason
            } for i in issues
        ]
        
        # Estimate LOC if not present (simple heuristic)
        estimated_loc = max(review.files_analyzed or 1, 1) * 200
        result_data = self.compute_review_score(issue_dicts, loc=estimated_loc, strictness=strictness)
        
        review.quality_score = result_data["score"]
        review.scoring_model_version = SCORING_MODEL_VERSION
        
        await self.db.commit()
        return result_data
