"""
Fingerprint service — issue identity and lifecycle management.

Implements fingerprint hashing, lifecycle state transitions
(active → resolved → regressed), and regression detection.
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Set
from uuid import UUID

from sqlalchemy import select, and_, update, func
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models
from db.models import FingerprintStatus
from db.enum_utils import normalize_severity

logger = logging.getLogger(__name__)

# Current fingerprint algorithm version
FINGERPRINT_VERSION = "v1.0"


def normalize_code_context(code: str) -> str:
    """
    Normalize code for fingerprinting stability.
    Removes whitespace variance, comments, and blank lines
    to make fingerprints resilient to formatting changes.
    """
    lines = code.strip().splitlines()
    normalized = []
    for line in lines:
        stripped = line.strip()
        # Skip empty lines and pure comments
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        # Collapse whitespace
        stripped = re.sub(r"\s+", " ", stripped)
        normalized.append(stripped)
    return "\n".join(normalized)


def compute_fingerprint_hash(
    file_path: str,
    rule_id: str,
    code_context: str,
    category: str = "",
) -> str:
    """
    Compute a deterministic fingerprint hash for an issue.

    Input: file_path + rule_id + normalized_code_context + category
    Output: SHA256 hex digest
    """
    normalized = normalize_code_context(code_context)
    raw = f"{file_path}|{rule_id}|{normalized}|{category}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FingerprintService:
    """
    Manages fingerprint lifecycle:
    - Create or match fingerprints for review issues
    - Track active → resolved → regressed transitions
    - Handle regression detection
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def process_review_fingerprints(
        self,
        review_id: str,
        repository_id: str,
        tenant_id: str,
        issues: List[Dict],
    ) -> List[Dict]:
        """
        Process all issues from a completed review:
        1. Compute fingerprint hash for each issue
        2. Match against existing fingerprints
        3. Create new fingerprints for unmatched issues
        4. Mark absent fingerprints as resolved
        5. Detect regressions

        Returns issues enriched with fingerprint_id.
        """
        # Load all active/resolved fingerprints for this repo
        existing_fp = await self._load_repo_fingerprints(repository_id)
        fp_hash_map = {fp.fingerprint_hash: fp for fp in existing_fp}

        seen_hashes: Set[str] = set()
        enriched_issues = []

        for issue in issues:
            fp_hash = compute_fingerprint_hash(
                file_path=issue.get("file_path", ""),
                rule_id=issue.get("rule_id", issue.get("title", "")),
                code_context=issue.get("code_context", ""),
                category=issue.get("category", ""),
            )

            seen_hashes.add(fp_hash)

            if fp_hash in fp_hash_map:
                # Existing fingerprint — update lifecycle
                fp = fp_hash_map[fp_hash]
                fp = await self._handle_existing_fingerprint(fp, review_id)
            else:
                # New fingerprint — severity must be canonical before the DB insert.
                fp = await self._create_fingerprint(
                    repository_id=repository_id,
                    tenant_id=tenant_id,
                    fingerprint_hash=fp_hash,
                    severity=normalize_severity(issue.get("severity")),
                    category=issue.get("category"),
                    review_id=review_id,
                )
                fp_hash_map[fp_hash] = fp

            issue["fingerprint_id"] = str(fp.id)
            issue["fingerprint_hash"] = fp_hash
            enriched_issues.append(issue)

        # Mark fingerprints NOT seen in this review as resolved
        await self._resolve_absent_fingerprints(
            repository_id, seen_hashes, existing_fp
        )

        await self.db.commit()

        return enriched_issues

    async def get_fingerprint_detail(
        self, fingerprint_id: str, tenant_id: str
    ) -> Optional[Dict]:
        """Fetch fingerprint detail with lifecycle info."""
        stmt = select(models.Fingerprint).where(
            models.Fingerprint.id == fingerprint_id,
            models.Fingerprint.tenant_id == tenant_id,
        )
        result = await self.db.execute(stmt)
        fp = result.scalar_one_or_none()

        if not fp:
            return None

        # Count total occurrences across reviews
        total_occurrences_stmt = select(func.count()).select_from(
            select(models.Issue.id)
            .where(models.Issue.fingerprint_id == fingerprint_id)
            .subquery()
        )
        total_occurrences = await self.db.scalar(total_occurrences_stmt) or 0

        return {
            "id": str(fp.id),
            "fingerprint_hash": fp.fingerprint_hash,
            "severity": fp.severity.value if fp.severity else None,
            "category": fp.category,
            "status": fp.status.value if fp.status else None,
            "first_seen_at": fp.first_seen_at.isoformat() if fp.first_seen_at else None,
            "resolved_at": fp.resolved_at.isoformat() if fp.resolved_at else None,
            "regression_count": fp.regression_count or 0,
            "total_occurrences": total_occurrences,
        }

    # -------------------------------------------------------
    # INTERNAL HELPERS
    # -------------------------------------------------------

    async def _load_repo_fingerprints(
        self, repository_id: str
    ) -> List[models.Fingerprint]:
        """Load all fingerprints for a repository."""
        stmt = select(models.Fingerprint).where(
            models.Fingerprint.repository_id == repository_id,
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def _handle_existing_fingerprint(
        self, fp: models.Fingerprint, _review_id: str
    ) -> models.Fingerprint:
        """Handle re-appearance of an existing fingerprint."""
        if fp.status == FingerprintStatus.resolved:
            # REGRESSION: was resolved, now reappeared
            fp.status = FingerprintStatus.regressed
            fp.regression_count = (fp.regression_count or 0) + 1
            fp.resolved_at = None
            logger.info(
                "Fingerprint %s regressed (count=%d)", fp.id, fp.regression_count
            )
        # Other statuses (active, regressed) remain unchanged as they are still "present"
        return fp

    async def _create_fingerprint(
        self,
        repository_id: str,
        tenant_id: str,
        fingerprint_hash: str,
        severity: Optional[models.IssueSeverity],
        category: Optional[str],
        review_id: str,
    ) -> models.Fingerprint:
        """Create a new fingerprint record."""
        fp = models.Fingerprint(
            repository_id=repository_id,
            tenant_id=tenant_id,
            fingerprint_hash=fingerprint_hash,
            severity=severity,
            category=category,
            status=FingerprintStatus.active,
            first_seen_review_id=review_id,
        )
        self.db.add(fp)
        await self.db.flush()
        return fp

    async def _resolve_absent_fingerprints(
        self,
        _repository_id: str,
        seen_hashes: Set[str],
        existing_fps: List[models.Fingerprint],
    ):
        """Mark fingerprints as resolved if they didn't appear in the latest review."""
        now = datetime.now(timezone.utc)
        for fp in existing_fps:
            if fp.fingerprint_hash not in seen_hashes:
                if fp.status in (FingerprintStatus.active, FingerprintStatus.regressed):
                    fp.status = FingerprintStatus.resolved
                    fp.resolved_at = now
                    logger.info("Fingerprint %s resolved", fp.id)
