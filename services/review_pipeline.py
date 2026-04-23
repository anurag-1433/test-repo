"""
services/review_pipeline.py
-----------------------------
Full async review execution pipeline.
Orchestrates multiple services to perform code analysis, scoring, and persistence.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models
from db.models import (
    Review,
    ReviewStatus,
    ReviewStage,
    IssueStatus,
)
from services.audit_service import log_event
from services.scan_service import ScanService
from services.fingerprint_service import FingerprintService
from services.quality_service import QualityService
from services.comment_service import CommentService
from services.analytics_service import AnalyticsService
from services.usage_service import UsageService
from db.enum_utils import normalize_severity
from intelligence.issue_similarity import IssueSimilarityEngine
from intelligence.issue_classifier import IssueClassifier
from intelligence.hotspot_detector import HotspotDetector
from integrations.ai.false_positive_filter import FalsePositiveFilter

logger = logging.getLogger(__name__)

REVIEW_STAGE_CHANGED_EVENT = "review.stage_changed"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class ReviewPipeline:
    """
    Orchestrates the end-to-end async review pipeline.
    
    This version is fully async-native and assumes dependency injection
    of all required sub-services.
    """

    def __init__(
        self,
        db: AsyncSession,
        scan_service: Optional[ScanService] = None,
        fingerprint_service: Optional[FingerprintService] = None,
        quality_service: Optional[QualityService] = None,
        comment_service: Optional[CommentService] = None,
        analytics_service: Optional[AnalyticsService] = None,
        usage_service: Optional[UsageService] = None,
    ):
        self.db = db
        self.scan_service = scan_service
        self.fingerprint_service = fingerprint_service
        self.quality_service = quality_service
        self.comment_service = comment_service
        self.analytics_service = analytics_service
        self.usage_service = usage_service

    async def _transition(
        self,
        review: Review,
        *,
        status: Optional[ReviewStatus] = None,
        stage: Optional[ReviewStage] = None,
        completed_at: Optional[datetime] = None,
        audit_action: str,
        audit_meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Helper to update state and log audit entry asynchronously."""
        prev_status = review.status.value if review.status else None
        prev_stage = review.stage.value if review.stage else None

        if status is not None:
            review.status = status
        if stage is not None:
            review.stage = stage
        if completed_at is not None:
            review.completed_at = completed_at

        await log_event(
            self.db,
            action=audit_action,
            entity_type="reviews",
            entity_id=str(review.id),
            tenant_id=str(review.tenant_id),
            metadata={
                **(audit_meta or {}),
                "from_status": prev_status,
                "to_status": review.status.value if review.status else None,
                "from_stage": prev_stage,
                "to_stage": review.stage.value if review.stage else None,
            },
        )

    # ------------------------------------------------------------------
    # Stage 1: Initializing + Dispatch
    # ------------------------------------------------------------------

    async def run_dispatch(self, review_id: str) -> Dict[str, Any]:
        """
        Load review, fetch PR diff, prepare file list for analysis.
        """
        from integrations.github.pr_fetcher import PRFetcher
        from config.settings import settings

        review = await self._load_review(review_id)

        # Stage: initializing
        await self._transition(
            review,
            status=ReviewStatus.running,
            stage=ReviewStage.initializing,
            audit_action="review.started",
            audit_meta={"trigger": review.trigger},
        )
        await self.db.commit()

        # Update to fetcher
        github_token = settings.GITHUB_TOKEN
        pr_fetcher = PRFetcher(github_token)

        # Stage: fetching_files (custom transition)
        await self._transition(review, stage=ReviewStage.static_analysis,
                             audit_action=REVIEW_STAGE_CHANGED_EVENT)
        await self.db.commit()

        # Resolve the best available GitHub token for this repo:
        # installation token (App auth) if the repo has one, else PAT fallback.
        from integrations.github.app_auth import GitHubAppAuth
        github_installation_id: Optional[int] = None
        if review.repository.github_installation_id:
            inst_row = await self.db.get(
                models.GithubInstallation, review.repository.github_installation_id
            )
            if inst_row:
                github_installation_id = inst_row.installation_id

        github_token = GitHubAppAuth.get().token_for_repo(github_installation_id)
        pr_fetcher = PRFetcher(github_token)

        if review.pr_url:
            logger.info(f"Fetching PR diff for review {review_id}")
            diff_text = pr_fetcher.fetch_pr_diff(review.pr_url)
            changed_files = pr_fetcher.parse_diff(diff_text)
        else:
            logger.info(f"No PR URL found for review {review_id}. Falling back to full commit scan.")
            repo_full_name = review.repository.name
            changed_files = self._fetch_all_repo_files(repo_full_name, review.commit_sha, pr_fetcher)

        _supported_exts = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java", ".go"}
        supported_files = {
            path: lines
            for path, lines in changed_files.items()
            if Path(path).suffix.lower() in _supported_exts
        }

        return {
            "review_id": review_id,
            "repo": review.repository.name,
            "commit_sha": review.commit_sha,
            "files": supported_files,
            "tenant_id": str(review.tenant_id),
            "github_installation_id": github_installation_id,
        }

    # ------------------------------------------------------------------
    # Stage 2: File Scanning
    # ------------------------------------------------------------------

    async def scan_file(
        self,
        repo_full_name: str,
        commit_sha: str,
        file_path: str,
        modified_lines: List[int],
        github_token: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Scan a single file using the ScanService (static analysis only).
        """
        if not self.scan_service:
            from engine.adapters.rule_engine_adapter import RuleEngineAdapter
            from services.scan_service import ScanService
            self.scan_service = ScanService(rule_engine=RuleEngineAdapter())

        return await self.scan_service.scan_file(
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
            file_path=file_path,
            modified_lines=modified_lines,
            github_token=github_token,
        )

    # ------------------------------------------------------------------
    # Stage 3: Finalize
    # ------------------------------------------------------------------

    async def run_finalize(
        self,
        file_results: List[List[Dict[str, Any]]],
        review_id: str,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Aggregate results, fingerprint, score, persist and complete.
        """
        # Flatten results — collect issues, tokens, and file contents for FP filter
        all_issues: List[Dict[str, Any]] = []
        file_contents: Dict[str, str] = {}
        total_tokens: int = 0
        for file_result in file_results:
            if isinstance(file_result, dict):
                all_issues.extend(file_result.get("issues", []))
                total_tokens += file_result.get("tokens", 0)
                fp = file_result.get("file_path", "")
                content = file_result.get("content", "")
                if fp and content:
                    file_contents[fp] = content
            elif isinstance(file_result, list):
                # backwards-compat with any caller still returning a plain list
                all_issues.extend(file_result)

        # Deduplication and classification (Intelligence layer)
        all_issues = IssueSimilarityEngine().deduplicate(all_issues)
        all_issues = IssueClassifier().classify_batch(all_issues)

        # False positive filter — run in executor to avoid blocking the event loop
        fp_filter = FalsePositiveFilter()
        filter_result = await asyncio.get_running_loop().run_in_executor(
            None, fp_filter.filter, all_issues, file_contents
        )
        all_issues = filter_result.kept

        # Normalize all severities to canonical DB values (critical / major / minor)
        # once, here, so every downstream consumer — fingerprinting, scoring,
        # DB persist, and GitHub comments — sees consistent values.
        for issue in all_issues:
            issue["severity"] = normalize_severity(issue.get("severity")).value

        # Load review
        review = await self._load_review(review_id)

        # Surface LLM-unavailable warning on the review record
        if filter_result.llm_unavailable:
            review.warnings = ["false_positive_filter_unavailable"]

        # Stage: post_processing
        await self._transition(review, stage=ReviewStage.post_processing,
                             audit_action=REVIEW_STAGE_CHANGED_EVENT)
        await self.db.flush()

        # Fingerprinting
        if self.fingerprint_service:
            all_issues = await self.fingerprint_service.process_review_fingerprints(
                review_id=review_id,
                repository_id=str(review.repository_id),
                tenant_id=str(review.tenant_id),
                issues=all_issues
            )
        
        # Persist logic
        self._persist_review_data(review, all_issues)
        
        # Scoring
        # Update denormalized counters on the review row so the UI reads correct values
        review.total_issues = len(all_issues)
        review.critical_count = sum(1 for i in all_issues if (i.get("severity") or "").lower() in ("critical",))
        review.major_count = sum(1 for i in all_issues if (i.get("severity") or "").lower() in ("major",))
        review.minor_count = sum(1 for i in all_issues if (i.get("severity") or "").lower() in ("minor",))
        review.files_analyzed = len({i.get("file_path") or i.get("file", "") for i in all_issues if i.get("file_path") or i.get("file")})

        if self.quality_service:
            loc = max(review.files_analyzed, 1) * 300
            score_data = self.quality_service.compute_review_score(all_issues, loc=loc)
            review.quality_score = score_data["score"]

        # Stage: analytics
        await self._transition(review, stage=ReviewStage.analytics,
                             audit_action=REVIEW_STAGE_CHANGED_EVENT)
        await self.db.flush()

        # Update analytics snapshot
        if self.analytics_service:
            await self.analytics_service.recompute_after_review(review_id, str(review.tenant_id))

        # Final transition: completed
        await self._transition(
            review,
            status=ReviewStatus.completed,
            stage=ReviewStage.completed,
            completed_at=_now_utc(),
            audit_action="review.completed",
            audit_meta={
                "issues_count": len(all_issues),
                "quality_score": review.quality_score,
            },
        )
        
        # Record actual token usage (prompt_eval_count + eval_count from Ollama)
        review.tokens_used = total_tokens
        if self.usage_service and total_tokens > 0:
            await self.usage_service.record_review_usage(str(review.tenant_id), total_tokens, review_id)

        await self.db.commit()

        # GitHub Comment (Only if it's a PR review)
        if self.comment_service and review.pr_number:
            logger.info(f"Posting review summary to GitHub PR #{review.pr_number}")
            hotspots = HotspotDetector().detect_hotspots(all_issues)
            await self.comment_service.post_review_comment(
                repo_full_name=review.repository.name,
                pr_number=review.pr_number,
                issues=all_issues,
                score=review.quality_score or 0.0,
                grade="B" if (review.quality_score or 0) > 80 else "C", # heuristic
                hotspots=hotspots
            )
        elif not review.pr_number:
            logger.info("Skipping GitHub comment: No PR number associated with this review.")

        return {
            "review_id": review_id,
            "issues_count": len(all_issues),
            "quality_score": review.quality_score,
        }

    async def mark_failed(self, review_id: str, error: str) -> None:
        """Mark the review as failed asynchronously."""
        review = await self._load_review(review_id)
        await self._transition(
            review,
            status=ReviewStatus.failed,
            completed_at=_now_utc(),
            audit_action="review.failed",
            audit_meta={"error": error},
        )
        await self.db.commit()

    async def _load_review(self, review_id: str) -> Review:
        stmt = (
            select(Review)
            .options(joinedload(Review.repository))
            .where(Review.id == review_id)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one()

    def _persist_review_data(self, review: Review, issues: List[Dict[str, Any]]):
        """Persist issues and review file summary rows.

        By the time this is called, all severities in `issues` have already
        been normalized to canonical values by run_finalize.
        normalize_severity() is called here as a safety net only.
        """
        file_counters: Dict[str, Dict[str, int]] = {}

        for item in issues:
            file_path = item.get("file_path") or item.get("file", "")
            severity = normalize_severity(item.get("severity")).value

            new_issue = models.Issue(
                review_id=review.id,
                tenant_id=review.tenant_id,
                repository_id=review.repository_id,
                file_path=file_path,
                line_number=item.get("line"),
                severity=severity,
                description=item.get("message", ""),
                category=item.get("category", "quality"),
                engine_source=item.get("engine_source", "static"),
                status=IssueStatus.open,
                fingerprint_id=item.get("fingerprint_id")
            )
            self.db.add(new_issue)

            # Track counters using the already-mapped severity value
            cntr = file_counters.setdefault(file_path, {"critical": 0, "major": 0, "minor": 0})
            cntr[severity] = cntr.get(severity, 0) + 1

        # Summary rows
        for file_path, cntr in file_counters.items():
            rf = models.ReviewFile(
                review_id=review.id,
                file_path=file_path,
                critical_count=cntr["critical"],
                major_count=cntr["major"],
                minor_count=cntr["minor"],
            )
            self.db.add(rf)

    def _fetch_all_repo_files(self, repo_full_name: str, commit_sha: str, pr_fetcher) -> dict:
        """
        Fetch supported source files in the repo at a specific commit, capped at
        FULL_SCAN_FILE_LIMIT. High-risk paths are prioritised so the most
        security/data-sensitive files are always included when the cap kicks in.
        """
        from config.settings import settings as _s

        _supported_exts = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java", ".go"}

        all_files = pr_fetcher.fetch_file_list(repo_full_name, commit_sha)
        source_files = [f for f in all_files if Path(f).suffix.lower() in _supported_exts]

        if len(source_files) <= _s.FULL_SCAN_FILE_LIMIT:
            return {f: [] for f in source_files}

        # Score each file so high-risk ones bubble to the top.
        _risk_keywords = {
            "auth": 10, "security": 10, "crypto": 10, "password": 10,
            "token": 9, "secret": 9, "jwt": 9, "oauth": 9,
            "db": 8, "database": 8, "migration": 8, "query": 8, "sql": 8,
            "model": 7, "schema": 7,
            "api": 6, "router": 6, "route": 6, "webhook": 6, "handler": 6,
            "payment": 6, "billing": 6, "admin": 6,
            "config": 5, "settings": 5, "middleware": 5,
        }

        def _risk_score(path: str) -> int:
            lower = path.lower().replace("\\", "/")
            return sum(weight for kw, weight in _risk_keywords.items() if kw in lower)

        source_files.sort(key=_risk_score, reverse=True)
        selected = source_files[: _s.FULL_SCAN_FILE_LIMIT]
        logger.info(
            "_fetch_all_repo_files: capped %d → %d files for full scan of %s",
            len(source_files),
            len(selected),
            repo_full_name,
        )
        return {f: [] for f in selected}
