"""
Comment service — handles formatting and posting GitHub PR comments.
Refactored to be asynchronous using httpx.
"""
import logging
from typing import List, Dict, Optional
import httpx

from db.enum_utils import normalize_severity
from integrations.ai.ai_orchestrator import AIOrchestrator

logger = logging.getLogger(__name__)


class CommentService:
    """
    Handles formatting and posting GitHub PR comments.
    """

    def __init__(self, github_token: str):
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self._ai = AIOrchestrator()

    async def post_review_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        issues: List[Dict],
        score: float,
        grade: str,
        hotspots: List[Dict],
    ):
        """
        Post a comprehensive review summary as a comment on a GitHub PR.
        """
        if not self.github_token:
            logger.warning("No GitHub token provided, skipping comment post.")
            return

        # Generate senior-dev narrative via Ollama (run in executor — it's blocking)
        loop = __import__('asyncio').get_event_loop()
        try:
            llm_narrative = await loop.run_in_executor(
                None,
                self._ai.generate_pr_review_comment,
                issues,
                score,
                repo_full_name,
            )
        except Exception as e:
            logger.warning("LLM narrative generation failed, using structured comment: %s", e)
            llm_narrative = ""

        body = self._build_comment_body(issues, score, grade, hotspots, llm_narrative)
        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {self.github_token}",
            "User-Agent": "AutoCritic-App"
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, headers=headers, json={"body": body})
                response.raise_for_status()
                logger.info("Successfully posted review comment to %s#%d", repo_full_name, pr_number)
            except httpx.HTTPStatusError as e:
                logger.error("Failed to post comment to GitHub: %s - %s", e.response.status_code, e.response.text)
            except Exception as e:
                logger.error("Unexpected error posting comment to GitHub: %s", str(e))

    def _build_comment_body(
        self,
        issues: List[Dict],
        score: float,
        grade: str,
        hotspots: List[Dict],
        llm_narrative: str = "",
    ) -> str:
        """
        Construct a markdown-formatted GitHub PR comment.
        LLM narrative goes first as the human-readable review,
        followed by structured data as a reference section.
        """
        severity_count = {"critical": 0, "major": 0, "minor": 0}
        for issue in issues:
            canonical = normalize_severity(issue.get("severity")).value
            severity_count[canonical] += 1

        score_bar = self._score_bar(score)

        # Header
        body = f"## 🤖 AutoCritic — `{score:.0f}/100` {score_bar} ({grade})\n\n"
        body += (
            f"| 🔴 Critical | 🟠 Major | 🟡 Minor | Total |\n"
            f"|---|---|---|---|\n"
            f"| {severity_count['critical']} | {severity_count['major']} | {severity_count['minor']} | {len(issues)} |\n\n"
        )

        # LLM narrative — the senior dev voice
        if llm_narrative:
            body += "---\n\n"
            body += llm_narrative
            body += "\n\n"

        # Hotspots
        if hotspots:
            body += "---\n\n### 🔥 Hotspots\n"
            for h in hotspots[:5]:
                fp = h.get("file") or h.get("file_path", "unknown")
                count = h.get("issue_count") or h.get("count", 0)
                body += f"- `{fp}` — {count} issue{'s' if count != 1 else ''}\n"
            body += "\n"

        # Issue reference table
        body += "---\n\n### 📋 Issues\n"
        body += "| Severity | File | Line | Description |\n"
        body += "|---|---|---|---|\n"
        icon_map = {"critical": "🔴", "major": "🟠", "minor": "🟡"}
        for issue in issues[:25]:
            canonical = normalize_severity(issue.get("severity")).value
            icon = icon_map.get(canonical, "🟡")
            fp = issue.get("file_path") or issue.get("file", "unknown")
            line = issue.get("line") or issue.get("line_number", "?")
            msg = (issue.get("message") or issue.get("description", ""))[:80]
            body += f"| {icon} {canonical} | `{fp}` | {line} | {msg} |\n"

        if len(issues) > 25:
            body += f"\n_...and {len(issues) - 25} more. View all on the [AutoCritic dashboard](https://autocritic.io)._\n"

        body += "\n---\n_Generated by [AutoCritic](https://autocritic.io) · qwen2.5-coder:7b_"
        return body

    @staticmethod
    def _score_bar(score: float) -> str:
        filled = round(score / 10)
        return "█" * filled + "░" * (10 - filled)
