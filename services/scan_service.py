from __future__ import annotations

import asyncio
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor

from config.settings import settings
from integrations.github.pr_fetcher import PRFetcher

logger = logging.getLogger(__name__)


class ScanService:
    """
    Orchestrates file-level scans using static analysis only.

    Static analysis (RuleEngineAdapter) is the sole source of issues.
    The LLM is used downstream to analyse issue context and generate
    reports — it does NOT find issues here.
    """

    def __init__(self, rule_engine):
        self.rule_engine = rule_engine
        self._executor = ThreadPoolExecutor(max_workers=4)

    async def scan_file(
        self,
        repo_full_name: str,
        commit_sha: str,
        file_path: str,
        modified_lines: List[int],
        ai_budget: bool = True,  # retained for call-site compatibility; not used
        github_token: str = "",
    ) -> Dict:
        """
        Fetch file content from GitHub and run static analysis.

        Returns {"issues": [...], "tokens": 0, "content": str, "file_path": str}.
        content is the raw file source (empty string if file was unreadable).
        Token count is always 0 here; tokens are tracked by the AI report
        generator which runs separately against already-found issues.
        """
        loop = asyncio.get_event_loop()
        pr_fetcher = PRFetcher(github_token or settings.GITHUB_TOKEN)

        raw_content = await loop.run_in_executor(
            self._executor,
            pr_fetcher.fetch_raw_file,
            repo_full_name,
            file_path,
            commit_sha,
        )

        if not raw_content:
            logger.warning("scan_file: empty content for %s@%s", file_path, commit_sha)
            return {"issues": [], "tokens": 0, "content": "", "file_path": file_path}

        # Static analysis — always runs, deterministic, no LLM calls
        async def run_static() -> List[Dict]:
            import ast
            from pathlib import Path as _Path

            ext = _Path(file_path).suffix.lower()
            tree = None

            # Only Python files can be parsed with Python's ast module.
            # Non-Python rules (Java, JS, TS, Go) are all regex-based and
            # accept tree=None, so we skip ast.parse for every other language.
            if ext == ".py":
                try:
                    tree = ast.parse(raw_content)
                except SyntaxError as e:
                    logger.error("Static analysis parse error %s: %s", file_path, e)
                    return [{
                        "file_path": file_path,
                        "line": 1,
                        "severity": "critical",
                        "message": f"[Static] Syntax error: {e}",
                        "title": "Syntax Error",
                        "rule_id": "engine-parse-error",
                        "category": "reliability",
                        "engine_source": "static",
                        "code_context": "",
                    }]

            try:
                issues = self.rule_engine.analyze(tree, file_path, raw_content)
                return [
                    {
                        "file_path": file_path,
                        "line": issue.line,
                        "severity": (
                            issue.severity.name.lower()
                            if hasattr(issue.severity, "name")
                            else "minor"
                        ),
                        "message": f"[Static] {issue.message}",
                        "title": getattr(issue, "title", "Static analysis finding"),
                        "rule_id": getattr(issue, "rule_id", "static-rule"),
                        "category": (
                            issue.category.value
                            if hasattr(issue, "category") and hasattr(issue.category, "value")
                            else "quality"
                        ),
                        "engine_source": "static",
                        "code_context": getattr(issue, "line_content", ""),
                    }
                    for issue in issues
                    if not modified_lines or issue.line in modified_lines
                ]
            except Exception as e:
                logger.error("Static analysis failed for %s: %s", file_path, e)
                return []

        static_issues = await run_static()
        logger.info("scan_file: %s — %d static issues", file_path, len(static_issues))
        return {"issues": static_issues, "tokens": 0, "content": raw_content, "file_path": file_path}
