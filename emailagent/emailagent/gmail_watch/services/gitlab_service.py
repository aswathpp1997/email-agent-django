"""GitLab API service."""
import logging
from typing import Any, Dict, List, Optional

import requests

from ..config import Config
from ..constants import REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


class GitLabServiceError(Exception):
    """Base exception for GitLab service errors."""
    pass


class GitLabService:
    """Service for interacting with GitLab API."""
    
    def __init__(
        self,
        token: Optional[str] = None,
        project_id: Optional[str] = None,
        base_url: Optional[str] = None
    ):
        """Initialize GitLab service."""
        self.token = token or Config.GITLAB_TOKEN
        self.project_id = project_id or Config.PROJECT_ID
        self.base_url = base_url or Config.GITLAB_URL
        
        if not self.token or not self.project_id:
            logger.warning("[GitLabService] Missing token or project_id")
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get GitLab API headers."""
        if not self.token:
            return {}
        return {"PRIVATE-TOKEN": self.token}
    
    def list_issues(self) -> List[Dict[str, Any]]:
        """
        List all issues for the configured project.
        
        Returns:
            List of issue dicts
            
        Raises:
            GitLabServiceError: If request fails
        """
        if not self.token or not self.project_id:
            raise GitLabServiceError("Missing GITLAB_TOKEN or PROJECT_ID")
        
        url = f"{self.base_url}/api/v4/projects/{self.project_id}/issues"
        
        logger.info(f"[GitLabService] Fetching issues from {url}")
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            issues = response.json()
            logger.info(f"[GitLabService] Fetched {len(issues)} issues")
            return issues
        except requests.RequestException as exc:
            error_detail = getattr(exc, "response", None)
            logger.error(
                f"[GitLabService] Failed to fetch issues: {exc}, "
                f"response: {error_detail}"
            )
            raise GitLabServiceError(f"Failed to fetch issues: {exc}") from exc
    
    def create_issue(
        self,
        title: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        priority: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new GitLab issue.
        
        Args:
            title: Issue title
            description: Issue description
            labels: List of labels
            priority: Priority label (will be added to labels)
            
        Returns:
            Created issue dict
            
        Raises:
            GitLabServiceError: If creation fails
        """
        if not self.token or not self.project_id:
            raise GitLabServiceError("Missing GITLAB_TOKEN or PROJECT_ID")
        
        url = f"{self.base_url}/api/v4/projects/{self.project_id}/issues"
        
        # Combine labels and priority
        issue_labels = list(labels) if labels else []
        if priority and priority not in issue_labels:
            issue_labels.append(priority)
        
        data = {
            "title": title,
            "description": description,
        }
        
        if issue_labels:
            data["labels"] = ",".join(issue_labels)
        
        logger.info(f"[GitLabService] Creating issue: {title}")
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                data=data,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            issue = response.json()
            logger.info(f"[GitLabService] Created issue: {issue.get('iid')}")
            return issue
        except requests.RequestException as exc:
            error_detail = getattr(exc, "response", None)
            logger.error(
                f"[GitLabService] Failed to create issue: {exc}, "
                f"response: {error_detail}"
            )
            raise GitLabServiceError(f"Failed to create issue: {exc}") from exc

