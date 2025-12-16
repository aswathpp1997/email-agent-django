"""Configuration management for Gmail Watch application."""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class Config:
    """Centralized configuration management."""
    
    # Google OAuth
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_CALLBACK_URL: Optional[str] = None
    ACCESS_TOKEN: Optional[str] = None
    
    # GitLab
    GITLAB_TOKEN: Optional[str] = None
    GITLAB_URL: str = "https://code.qburst.com"
    PROJECT_ID: Optional[str] = None
    
    # AWS Bedrock
    AGENT_ID: Optional[str] = None
    ALIAS_ID: Optional[str] = None
    AWS_REGION: str = "us-east-1"
    
    # Gmail
    START_HISTORY_ID: int = 2377
    GMAIL_STATE_ID: int = 1  # ID for singleton GmailState record
    
    # Google API Scopes
    GOOGLE_SCOPES = [
        "profile",
        "email",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.labels",
    ]
    
    @classmethod
    def load(cls) -> None:
        """Load configuration from environment variables."""
        cls.GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
        cls.GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
        cls.GOOGLE_CALLBACK_URL = os.getenv("GOOGLE_CALLBACK_URL")
        cls.ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
        
        cls.GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
        cls.GITLAB_URL = os.getenv("GITLAB_URL", cls.GITLAB_URL)
        cls.PROJECT_ID = os.getenv("PROJECT_ID")
        
        cls.AGENT_ID = os.getenv("AGENT_ID")
        cls.ALIAS_ID = os.getenv("ALIAS_ID")
        cls.AWS_REGION = os.getenv("REGION", cls.AWS_REGION)
        
        start_history_id = os.getenv("START_HISTORY_ID")
        if start_history_id:
            try:
                cls.START_HISTORY_ID = int(start_history_id)
            except ValueError:
                logger.warning(f"Invalid START_HISTORY_ID: {start_history_id}, using default")
        
        # Log important configuration
        logger.info(f"[config] AGENT_ID: {cls.AGENT_ID}")
        logger.info(f"[config] ALIAS_ID: {cls.ALIAS_ID}")
        logger.info(f"[config] AWS_REGION: {cls.AWS_REGION}")
    
    @classmethod
    def validate_google_oauth(cls) -> tuple[bool, Optional[str]]:
        """Validate Google OAuth configuration."""
        if not cls.GOOGLE_CLIENT_ID:
            return False, "Missing GOOGLE_CLIENT_ID"
        if not cls.GOOGLE_CLIENT_SECRET:
            return False, "Missing GOOGLE_CLIENT_SECRET"
        if not cls.GOOGLE_CALLBACK_URL:
            return False, "Missing GOOGLE_CALLBACK_URL"
        return True, None
    
    @classmethod
    def validate_gitlab(cls) -> tuple[bool, Optional[str]]:
        """Validate GitLab configuration."""
        if not cls.GITLAB_TOKEN:
            return False, "Missing GITLAB_TOKEN"
        if not cls.PROJECT_ID:
            return False, "Missing PROJECT_ID"
        return True, None
    
    @classmethod
    def validate_bedrock(cls) -> tuple[bool, Optional[str]]:
        """Validate Bedrock configuration."""
        if not cls.AGENT_ID:
            return False, "Missing AGENT_ID"
        if not cls.ALIAS_ID:
            return False, "Missing ALIAS_ID"
        return True, None


# Initialize configuration on module load
Config.load()

