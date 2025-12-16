"""Gmail API service."""
import base64
import json
import logging
from typing import Any, Dict, Optional

import requests

from ..constants import GMAIL_HISTORY_ENDPOINT, GMAIL_MESSAGES_ENDPOINT, REQUEST_TIMEOUT
from ..models import GmailOAuthToken

logger = logging.getLogger(__name__)


class GmailServiceError(Exception):
    """Base exception for Gmail service errors."""
    pass


class GmailService:
    """Service for interacting with Gmail API."""
    
    def __init__(self, email: Optional[str] = None, access_token: Optional[str] = None):
        """
        Initialize Gmail service with access token.
        
        Args:
            email: Email address to fetch tokens from database. If None, uses first available token.
            access_token: Direct access token (overrides database lookup if provided)
        """
        if access_token:
            self.access_token = access_token
            self.email = None
        elif email:
            self.email = email
            self.access_token = self._fetch_access_token_from_db(email)
        else:
            # Try to get first available token
            token_obj = GmailOAuthToken.objects.first()
            if token_obj:
                self.email = token_obj.email
                self.access_token = token_obj.access_token
            else:
                self.email = None
                self.access_token = None
        
        if not self.access_token:
            logger.warning(f"[GmailService] No access token available for email: {email}")
    
    def _fetch_access_token_from_db(self, email: str) -> Optional[str]:
        """Fetch access token from database for given email."""
        try:
            token_obj = GmailOAuthToken.objects.get(email=email)
            return token_obj.access_token
        except GmailOAuthToken.DoesNotExist:
            logger.warning(f"[GmailService] No token found for email: {email}")
            return None
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get authorization headers."""
        if not self.access_token:
            return {}
        return {"Authorization": f"Bearer {self.access_token}"}
    
    def fetch_history(self, start_history_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch Gmail history starting from a given history ID.
        
        Args:
            start_history_id: The history ID to start from
            
        Returns:
            History response dict or None on error
        """
        if not self.access_token:
            logger.warning("[GmailService] Cannot fetch history: missing access token")
            return None
        
        params = {
            "startHistoryId": start_history_id,
            "historyTypes": "messageAdded"
        }
        
        logger.info(f"[GmailService] Fetching history with params: {params}")
        
        try:
            response = requests.get(
                GMAIL_HISTORY_ENDPOINT,
                headers=self.headers,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"[GmailService] History fetched successfully: {len(result.get('history', []))} entries")
            return result
        except requests.RequestException as exc:
            error_detail = getattr(exc, "response", None)
            logger.error(
                f"[GmailService] History fetch failed: {exc}, "
                f"response: {error_detail}"
            )
            return None
    
    def fetch_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a full Gmail message by ID.
        
        Args:
            message_id: The Gmail message ID
            
        Returns:
            Message dict or None on error
        """
        if not self.access_token:
            logger.warning("[GmailService] Cannot fetch message: missing access token")
            return None
        
        params = {"format": "full"}
        url = f"{GMAIL_MESSAGES_ENDPOINT}/{message_id}"
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            error_detail = getattr(exc, "response", None)
            logger.error(
                f"[GmailService] Message fetch failed for {message_id}: {exc}, "
                f"response: {error_detail}"
            )
            return None
    
    @staticmethod
    def decode_b64_url(data: str) -> str:
        """
        Decode base64url-encoded strings safely.
        
        Args:
            data: Base64url-encoded string
            
        Returns:
            Decoded string
        """
        try:
            # Gmail uses URL-safe base64 without padding
            padded = data + "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning(f"[GmailService] Failed to decode base64url: {exc}")
            return ""
    
    @staticmethod
    def extract_payload_text(payload: Dict[str, Any]) -> str:
        """
        Extract text content from a Gmail message payload.
        
        Args:
            payload: Gmail message payload dict
            
        Returns:
            Extracted text content
        """
        if not payload:
            return ""
        
        # Check direct body data
        body = payload.get("body", {})
        if body and body.get("data"):
            return GmailService.decode_b64_url(body["data"])
        
        # Check parts
        parts = payload.get("parts", [])
        texts: list[str] = []
        
        for part in parts:
            mime_type = part.get("mimeType", "")
            if mime_type.startswith("text/plain"):
                data = part.get("body", {}).get("data")
                if data:
                    texts.append(GmailService.decode_b64_url(data))
            
            # Recurse for nested parts
            if "parts" in part:
                nested = GmailService.extract_payload_text(part)
                if nested:
                    texts.append(nested)
        
        return "\n".join(filter(None, texts))
    
    @staticmethod
    def extract_message_text(message: Dict[str, Any]) -> tuple[str, str]:
        """
        Extract subject and body text from a Gmail message.
        
        Args:
            message: Full Gmail message dict
            
        Returns:
            Tuple of (subject, body_text)
        """
        payload = message.get("payload", {})
        headers = payload.get("headers", [])
        
        subject = ""
        for header in headers:
            if header.get("name", "").lower() == "subject":
                subject = header.get("value", "")
                break
        
        body_text = GmailService.extract_payload_text(payload)
        if not body_text:
            body_text = message.get("snippet", "")
        
        return subject, body_text

