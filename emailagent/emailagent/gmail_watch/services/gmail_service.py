"""Gmail API service."""
import base64
import json
import logging
from datetime import timedelta
from typing import Any, Dict, Optional

import requests
from django.utils import timezone

from ..config import Config
from ..constants import (
    GMAIL_HISTORY_ENDPOINT,
    GMAIL_MESSAGES_ENDPOINT,
    GOOGLE_TOKEN_ENDPOINT,
    REQUEST_TIMEOUT,
)
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
        self.token_obj: Optional[GmailOAuthToken] = None
        
        if access_token:
            self.access_token = access_token
            self.email = None
        elif email:
            self.email = email
            self.token_obj = self._fetch_token_from_db(email)
            self.access_token = self.token_obj.access_token if self.token_obj else None
        else:
            # Try to get first available token
            self.token_obj = GmailOAuthToken.objects.first()
            if self.token_obj:
                self.email = self.token_obj.email
                self.access_token = self.token_obj.access_token
            else:
                self.email = None
                self.access_token = None
        
        # Refresh token if expired
        if self.token_obj and self.access_token:
            self._ensure_valid_token()
        
        if not self.access_token:
            logger.warning(f"[GmailService] No access token available for email: {email}")
    
    def _fetch_token_from_db(self, email: str) -> Optional[GmailOAuthToken]:
        """Fetch token object from database for given email."""
        try:
            return GmailOAuthToken.objects.get(email=email)
        except GmailOAuthToken.DoesNotExist:
            logger.warning(f"[GmailService] No token found for email: {email}")
            return None
    
    def _is_token_expired(self, token_obj: GmailOAuthToken) -> bool:
        """Check if access token is expired or about to expire."""
        if not token_obj.token_expires_at:
            # If no expiration time is set, assume token is valid
            return False
        
        # Refresh if token expires in less than 5 minutes
        expiration_buffer = timedelta(minutes=5)
        now = timezone.now()
        
        # Ensure both datetimes are timezone-aware for comparison
        expires_at = token_obj.token_expires_at
        if timezone.is_naive(expires_at):
            # If token_expires_at is naive, make it timezone-aware
            expires_at = timezone.make_aware(expires_at)
        
        return now >= (expires_at - expiration_buffer)
    
    def _refresh_access_token(self, token_obj: GmailOAuthToken) -> bool:
        """
        Refresh access token using refresh token.
        
        Args:
            token_obj: GmailOAuthToken object to refresh
            
        Returns:
            True if refresh was successful, False otherwise
        """
        if not token_obj.refresh_token:
            logger.warning(f"[GmailService] No refresh token available for email: {token_obj.email}")
            return False
        
        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET:
            logger.error("[GmailService] Missing Google OAuth credentials for token refresh")
            return False
        
        data = {
            "client_id": Config.GOOGLE_CLIENT_ID,
            "client_secret": Config.GOOGLE_CLIENT_SECRET,
            "refresh_token": token_obj.refresh_token,
            "grant_type": "refresh_token",
        }
        
        try:
            logger.info(f"[GmailService] Refreshing access token for email: {token_obj.email}")
            response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=data, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            tokens = response.json()
            
            new_access_token = tokens.get("access_token")
            expires_in = tokens.get("expires_in")
            
            if not new_access_token:
                logger.error("[GmailService] No access token in refresh response")
                return False
            
            # Calculate new expiration time
            token_expires_at = None
            if expires_in:
                token_expires_at = timezone.now() + timedelta(seconds=expires_in)
            
            # Update token in database
            token_obj.access_token = new_access_token
            if token_expires_at:
                token_obj.token_expires_at = token_expires_at
            token_obj.save(update_fields=["access_token", "token_expires_at", "updated_at"])
            
            # Update instance variable
            self.access_token = new_access_token
            
            logger.info(f"[GmailService] Successfully refreshed access token for email: {token_obj.email}")
            return True
            
        except requests.RequestException as exc:
            error_detail = getattr(exc, "response", None)
            logger.error(
                f"[GmailService] Token refresh failed for email {token_obj.email}: {exc}, "
                f"response: {error_detail}"
            )
            return False
    
    def _ensure_valid_token(self) -> None:
        """Ensure access token is valid, refresh if expired."""
        if not self.token_obj:
            return
        
        if self._is_token_expired(self.token_obj):
            logger.info(f"[GmailService] Access token expired for email: {self.token_obj.email}, refreshing...")
            if not self._refresh_access_token(self.token_obj):
                logger.error(f"[GmailService] Failed to refresh token for email: {self.token_obj.email}")
                self.access_token = None
    
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
        # Ensure token is valid before making request
        if self.token_obj:
            self._ensure_valid_token()
        
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
            
            # If unauthorized, try refreshing token and retry once
            if response.status_code == 401 and self.token_obj:
                logger.warning("[GmailService] Got 401, attempting token refresh")
                if self._refresh_access_token(self.token_obj):
                    # Retry with new token
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
        # Ensure token is valid before making request
        if self.token_obj:
            self._ensure_valid_token()
        
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
            
            # If unauthorized, try refreshing token and retry once
            if response.status_code == 401 and self.token_obj:
                logger.warning(f"[GmailService] Got 401 for message {message_id}, attempting token refresh")
                if self._refresh_access_token(self.token_obj):
                    # Retry with new token
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

