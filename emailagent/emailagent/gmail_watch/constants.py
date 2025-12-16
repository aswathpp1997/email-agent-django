"""Constants for Gmail Watch application."""

# Gmail Message Status Choices
class GmailMessageStatus:
    """Status constants for GmailMessage model."""
    PENDING = "Pending"
    APPROVED = "Approved"
    DECLINED = "Declined"


# Gmail API Endpoints
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GMAIL_HISTORY_ENDPOINT = f"{GMAIL_API_BASE}/users/me/history"
GMAIL_MESSAGES_ENDPOINT = f"{GMAIL_API_BASE}/users/me/messages"

# Google OAuth Endpoints
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

# Request Timeouts
REQUEST_TIMEOUT = 10

