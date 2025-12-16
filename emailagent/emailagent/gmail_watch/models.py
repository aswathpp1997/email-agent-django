from django.db import models


class GmailOAuthToken(models.Model):
    """Stores OAuth tokens for Gmail accounts."""
    
    email = models.EmailField(unique=True, db_index=True)
    access_token = models.TextField()
    refresh_token = models.TextField(blank=True, null=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "gmail_oauth_tokens"
        verbose_name = "Gmail OAuth Token"
        verbose_name_plural = "Gmail OAuth Tokens"
    
    def __str__(self) -> str:
        return f"GmailOAuthToken({self.email})"


class GmailState(models.Model):
    """Tracks the latest processed Gmail history ID."""

    last_history_id = models.BigIntegerField(default=2377)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"GmailState(last_history_id={self.last_history_id})"


class GmailMessage(models.Model):
    STATUS_PENDING = "Pending"
    STATUS_APPROVED = "Approved"
    STATUS_DECLINED = "Declined"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_DECLINED, "Declined"),
    ]

    history_id = models.BigIntegerField()
    message_id = models.CharField(max_length=255, unique=True)
    subject = models.TextField(blank=True, default="")
    body = models.TextField(blank=True, default="")
    bedrock_json = models.JSONField(blank=True, null=True)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.message_id} ({self.status})"

