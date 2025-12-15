from django.db import models


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

