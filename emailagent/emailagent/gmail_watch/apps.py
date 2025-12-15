from django.apps import AppConfig


class GmailWatchConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "emailagent.gmail_watch"

    def ready(self):
        # Ensure signals are loaded if added in future
        try:
            import emailagent.gmail_watch.models  # noqa: F401
        except Exception:
            pass

