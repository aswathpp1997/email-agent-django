from django.urls import path

from . import views

urlpatterns = [
    path("auth/google", views.auth_google, name="gmail_auth_google"),
    path("auth/google/callback", views.auth_google_callback, name="gmail_auth_google_callback"),
    path("webhook/gmail", views.gmail_webhook, name="gmail_webhook"),
    path("pubsub", views.pubsub_webhook, name="gmail_pubsub"),
    path("hello", views.hello, name="gmail_hello"),
    path("gitlab-issues", views.get_gitlab_issues, name="gitlab_issues"),
    path("bedrock-sample", views.bedrock_sample, name="bedrock_sample"),
]

