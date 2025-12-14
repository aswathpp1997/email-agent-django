import base64
import json
import os
from typing import Any, Dict, Optional

import requests
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt

GOOGLE_SCOPES = [
    "profile",
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

# In-memory token storage for dev/demo parity with the Node service
TOKEN_STORE: Dict[str, Any] = {}


def _get_env(key: str) -> Optional[str]:
    value = os.getenv(key)
    if not value:
        print(f"[gmail_watch] Missing env var: {key}")
    return value


def auth_google(_request: HttpRequest) -> HttpResponse:
    client_id = _get_env("GOOGLE_CLIENT_ID")
    print(f"[gmail_watch] Client ID: {client_id}")
    redirect_uri = _get_env("GOOGLE_CALLBACK_URL")
    if not client_id or not redirect_uri:
        return HttpResponseBadRequest("Missing Google OAuth env configuration.")

    scope = " ".join(GOOGLE_SCOPES)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent",
    }
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{query}"
    return HttpResponseRedirect(auth_url)


def auth_google_callback(request: HttpRequest) -> HttpResponse:
    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("Missing authorization code.")

    client_id = _get_env("GOOGLE_CLIENT_ID")
    client_secret = _get_env("GOOGLE_CLIENT_SECRET")
    redirect_uri = _get_env("GOOGLE_CALLBACK_URL")
    if not client_id or not client_secret or not redirect_uri:
        return HttpResponseBadRequest("Missing Google OAuth env configuration.")

    token_endpoint = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    try:
        resp = requests.post(token_endpoint, data=data, timeout=10)
        resp.raise_for_status()
        tokens = resp.json()
        TOKEN_STORE["tokens"] = tokens
        print("[gmail_watch] Stored tokens:", tokens)
        return JsonResponse({"status": "ok", "tokens": tokens})
    except requests.RequestException as exc:
        print("[gmail_watch] Token exchange failed:", exc)
        return HttpResponseBadRequest("Token exchange failed.")


@csrf_exempt
def gmail_webhook(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST allowed.")

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON.")

    print("[gmail_watch] Gmail Webhook Received")
    print(payload)

    message = payload.get("message")
    if not message or "data" not in message:
        print("[gmail_watch] No message data found")
        return JsonResponse({"status": "no_message_data"}, status=200)

    encoded = message.get("data")
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
        decoded_json = json.loads(decoded)
        print("[gmail_watch] Decoded Message:", decoded_json)
    except (ValueError, json.JSONDecodeError) as exc:
        print("[gmail_watch] Failed to decode message.data:", exc)
        return JsonResponse({"status": "decode_failed"}, status=200)

    return JsonResponse({"status": "ok"})


@csrf_exempt
def pubsub_webhook(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST allowed.")
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON.")

    print("[gmail_watch] Pubsub received")
    print(payload)
    return JsonResponse({"status": "ok"})


def hello(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("Hello World from the Django server")

