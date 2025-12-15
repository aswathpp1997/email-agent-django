import base64
import json
import os
import uuid
import logging
from typing import Any, Dict, Optional

import boto3
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

GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
GITLAB_URL = os.getenv("GITLAB_URL", "https://code.qburst.com")
PROJECT_ID = os.getenv("PROJECT_ID")
AGENT_ID = os.getenv("AGENT_ID")
ALIAS_ID = os.getenv("ALIAS_ID")
AWS_REGION = os.getenv("REGION", "us-east-1")

logger = logging.getLogger(__name__)

print(f"[gmail_watch] AGENT_ID: {AGENT_ID}")
print(f"[gmail_watch] ALIAS_ID: {ALIAS_ID}")
print(f"[gmail_watch] AWS_REGION: {AWS_REGION}")


def _get_env(key: str) -> Optional[str]:
    value = os.getenv(key)
    if not value:
        print(f"[gmail_watch] Missing env var: {key}")
    return value


@csrf_exempt
def get_gitlab_issues(_request: HttpRequest) -> HttpResponse:
    if not GITLAB_TOKEN or not PROJECT_ID:
        return JsonResponse({"error": "Missing GITLAB_TOKEN or PROJECT_ID env"}, status=400)

    url = f"{GITLAB_URL}/api/v4/projects/{PROJECT_ID}/issues"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        print("[gmail_watch] GitLab issues:", data)
        return JsonResponse(data, safe=False)
    except requests.RequestException as exc:
        print("[gmail_watch] GitLab issues fetch failed:", exc, getattr(exc, "response", None))
        return JsonResponse({"error": "gitlab_issues_failed"}, status=500)


def auth_google(_request: HttpRequest) -> HttpResponse:
    client_id = _get_env("GOOGLE_CLIENT_ID")
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

    # Use the historyId from the Pub/Sub payload to fetch the latest added messages
    history_id = decoded_json.get("historyId")
    if not history_id:
        print("[gmail_watch] No historyId in decoded message")
        return JsonResponse({"status": "ok", "note": "no_history_id"})

    headers = _auth_headers()
    if not headers:
        print("[gmail_watch] Missing ACCESS_TOKEN for history fetch")
        return JsonResponse({"status": "ok", "note": "missing_access_token"})

    history_resp = _fetch_history(headers, str(history_id))
    fetched_messages: list[Dict[str, Any]] = []

    if history_resp:
        history_entries = history_resp.get("history", [])
        for entry in history_entries:
            for added in entry.get("messagesAdded", []):
                msg = added.get("message")
                if not msg:
                    continue
                msg_id = msg.get("id")
                if not msg_id:
                    continue
                full_msg = _fetch_message(headers, msg_id)
                if full_msg:
                    fetched_messages.append(full_msg)

    print("[gmail_watch] Fetched messages:", fetched_messages)

    return JsonResponse(
        {
            "status": "ok",
            "historyId": history_id,
            "fetched_messages": len(fetched_messages),
            "messages": fetched_messages,
        }
    )


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


def _auth_headers() -> Optional[Dict[str, str]]:
    access_token = _get_env("ACCESS_TOKEN")
    if not access_token:
        return None
    return {"Authorization": f"Bearer {access_token}"}


def _fetch_history(headers: Dict[str, str], start_history_id: str) -> Optional[Dict[str, Any]]:
    params = {"startHistoryId": start_history_id, "historyTypes": "messageAdded"}
    try:
        resp = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/history",
            headers=headers,
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print("[gmail_watch] history call failed (webhook helper):", exc, getattr(exc, "response", None))
        return None


def _fetch_message(headers: Dict[str, str], message_id: str) -> Optional[Dict[str, Any]]:
    params = {"format": "full"}
    try:
        resp = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
            headers=headers,
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print("[gmail_watch] message call failed (webhook helper):", exc, getattr(exc, "response", None))
        return None


def _bedrock_client():
    return boto3.client("bedrock-agent-runtime", region_name=AWS_REGION)


def _invoke_agent(agent_id: str, alias_id: str, prompt: str, session_id: str) -> str:
    """Invoke a Bedrock Agent and collect streamed output."""
    client = _bedrock_client()
    response = client.invoke_agent(
        agentId=agent_id,
        agentAliasId=alias_id,
        sessionId=session_id,
        inputText=prompt,
        enableTrace=True,
        streamingConfigurations={
            "applyGuardrailInterval": 20,
            "streamFinalResponse": False
        }
    )

    completion = ""
    for event in response.get("completion", []):
        if "chunk" in event:
            chunk = event["chunk"]["bytes"].decode()
            completion += chunk
        if "trace" in event:
            trace_event = event["trace"]
            for key, value in trace_event.get("trace", {}).items():
                logger.info("Trace %s: %s", key, value)

    return completion


@csrf_exempt
def bedrock_sample(request: HttpRequest) -> HttpResponse:
    """Sample GET endpoint to exercise Bedrock Agent invocation."""
    if request.method != "GET":
        return HttpResponseBadRequest("Use GET.")

    if not AGENT_ID or not ALIAS_ID:
        return JsonResponse({"error": "Missing AGENT_ID or ALIAS_ID env"}, status=400)

    session_id = f"session-{uuid.uuid4()}"
    message = """Subject: Issue: App crashes when uploading files

Hi team,

I noticed that the app crashes every time I try to upload a PDF file. The screen freezes for a few seconds and then closes completely. This started happening after the latest update.

Can someone please look into this?

Thanks,
Alex"""
    prompt = f"Process this incoming message: {message}"

    try:
        completion = _invoke_agent(
            agent_id=AGENT_ID,
            alias_id=ALIAS_ID,
            prompt=prompt,
            session_id=session_id,
        )
        parsed = None
        try:
            parsed = json.loads(completion)
        except json.JSONDecodeError:
            parsed = completion

        return JsonResponse({
            "sessionId": session_id,
            "prompt": prompt,
            "completion": parsed,
        })
    except Exception as exc:  # boto3 can raise various exceptions
        logger.exception("Bedrock sample invocation failed")
        return JsonResponse({"error": "bedrock_invoke_failed", "detail": str(exc)}, status=500)

