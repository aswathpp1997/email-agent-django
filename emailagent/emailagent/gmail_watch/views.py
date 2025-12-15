import base64
import json
import os
import uuid
import logging
import textwrap
from typing import Any, Dict, Optional

import boto3
import requests
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction

from .models import GmailMessage, GmailState

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
START_HISTORY_ID = int(os.getenv("START_HISTORY_ID", "2377"))

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

    # Track latest history id in DB
    with transaction.atomic():
        state, _created = GmailState.objects.select_for_update().get_or_create(
            id=1, defaults={"last_history_id": START_HISTORY_ID}
        )
        start_history_id = state.last_history_id or START_HISTORY_ID

    history_resp = _fetch_history(headers, str(start_history_id))
    fetched_messages: list[Dict[str, Any]] = []
    errors: list[str] = []

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

    processed = 0
    bedrock_saved: list[int] = []
    for msg in fetched_messages:
        subject, body_text = _extract_message_text(msg)
        email_message = f"Subject: {subject}\n\n{body_text}"
        prompt = _build_ticket_prompt(email_message)

        try:
            completion, _raw = _invoke_agent(
                agent_id=AGENT_ID,
                alias_id=ALIAS_ID,
                prompt=prompt,
                session_id=f"session-{uuid.uuid4()}",
            )
            parsed = json.loads(completion)
        except json.JSONDecodeError:
            errors.append("bedrock_parse_failed")
            continue
        except Exception as exc:
            print("[gmail_watch] Bedrock invocation failed:", exc)
            errors.append("bedrock_invoke_failed")
            continue

        try:
            gm = GmailMessage.objects.create(
                history_id=history_id,
                message_id=msg.get("id", ""),
                subject=subject,
                body=body_text,
                bedrock_json=parsed,
                status=GmailMessage.STATUS_PENDING,
            )
            bedrock_saved.append(gm.id)
            processed += 1
        except Exception as exc:
            print("[gmail_watch] DB save failed:", exc)
            errors.append("db_save_failed")

    # Update latest history id
    with transaction.atomic():
        state = GmailState.objects.select_for_update().get(id=1)
        if history_id and (not state.last_history_id or int(history_id) > state.last_history_id):
            state.last_history_id = int(history_id)
            state.save(update_fields=["last_history_id", "updated_at"])

    print("[gmail_watch] Fetched messages:", len(fetched_messages))
    print("[gmail_watch] Saved entries:", bedrock_saved)

    return JsonResponse(
        {
            "status": "ok",
            "historyId": history_id,
            "startHistoryId": start_history_id,
            "fetched_messages": len(fetched_messages),
            "saved_entries": bedrock_saved,
            "errors": errors,
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


def _invoke_agent(agent_id: str, alias_id: str, prompt: str, session_id: str) -> tuple[str, list[Dict[str, Any]]]:
    """Invoke a Bedrock Agent, collect streamed output, and capture raw events for debugging."""
    client = _bedrock_client()
    response = client.invoke_agent(
        agentId=agent_id,
        agentAliasId=alias_id,
        sessionId=session_id,
        inputText=prompt,
        enableTrace=True,
        streamingConfigurations={
            "applyGuardrailInterval": 20,
            "streamFinalResponse": True,
        }
    )

    completion = ""
    raw_events: list[Dict[str, Any]] = []
    for event in response.get("completion", []):
        logger.info("[bedrock] event keys=%s", list(event.keys()))
        print("[bedrock] event:", event)
        raw_events.append(event)
        if "chunk" in event:
            raw = event["chunk"].get("bytes")
            if raw is not None:
                decoded = raw.decode()
                completion += decoded
                print(f"[bedrock] chunk decoded len={len(decoded)} text={decoded!r}")
                logger.info("[bedrock] chunk len=%s", len(decoded))
        if "finalResponse" in event:
            final_parts = event["finalResponse"].get("finalResponse", [])
            for part in final_parts:
                text = part.get("text")
                if text:
                    completion += text
                    print(f"[bedrock] finalResponse text len={len(text)} text={text!r}")
                    logger.info("[bedrock] finalResponse text len=%s", len(text))
        if "outputText" in event:
            for ot in event.get("outputText", []):
                text = ot.get("text")
                if text:
                    completion += text
                    print(f"[bedrock] outputText len={len(text)} text={text!r}")
                    logger.info("[bedrock] outputText len=%s", len(text))
        if "trace" in event:
            trace_event = event["trace"]
            for key, value in trace_event.get("trace", {}).items():
                logger.info("Trace %s: %s", key, value)

    return completion, raw_events


def _make_json_safe(obj: Any) -> Any:
    """Recursively convert bytes into utf-8 strings and leave other types intact."""
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode(errors="replace")
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_json_safe(v) for v in obj]
    return obj


def _serialize_events(events: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """Prepare events for JSON serialization by decoding any bytes recursively."""
    return [_make_json_safe(ev) for ev in events]


def _decode_b64_url(data: str) -> str:
    """Decode base64url-encoded strings safely."""
    try:
        # Gmail uses URL-safe base64 without padding
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_payload_text(payload: Dict[str, Any]) -> str:
    """Extract text content from a Gmail message payload."""
    if not payload:
        return ""

    body = payload.get("body", {})
    if body and body.get("data"):
        return _decode_b64_url(body["data"])

    parts = payload.get("parts", [])
    texts: list[str] = []
    for part in parts:
        mime_type = part.get("mimeType", "")
        if mime_type.startswith("text/plain"):
            data = part.get("body", {}).get("data")
            if data:
                texts.append(_decode_b64_url(data))
        # Recurse if nested parts
        if "parts" in part:
            nested = _extract_payload_text(part)
            if nested:
                texts.append(nested)

    return "\n".join(filter(None, texts))


def _extract_message_text(message: Dict[str, Any]) -> tuple[str, str]:
    """Return (subject, body_text or snippet) from a Gmail message."""
    payload = message.get("payload", {})
    headers = payload.get("headers", [])
    subject = ""
    for h in headers:
        if h.get("name", "").lower() == "subject":
            subject = h.get("value", "")
            break

    body_text = _extract_payload_text(payload)
    if not body_text:
        body_text = message.get("snippet", "")

    return subject, body_text


def _build_ticket_prompt(email_message: str) -> str:
    prompt_template = textwrap.dedent(
        """
        Read the email subject and body. Determine if it describes a real issue that should become a GitLab ticket.
        If yes, extract key details and generate a clear issue title, description, labels, and priority.
        If no, return should_create_ticket=false.

        Do NOT call any tools or functions. Respond only with JSON.

        Guidelines:
        - Create a ticket only if the email reports a bug, incident, access problem, performance issue, or feature request.
        - If the email is not actionable (e.g., greetings, thanks, spam), return "should_create_ticket": false.
        - Use short, clear titles.
        - Include important details in the description (error messages, impact, steps, timestamps).
        - Priority: P1 critical outage; P2 major problem; P3 normal bug/feature request; P4 low impact.
        - Detected issue types: bug, feature_request, outage, performance, access_issue, other.

        Output ONLY this JSON:
        {
          "should_create_ticket": true | false,
          "issue_title": "",
          "issue_description": "",
          "issue_labels": [],
          "priority": "",
          "detected_issue_type": ""
        }

        Email message:
        {email_message}
        """
    ).strip()
    return prompt_template.replace("{email_message}", email_message)


def _create_gitlab_issue_from_payload(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Create a GitLab issue using parsed Bedrock output."""
    if not GITLAB_TOKEN or not PROJECT_ID:
        print("[gmail_watch] Missing GITLAB_TOKEN/PROJECT_ID; skipping issue creation")
        return None

    title = payload.get("issue_title") or "Untitled issue"
    description = payload.get("issue_description") or ""
    labels = payload.get("issue_labels") or []
    priority = payload.get("priority")
    if priority:
        if isinstance(labels, list):
            if priority not in labels:
                labels.append(priority)
        else:
            labels = [priority]

    url = f"{GITLAB_URL}/api/v4/projects/{PROJECT_ID}/issues"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    data = {
        "title": title,
        "description": description,
    }
    if labels:
        data["labels"] = ",".join(labels)

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print("[gmail_watch] GitLab issue creation failed:", exc, getattr(exc, "response", None))
        return None


@csrf_exempt
def list_gmail_messages(request: HttpRequest) -> HttpResponse:
    status = request.GET.get("status")
    qs = GmailMessage.objects.all().order_by("-created_at")
    if status:
        qs = qs.filter(status=status)

    data = []
    for item in qs[:200]:
        data.append(
            {
                "id": item.id,
                "history_id": item.history_id,
                "message_id": item.message_id,
                "subject": item.subject,
                "status": item.status,
                "created_at": item.created_at,
                "bedrock_json": item.bedrock_json,
                "body": item.body,
            }
        )
    return JsonResponse({"results": data})


@csrf_exempt
def create_ticket_from_entry(request: HttpRequest, entry_id: int) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseBadRequest("Use POST.")

    try:
        entry = GmailMessage.objects.get(id=entry_id)
    except GmailMessage.DoesNotExist:
        return JsonResponse({"error": "not_found"}, status=404)

    if not entry.bedrock_json:
        return JsonResponse({"error": "no_bedrock_json"}, status=400)

    if not entry.bedrock_json.get("should_create_ticket"):
        return JsonResponse({"error": "should_create_ticket_false"}, status=400)

    issue = _create_gitlab_issue_from_payload(entry.bedrock_json)
    if issue:
        entry.status = GmailMessage.STATUS_APPROVED
        entry.save(update_fields=["status", "updated_at"])
        return JsonResponse({"issue": issue, "entry_id": entry.id})

    return JsonResponse({"error": "gitlab_issue_failed"}, status=500)


@csrf_exempt
def bedrock_sample(request: HttpRequest) -> HttpResponse:
    """Sample GET endpoint to exercise Bedrock Agent invocation."""
    if request.method != "GET":
        return HttpResponseBadRequest("Use GET.")

    if not AGENT_ID or not ALIAS_ID:
        return JsonResponse({"error": "Missing AGENT_ID or ALIAS_ID env"}, status=400)

    session_id = f"session-{uuid.uuid4()}"

    # Allow quick prompt override for debugging
    email_message = request.GET.get(
        "message",
        textwrap.dedent(
            """
            Subject: Issue: App crashes when uploading files

            Hi team,

            I noticed that the app crashes every time I try to upload a PDF file. The screen freezes for a few seconds and then closes completely. This started happening after the latest update.

            Can someone please look into this?

            Thanks,
            Alex
            """
        ).strip(),
    )

    prompt_override = request.GET.get("prompt")
    if prompt_override:
        prompt = prompt_override
    else:
        prompt_template = textwrap.dedent(
            """
            Read the email subject and body. Determine if it describes a real issue that should become a GitLab ticket.
            If yes, extract key details and generate a clear issue title, description, labels, and priority.
            If no, return should_create_ticket=false.

            Do NOT call any tools or functions. Respond only with JSON.

            Guidelines:
            - Create a ticket only if the email reports a bug, incident, access problem, performance issue, or feature request.
            - If the email is not actionable (e.g., greetings, thanks, spam), return "should_create_ticket": false.
            - Use short, clear titles.
            - Include important details in the description (error messages, impact, steps, timestamps).
            - Priority: P1 critical outage; P2 major problem; P3 normal bug/feature request; P4 low impact.
            - Detected issue types: bug, feature_request, outage, performance, access_issue, other.

            Output ONLY this JSON:
            {
              "should_create_ticket": true | false,
              "issue_title": "",
              "issue_description": "",
              "issue_labels": [],
              "priority": "",
              "detected_issue_type": ""
            }

            Email message:
            {email_message}
            """
        ).strip()
        # Avoid str.format conflicts with JSON braces; perform a simple replace for the placeholder.
        prompt = prompt_template.replace("{email_message}", email_message)

    try:
        completion, raw_events = _invoke_agent(
            agent_id=AGENT_ID,
            alias_id=ALIAS_ID,
            prompt=prompt,
            session_id=session_id,
        )

        print("[gmail_watch] Bedrock completion:", completion)
        parsed = None
        try:
            parsed = json.loads(completion)
        except json.JSONDecodeError:
            parsed = completion

        return JsonResponse({
            
            "completion": parsed,
        })
    except Exception as exc:  # boto3 can raise various exceptions
        logger.exception("Bedrock sample invocation failed")
        return JsonResponse({"error": "bedrock_invoke_failed", "detail": str(exc)}, status=500)

