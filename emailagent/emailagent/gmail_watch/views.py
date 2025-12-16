"""Django views for Gmail Watch application."""
import base64
import json
import logging
import uuid
from typing import Any, Dict

import requests
from django.db import transaction
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
    JsonResponse,
)
from django.views.decorators.csrf import csrf_exempt

from .config import Config
from .constants import GOOGLE_AUTH_ENDPOINT, GOOGLE_TOKEN_ENDPOINT
from .models import GmailMessage, GmailState
from .services import BedrockService, GitLabService, GmailService
from .utils import build_ticket_prompt, format_email_message

logger = logging.getLogger(__name__)

# In-memory token storage for dev/demo (consider moving to database/cache in production)
TOKEN_STORE: Dict[str, Any] = {}


def auth_google(_request: HttpRequest) -> HttpResponse:
    """Initiate Google OAuth flow."""
    is_valid, error_msg = Config.validate_google_oauth()
    if not is_valid:
        return HttpResponseBadRequest(f"Missing Google OAuth configuration: {error_msg}")
    
    scope = " ".join(Config.GOOGLE_SCOPES)
    params = {
        "response_type": "code",
        "client_id": Config.GOOGLE_CLIENT_ID,
        "redirect_uri": Config.GOOGLE_CALLBACK_URL,
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent",
    }
    
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    auth_url = f"{GOOGLE_AUTH_ENDPOINT}?{query}"
    
    return HttpResponseRedirect(auth_url)


def auth_google_callback(request: HttpRequest) -> HttpResponse:
    """Handle Google OAuth callback."""
    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("Missing authorization code.")
    
    is_valid, error_msg = Config.validate_google_oauth()
    if not is_valid:
        return HttpResponseBadRequest(f"Missing Google OAuth configuration: {error_msg}")
    
    data = {
        "code": code,
        "client_id": Config.GOOGLE_CLIENT_ID,
        "client_secret": Config.GOOGLE_CLIENT_SECRET,
        "redirect_uri": Config.GOOGLE_CALLBACK_URL,
        "grant_type": "authorization_code",
    }
    
    try:
        response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=data, timeout=10)
        response.raise_for_status()
        tokens = response.json()
        TOKEN_STORE["tokens"] = tokens
        logger.info("[views] OAuth tokens stored successfully")
        return JsonResponse({"status": "ok", "tokens": tokens})
    except requests.RequestException as exc:
        logger.error(f"[views] Token exchange failed: {exc}", exc_info=True)
        return HttpResponseBadRequest("Token exchange failed.")


@csrf_exempt
def gmail_webhook(request: HttpRequest) -> HttpResponse:
    """Handle Gmail webhook notifications."""
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST allowed.")
    
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON.")
    
    logger.info("[views] Gmail webhook received")
    logger.debug(f"[views] Webhook payload: {payload}")
    
    message = payload.get("message")
    if not message or "data" not in message:
        logger.warning("[views] No message data found in webhook")
        return JsonResponse({"status": "no_message_data"}, status=200)
    
    # Decode webhook message
    encoded = message.get("data")
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
        decoded_json = json.loads(decoded)
        logger.info(f"[views] Decoded webhook message: {decoded_json}")
    except (ValueError, json.JSONDecodeError) as exc:
        logger.error(f"[views] Failed to decode message.data: {exc}")
        return JsonResponse({"status": "decode_failed"}, status=200)
    
    # Get stored history ID
    with transaction.atomic():
        state, _created = GmailState.objects.select_for_update().get_or_create(
            id=Config.GMAIL_STATE_ID,
            defaults={"last_history_id": Config.START_HISTORY_ID}
        )
        start_history_id = state.last_history_id or Config.START_HISTORY_ID
    
    # Extract webhook history ID
    history_id = decoded_json.get("historyId")
    if not history_id:
        logger.warning("[views] No historyId in decoded message")
        return JsonResponse({"status": "ok", "note": "no_history_id"})
    
    logger.info(
        f"[views] Processing webhook - stored history_id: {start_history_id}, "
        f"webhook history_id: {history_id}"
    )
    
    # Initialize services
    gmail_service = GmailService()
    bedrock_service = BedrockService()
    
    if not gmail_service.access_token:
        logger.warning("[views] Missing ACCESS_TOKEN for history fetch")
        return JsonResponse({"status": "ok", "note": "missing_access_token"})
    
    # Fetch history using stored history ID
    history_resp = gmail_service.fetch_history(str(start_history_id))
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
                
                full_msg = gmail_service.fetch_message(msg_id)
                if full_msg:
                    fetched_messages.append(full_msg)
    
    # Process messages
    processed = 0
    bedrock_saved: list[int] = []
    skipped_no_ticket: int = 0
    
    for msg in fetched_messages:
        subject, body_text = gmail_service.extract_message_text(msg)
        email_message = format_email_message(subject, body_text)
        prompt = build_ticket_prompt(email_message)
        
        try:
            completion, _raw = bedrock_service.invoke_agent(
                prompt=prompt,
                session_id=f"session-{uuid.uuid4()}",
            )
            parsed = bedrock_service.parse_completion(completion)
        except Exception as exc:
            logger.error(
                f"[views] Bedrock processing failed for message {msg.get('id')}: {exc}",
                exc_info=True
            )
            errors.append("bedrock_processing_failed")
            continue
        
        # Only save to DB if should_create_ticket is true
        should_create_ticket = parsed.get("should_create_ticket", False)
        if not should_create_ticket:
            skipped_no_ticket += 1
            logger.info(
                f"[views] Skipping message {msg.get('id')} - "
                f"should_create_ticket is false"
            )
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
            logger.info(
                f"[views] Saved message {gm.message_id} (DB id: {gm.id}) "
                f"with status {GmailMessage.STATUS_PENDING}"
            )
        except Exception as exc:
            logger.error(
                f"[views] DB save failed for message {msg.get('id')}: {exc}",
                exc_info=True
            )
            errors.append("db_save_failed")
    
    # Update stored history ID after processing
    with transaction.atomic():
        state = GmailState.objects.select_for_update().get(id=Config.GMAIL_STATE_ID)
        if history_id and (not state.last_history_id or int(history_id) > state.last_history_id):
            old_id = state.last_history_id
            state.last_history_id = int(history_id)
            state.save(update_fields=["last_history_id", "updated_at"])
            logger.info(
                f"[views] Updated stored history_id from {old_id} to {history_id} "
                f"after processing"
            )
        else:
            logger.info(
                f"[views] No history_id update needed "
                f"(stored: {state.last_history_id}, webhook: {history_id})"
            )
    
    logger.info(
        f"[views] Webhook processing complete - "
        f"Fetched: {len(fetched_messages)}, Saved: {len(bedrock_saved)}, "
        f"Skipped (no ticket): {skipped_no_ticket}, Errors: {len(errors)}"
    )
    
    if bedrock_saved:
        logger.info(f"[views] Saved entry IDs: {bedrock_saved}")
    if skipped_no_ticket > 0:
        logger.info(f"[views] Skipped {skipped_no_ticket} messages (should_create_ticket=false)")
    if errors:
        logger.warning(f"[views] Errors encountered: {errors}")
    
    return JsonResponse(
        {
            "status": "ok",
            "historyId": history_id,
            "startHistoryId": start_history_id,
            "fetched_messages": len(fetched_messages),
            "saved_entries": bedrock_saved,
            "skipped_no_ticket": skipped_no_ticket,
            "errors": errors,
        }
    )


def hello(_request: HttpRequest) -> HttpResponse:
    """Health check endpoint."""
    return HttpResponse("Hello World from the Django server")


@csrf_exempt
def list_gmail_messages(request: HttpRequest) -> HttpResponse:
    """List Gmail messages with optional status filter."""
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
    """Create a GitLab issue from a Gmail message entry."""
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
    
    gitlab_service = GitLabService()
    
    try:
        issue = gitlab_service.create_issue(
            title=entry.bedrock_json.get("issue_title") or "Untitled issue",
            description=entry.bedrock_json.get("issue_description") or "",
            labels=entry.bedrock_json.get("issue_labels") or [],
            priority=entry.bedrock_json.get("priority"),
        )
        
        entry.status = GmailMessage.STATUS_APPROVED
        entry.save(update_fields=["status", "updated_at"])
        
        logger.info(f"[views] Created GitLab issue {issue.get('iid')} from entry {entry_id}")
        
        return JsonResponse({"issue": issue, "entry_id": entry.id})
    except Exception as exc:
        logger.error(f"[views] Failed to create GitLab issue: {exc}", exc_info=True)
        return JsonResponse({"error": "gitlab_issue_failed"}, status=500)


@csrf_exempt
def decline_entry(request: HttpRequest, entry_id: int) -> HttpResponse:
    """Decline a Gmail message entry."""
    if request.method != "POST":
        return HttpResponseBadRequest("Use POST.")
    
    try:
        entry = GmailMessage.objects.get(id=entry_id)
    except GmailMessage.DoesNotExist:
        return JsonResponse({"error": "not_found"}, status=404)
    
    entry.status = GmailMessage.STATUS_DECLINED
    entry.save(update_fields=["status", "updated_at"])
    
    logger.info(f"[views] Declined entry {entry_id}")
    
    return JsonResponse({"entry_id": entry.id, "status": entry.status})
