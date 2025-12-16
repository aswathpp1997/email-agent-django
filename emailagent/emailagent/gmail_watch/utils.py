"""Utility functions for Gmail Watch application."""
import json
import textwrap
from typing import Any, Dict

# Default prompt template for ticket creation
TICKET_PROMPT_TEMPLATE = textwrap.dedent(
    """
    Read the email subject and body. Determine if it describes a real issue that should become a ticket.
    If yes, extract key details and generate a clear issue title, description, labels, and priority.
    If no, return should_create_ticket=false.

    Do NOT call any tools or functions. Respond only with JSON.

    Guidelines:
    - Create a ticket only if the email reports a bug, incident, access problem, performance issue,.
    - If the email is not actionable (e.g., greetings, thanks, spam), return "should_create_ticket": false.
    - Use short, clear titles.
    - Include important details in the description (error messages, impact, steps, timestamps).
    - Priority: P1 critical outage; P2 major problem; P3 normal bug; P4 low impact.
    - Detected issue types: bug, feature_request, outage, performance, access_issue, other.

    Output ONLY this JSON:
    {{
      "should_create_ticket": true | false,
      "issue_title": "",
      "issue_description": "",
      "issue_labels": [],
      "priority": "",
      "detected_issue_type": ""
    }}

    Email message:
    {email_message}
    """
).strip()


def build_ticket_prompt(email_message: str) -> str:
    """
    Build a prompt for ticket creation from an email message.
    
    Args:
        email_message: The email subject and body
        
    Returns:
        Formatted prompt string
    """
    return TICKET_PROMPT_TEMPLATE.replace("{email_message}", email_message)


def make_json_safe(obj: Any) -> Any:
    """
    Recursively convert bytes into utf-8 strings for JSON serialization.
    
    Args:
        obj: Object to make JSON-safe
        
    Returns:
        JSON-safe object
    """
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode(errors="replace")
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    return obj


def serialize_events(events: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """
    Prepare events for JSON serialization by decoding any bytes recursively.
    
    Args:
        events: List of event dicts
        
    Returns:
        JSON-safe event dicts
    """
    return [make_json_safe(ev) for ev in events]


def format_email_message(subject: str, body_text: str) -> str:
    """
    Format email subject and body into a single message string.
    
    Args:
        subject: Email subject
        body_text: Email body text
        
    Returns:
        Formatted email message
    """
    return f"Subject: {subject}\n\n{body_text}"

