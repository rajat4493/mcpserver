import inspect
import os
from typing import Any, Dict, List

import requests
from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("zendesk_slack_tools")

API_KEY = os.getenv("MCP_API_KEY", "")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
ZENDESK_SUBDOMAIN = os.getenv("ZENDESK_SUBDOMAIN", "")
ZENDESK_EMAIL = os.getenv("ZENDESK_EMAIL", "")
ZENDESK_API_TOKEN = os.getenv("ZENDESK_API_TOKEN", "")

slack_client = WebClient(token=SLACK_BOT_TOKEN)
ZENDESK_BASE = f"https://{ZENDESK_SUBDOMAIN}.zendesk.com/api/v2"
zendesk_auth = HTTPBasicAuth(f"{ZENDESK_EMAIL}/token", ZENDESK_API_TOKEN)
REQUEST_TIMEOUT = 30


def _require_key(ctx: Context):
    auth = (ctx.request.headers.get("authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        raise PermissionError("Missing MCP key")
    token = auth.split(" ", 1)[1].strip()
    if token != API_KEY:
        raise PermissionError("Invalid MCP key")


@mcp.tool()
def slack_post_message(channel: str, text: str, ctx: Context):
    """
    Post a message to a Slack channel.
    """
    _require_key(ctx)
    slack_client.chat_postMessage(channel=channel.strip(), text=text.strip())
    return {"status": "sent"}


@mcp.tool()
def zendesk_add_internal_note(ticket_id: str, note: str, ctx: Context):
    """
    Append an internal note to a Zendesk ticket.
    """
    _require_key(ctx)
    payload = {
        "ticket": {
            "comment": {
                "body": note,
                "public": False,
            }
        }
    }
    response = requests.put(
        f"{ZENDESK_BASE}/tickets/{ticket_id}.json",
        json=payload,
        auth=zendesk_auth,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return {"status": "ok", "zendesk_status": response.status_code}


@mcp.tool()
def zendesk_list_recent_tickets(limit: int = 10, ctx: Context = None):
    """
    Fetch the most recent Zendesk tickets.
    """
    if ctx is None:
        raise RuntimeError("Context is required")
    _require_key(ctx)

    try:
        limit_value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    limit_value = max(1, min(limit_value, 100))

    params = {
        "sort_by": "created_at",
        "sort_order": "desc",
        "per_page": limit_value,
        "include": "users",
    }
    response = requests.get(
        f"{ZENDESK_BASE}/tickets.json",
        params=params,
        auth=zendesk_auth,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()

    users = {user.get("id"): user for user in data.get("users", [])}
    tickets = data.get("tickets", [])[:limit_value]
    normalized: List[Dict[str, Any]] = []
    for ticket in tickets:
        requester_id = ticket.get("requester_id")
        requester = users.get(requester_id, {})
        requester_name = (
            requester.get("name")
            or requester.get("email")
            or requester_id
        )
        normalized.append(
            {
                "id": ticket.get("id"),
                "subject": ticket.get("subject"),
                "description": ticket.get("description"),
                "requester": requester_name,
                "created_at": ticket.get("created_at"),
                "tags": ticket.get("tags") or [],
            }
        )

    return normalized


def _run_server():
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")
    os.environ["PORT"] = str(port)

    run_signature = inspect.signature(mcp.run)
    kwargs = {"transport": "sse"}
    if "host" in run_signature.parameters:
        kwargs["host"] = host
    if "port" in run_signature.parameters:
        kwargs["port"] = port
    if "path" in run_signature.parameters:
        kwargs["path"] = "/sse"

    mcp.run(**kwargs)


if __name__ == "__main__":
    _run_server()
