import os
import requests
from fastapi import FastAPI
from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

try:
    from fastmcp import FastMCP, Context
except ImportError:  # pragma: no cover - fallback when fastmcp not installed
    from mcp.server.fastmcp import FastMCP, Context  # type: ignore

mcp = FastMCP("zendesk_slack", stateless_http=True)
app = FastAPI(redirect_slashes=False)

API_KEY = os.getenv("MCP_API_KEY", "")

# --- Clients ---
slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN", ""))

ZENDESK_BASE = f"https://{os.getenv('ZENDESK_SUBDOMAIN')}.zendesk.com/api/v2"
zendesk_auth = HTTPBasicAuth(
    f"{os.getenv('ZENDESK_EMAIL')}/token",
    os.getenv("ZENDESK_API_TOKEN", "")
)


def require_key(ctx: Context):
    auth = (ctx.request.headers.get("authorization") or "").strip()
    token = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else ""
    if token != API_KEY:
        raise PermissionError("Invalid MCP key")


@mcp.tool()
def slack_post_message(text: str, ctx: Context):
    require_key(ctx)
    channel, message = text.split("|", 1)
    slack.chat_postMessage(channel=channel.strip(), text=message.strip())
    return {"status": "sent"}


@mcp.tool()
def zendesk_add_internal_note(ticket_id: str, note: str, ctx: Context):
    require_key(ctx)
    payload = {"ticket": {"comment": {"body": note, "public": False}}}
    r = requests.put(
        f"{ZENDESK_BASE}/tickets/{ticket_id}.json",
        json=payload,
        auth=zendesk_auth,
        timeout=30,
    )
    return {"status": "ok", "zendesk_status": r.status_code}


mcp.mount(app, path="/mcp/")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=port)
