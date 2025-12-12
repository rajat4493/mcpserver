from fastapi import FastAPI, Header, HTTPException
from mcp.server.fastapi import MCPServer
from slack_sdk import WebClient
import requests
from requests.auth import HTTPBasicAuth
import os

API_KEY = os.getenv("MCP_API_KEY")

app = FastAPI()
mcp = MCPServer(app)

# --- Clients ---
slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN"))

ZENDESK_BASE = f"https://{os.getenv('ZENDESK_SUBDOMAIN')}.zendesk.com/api/v2"
zendesk_auth = HTTPBasicAuth(
    f"{os.getenv('ZENDESK_EMAIL')}/token",
    os.getenv("ZENDESK_API_TOKEN")
)

def auth(authorization: str | None, x_api_key: str | None):
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif x_api_key:
        token = x_api_key

    if token != API_KEY:
        raise HTTPException(401, "Invalid MCP key")

# --- MCP Tools ---

@mcp.tool()
def zendesk_add_internal_note(
    ticket_id: str,
    note: str,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None)
):
    auth(authorization, x_api_key)
    payload = {
        "ticket": {
            "comment": {
                "body": note,
                "public": False
            }
        }
    }
    requests.put(
        f"{ZENDESK_BASE}/tickets/{ticket_id}.json",
        json=payload,
        auth=zendesk_auth
    )
    return {"status": "ok"}

@mcp.tool()
def slack_post_message(
    channel: str,
    message: str,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None)
):
    auth(authorization, x_api_key)
    slack.chat_postMessage(channel=channel, text=message)
    return {"status": "sent"}
