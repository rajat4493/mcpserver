import inspect
import os
import requests
from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("zendesk_slack")

API_KEY = os.getenv("MCP_API_KEY", "")
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


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = "0.0.0.0"
    os.environ["PORT"] = str(port)

    run_params = inspect.signature(mcp.run).parameters
    run_kwargs = {"transport": "sse"}
    if "host" in run_params:
        run_kwargs["host"] = host
    if "port" in run_params:
        run_kwargs["port"] = port
    if "path" in run_params:
        run_kwargs["path"] = "/sse"

    supports_direct = any(param in run_params for param in ("host", "port", "path"))
    if supports_direct:
        mcp.run(**run_kwargs)
    else:
        sse_app = getattr(mcp, "sse_app", None)
        if sse_app is None:
            raise RuntimeError("FastMCP version does not expose `sse_app`; update the package.")
        import uvicorn

        uvicorn.run(sse_app, host=host, port=port)
