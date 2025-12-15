# Zendesk + Slack MCP Server

Production-focused MCP server exposing Slack and Zendesk tools for AgentKit Cloud.

## Required environment variables

- `MCP_API_KEY` – shared secret for Bearer auth
- `SLACK_BOT_TOKEN` – Slack bot token with `chat:write`
- `ZENDESK_SUBDOMAIN` – e.g., `acme` (without `.zendesk.com`)
- `ZENDESK_EMAIL` – Zendesk agent email
- `ZENDESK_API_TOKEN` – Zendesk API token for the email above

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export MCP_API_KEY=changeme
export SLACK_BOT_TOKEN=xoxb-...
export ZENDESK_SUBDOMAIN=your_subdomain
export ZENDESK_EMAIL=agent@example.com
export ZENDESK_API_TOKEN=token
python server.py
```

Verify the service:

1. `curl http://localhost:8080/health` → `{ "status": "ok" }`
2. `curl -H "Accept: text/event-stream" http://localhost:8080/sse` → FastMCP stream headers

## Railway deployment

1. Push this repo to GitHub.
2. Create a new Railway project from the repo.
3. Set the required environment variables listed above.
4. Deploy – Railway will run `python server.py` via the Procfile.
5. Confirm the service is healthy with `curl https://<railway-domain>/health`.
6. In AgentKit Cloud, configure the MCP endpoint to `https://<railway-domain>/sse` and use `MCP_API_KEY` as the Bearer token.

## Tools

- `slack_post_message(text)` – expects `CHANNEL_ID|message`.
- `zendesk_list_recent_tickets(limit=10)` – returns `[id, subject, description, requester, created_at, tags]`.
- `zendesk_add_internal_note(ticket_id, note)` – adds a private Zendesk comment.
