# AgentMan

Professionalized Postman-like API IDE with an AI agent backend.

## Architecture

- `agentman.html`: UI shell and layout
- `styles.css`: styling
- `app.js`: frontend state + interactions + calls to backend APIs
- `server.js`: Express server, static hosting, secure OpenRouter integration

## Why this design

- The master system prompt now lives on the server (not in browser code).
- `OPENROUTER_API_KEY` is loaded from environment variables.
- Frontend talks only to internal routes:
  - `POST /api/agent`
  - `POST /api/security-agent`
  - `POST /api/assertions`
  - `POST /api/request`
  - `GET /api/health`

## Setup

1. Install dependencies:

```bash
npm install
```

1. Create `.env` from the example:

```bash
cp .env.example .env
```

1. Set your OpenRouter API key in `.env`:

```env
OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_SECURITY_MODEL=openai/gpt-4o
PORT=3000
```

1. Start the app:

```bash
npm start
```

1. Open:

- `http://localhost:3000/agentman.html`

## Notes

- If `OPENROUTER_API_KEY` is missing, `/api/agent` and `/api/assertions` will return an error.
- `/api/security-agent` accepts either a top-level security context payload or `{ context: { ... } }` and returns strict JSON for `message`, `threat_level`, `findings`, and `actions`.
- Security instructions (for example, scan/audit/pentest/IDOR/SQLi/SSRF) are automatically routed to the security agent in the chat panel.
- In Agent mode, non-destructive `GET` probes are auto-executed; mutating probes and probe chains are exposed as action chips for explicit user-triggered execution.
- `scan_plan` actions now include a one-click runner that iterates plan steps and executes generated probes in order.
- Every non-`GET` probe execution path (manual probe, chain step, and scan-plan runner) requires an explicit confirmation prompt before execution.
- `/api/health` should still respond for quick diagnostics.
