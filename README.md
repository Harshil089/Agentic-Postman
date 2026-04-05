# AgentMan

Professionalized Postman-like API IDE with an AI agent backend.

## What is new

- Workspace persistence now saves requests, chat context, diagnostics, errors, history, and UI state to local storage.
- Request history sidebar now shows recent executions with status, latency, preview, diff summary, and replay.
- Environment management now supports per-environment variables and default headers.
- Template resolution now supports both chain placeholders (for example {{json.user.id}}) and environment placeholders (for example {{baseUrl}}).
- Outbound request handling in /api/request is hardened with DNS fail-closed behavior, request timeout, and response size limit.
- Lint, test, and CI workflows are now included for continuous validation.
- Security prompting now includes a curated CWE-first CVE retrieval layer with endpoint fingerprints, weighted matching, response-clue scoring, and UI-visible knowledge matches for auth, authorization, injection, session, upload, SSRF, disclosure, and workflow abuse patterns.
- Security knowledge now separates safe detection probes from mutation-risk probes and includes negative assertion templates per vulnerability family.
- Planning mode for the security agent now enforces semantic output (must return a `scan_plan` first), not just valid JSON shape.

## Version delta (Past vs current)

### Security intelligence and prompting

| Area | Past behavior | Current behavior |
| --- | --- | --- |
| Security knowledge source | Basic generic prompt guidance | Curated CWE-first CVE family dataset (`security-cve-dataset.json`) |
| Matching strategy | Mostly request-shape keyword overlap | Weighted fingerprint scoring + `last_response` clue scoring |
| Probe intent | Mixed, often generic suggestions | Per-family templates: `safe_detection_templates` and `mutation_risk_templates` |
| Assertion guidance | Minimal assertion hints | Per-family `negative_assertion_templates` + stronger assertion semantics |
| Prompt context richness | Limited endpoint context | Includes param descriptors, matched terms, CVE examples, safety profile |

### Security agent mode behavior

| Area | Past behavior | Current behavior |
| --- | --- | --- |
| `planning` mode contract | Could return prose with `actions: []` | Must return `scan_plan` as first action (semantic validation + repair loop) |
| `agent` mode behavior | Could over-plan instead of probing | Prefers executable probes; scan plans are mode-gated |
| Provider output handling | Provider-specific shape failures could break generation | Improved fallback and structured-output repair paths across OpenRouter/Groq/Gemini |
| Diagnostics | Generic diagnostics only | Returns matched CVE knowledge records in diagnostics for transparency |

### UI and operator experience

| Area | Past behavior | Current behavior |
| --- | --- | --- |
| Matched security knowledge display | Chat-only messages | Dedicated panel with explicit sections and show/hide toggle |
| Right panel density | Knowledge blocks could crowd agent messages | Compact/collapsible knowledge panel with constrained height |
| Safety profile label rendering | Long labels could overflow card | Wrapped and width-constrained badge rendering |
| Sidebar readability | Transparency and rail overlap could reduce legibility | Stronger visual separation and rail/background hardening |

## Architecture

- `agentman.html`: UI shell and layout
- `styles.css`: styling
- `app.js`: frontend state + interactions + calls to backend APIs
- `ai-contracts.js`: shared client/server validators and action normalization rules
- `workspace-utils.js`: shared pure utilities for request preview, diffing, and template resolution
- `server.js`: Express server, static hosting, secure multi-provider AI integration
- `security-cve-dataset.json`: curated CWE-first CVE family knowledge with endpoint fingerprints, response clues, templates, and CVE examples
- `security-knowledge.js`: retrieval and weighted scoring layer for endpoint-relevant security knowledge (request shape + response clues)
- `model-capabilities.json`: model reliability and capability registry used by dynamic routing
- `test/server.request.test.js`: backend route behavior tests for /api/request
- `test/workspace-utils.test.js`: utility tests for preview, diffing, and template resolution
- `test/security-knowledge.test.js`: dataset/retrieval scoring and response-clue matching tests
- `test/server.assertions.test.js`: assertions + security payload semantic validation tests
- `.github/workflows/ci.yml`: GitHub Actions workflow for lint + tests

## Why this design

- The master system prompt now lives on the server (not in browser code).
- `OPENROUTER_API_KEY` and `GEMINI_API_KEY` are loaded from environment variables.
- Provider keys (`OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`) are loaded from environment variables.
- Model routing is task-aware (`agent`, `assertions`, `security`) and scored using capability + live runtime reliability.
- Retry policy is adaptive: per-model failure reasons adjust token fallback and candidate ordering automatically.
- Frontend talks only to internal routes:
  - `POST /api/agent`
  - `POST /api/security-agent`
  - `POST /api/assertions`
  - `POST /api/request`
  - `GET /api/config`
  - `GET /api/health`
  - `GET /api/model-reliability`

## Key features

- Request builder with params, headers, body, assertions, and AI-assisted generation.
- Agent mode, planning mode, and ask mode with provider/model switching.
- History tab with replay support and request/response diff summaries.
- Environment tab with:
  - Named environments
  - Variables for {{variable}} interpolation
  - Default headers applied when a request-level header is missing
- Chain template support in URLs using prior response JSON values.
- Security scan orchestration with guarded execution paths for mutating requests.
- CVE-informed security prompting that retrieves endpoint-relevant weakness families, safer test objectives, and matched CVE examples before the model generates probes.
- Per-family security templates:
  - Safe detection probes (`safe_detection_templates`)
  - Mutation-risk probes (`mutation_risk_templates`)
  - Negative assertion templates (`negative_assertion_templates`)
- Dedicated matched security knowledge panel in the right-side assistant with compact/collapsible behavior.
- Planning-mode security contract enforcement to guarantee a concrete scan plan output.

## Setup

1. Install dependencies:

```bash
npm install
```

1. Create `.env` from the example:

```bash
cp .env.example .env
```

1. Set your model provider API keys in `.env`:

```env
OPENROUTER_API_KEY=your_openrouter_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
GROQ_API_KEY=your_groq_api_key_here
OPENROUTER_DEFAULT_MODEL=deepseek/deepseek-v3.2
OPENROUTER_ADVANCED_MODEL=deepseek/deepseek-v3.2
OPENROUTER_SECURITY_MODEL=deepseek/deepseek-v3.2
OUTBOUND_REQUEST_TIMEOUT_MS=15000
OUTBOUND_RESPONSE_MAX_BYTES=2097152
DNS_LOOKUP_TIMEOUT_MS=5000
PORT=3000
```

1. Start the app:

```bash
npm start
```

For local development with auto-reload:

```bash
npm run dev
```

1. Open:

- `http://localhost:3000/agentman.html`

## Quality checks

Run lint:

```bash
npm run lint
```

Run tests:

```bash
npm test
```

Run combined CI checks locally:

```bash
npm run ci
```

## Notes

- The model provider selector in the agent prompt area lets you switch between OpenRouter, Gemini, and Groq for `/api/agent`, `/api/assertions`, and `/api/security-agent`.
- The backend now picks provider-specific model candidates dynamically per task type and de-prioritizes models that fail repeatedly.
- OpenRouter chat-completion calls are sent with `reasoning: { enabled: true }`.
- If `OPENROUTER_API_KEY` is missing, OpenRouter calls will fail.
- If `GEMINI_API_KEY` is missing, Gemini calls will fail.
- If `GROQ_API_KEY` is missing, Groq calls will fail.
- /api/request now:
  - Rejects unsafe or unresolved targets with fail-closed DNS checks.
  - Aborts slow upstream calls after OUTBOUND_REQUEST_TIMEOUT_MS.
  - Rejects oversized responses above OUTBOUND_RESPONSE_MAX_BYTES.
  - Preserves policy and timeout error status codes.
- `/api/model-reliability` returns the loaded model capability registry and in-memory per-model runtime failure/success stats.
- `/api/security-agent` accepts either a top-level security context payload or `{ context: { ... } }` and returns strict JSON for `message`, `threat_level`, `findings`, and `actions`.
- In security `planning` mode, semantic validation requires `scan_plan` as the first action and uses repair retries if missing.
- Security instructions (for example, scan/audit/pentest/IDOR/SQLi/SSRF) are automatically routed to the security agent in the chat panel.
- In Agent mode, non-destructive `GET` probes are auto-executed; mutating probes and probe chains are exposed as action chips for explicit user-triggered execution.
- `scan_plan` actions now include a one-click runner that iterates plan steps and executes generated probes in order.
- Every non-`GET` probe execution path (manual probe, chain step, and scan-plan runner) requires an explicit confirmation prompt before execution.
- `/api/health` should still respond for quick diagnostics.
- GitHub Actions CI runs lint + tests on push and pull request to main.

## Future scope

1. Add confidence-scored evidence extraction so findings cite exact response deltas and confidence values.
2. Introduce family-specific payload packs with environment-aware safety tiers (`safe`, `controlled-mutation`, `high-risk`) and execution guards.
3. Add response-diff-aware adaptive planning so later scan steps are generated from observed behavior drift, not static prompts.
4. Build a first-class security run report view with timeline, probe lineage, finding history, and export (JSON/Markdown/PDF).
5. Expand dataset automation with scheduled CVE/CWE ingestion pipelines, deduplication, and benchmark scoring against known vulnerable test apps.
6. Add policy packs (OWASP API Top 10, ASVS-lite, internal standards) that can auto-generate assertion suites per endpoint.

## Deploy On Vercel

1. Import the repository into Vercel.
1. Framework preset: `Other`.
1. Build command: leave empty.
1. Output directory: leave empty.
1. Install command: `npm install`.
1. Add environment variables in Vercel Project Settings:

```env
OPENROUTER_API_KEY=your_openrouter_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
GROQ_API_KEY=your_groq_api_key_here
OPENROUTER_DEFAULT_MODEL=deepseek/deepseek-v3.2
OPENROUTER_ADVANCED_MODEL=deepseek/deepseek-v3.2
OPENROUTER_SECURITY_MODEL=deepseek/deepseek-v3.2
OUTBOUND_REQUEST_TIMEOUT_MS=15000
OUTBOUND_RESPONSE_MAX_BYTES=2097152
DNS_LOOKUP_TIMEOUT_MS=5000
```

1. Deploy.

`vercel.json` serves the frontend as static files and routes only `/api/*` through the Express serverless entry.
