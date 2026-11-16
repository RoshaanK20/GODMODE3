# JARVIS (module inside GODMODE3)

Supervised multi-agent assistant. Lives entirely in `api/jarvis/`; the only change to existing code is one `app.use('/v1/jarvis', …)` line in `api/server.ts`.

**Deliberately NOT used:** `src/lib/libertas.ts`, `parseltongue.ts`, `godmode-prompt.ts`, ULTRAPLINIAN/consortium. JARVIS is an honest assistant, not a jailbreak harness, so none of that is imported.

## Run

```bash
export OPENROUTER_API_KEY=...      # free ":free" models work; or OLLAMA_URL=http://localhost:11434
export GODMODE_API_KEY=...         # strongly recommended; with none set, auth is OFF
export CORS_ORIGIN='*'             # only if the page is served from a different origin
npm run api                        # → http://localhost:7860/v1/jarvis/status
npm run dev                        # second terminal → open http://localhost:3000/jarvis.html (Next serves the page;
                                   # set the page's API URL to http://localhost:7860 and CORS_ORIGIN accordingly)
npm run jarvis:test
```

## Architecture

| Piece | File | What it really does |
|---|---|---|
| ZEUS | `zeus.ts` | plan → delegate → tool loop → verify → reply. Never fabricates success. |
| Agents | `agents.ts` | ATLAS, ORACLE, ENGINEER, LARA, AUTOPILOT: prompt + **tool allowlist**. NOVA (voice/persona) and SENTINEL (verification) are steps inside ZEUS. |
| Tools | `tools.ts` | calculator (no eval), web_search, fetch_url (SSRF-guarded), github_read (owner allowlist), workspace_read/write (sandboxed), memory_*, get_time, n8n_trigger (opt-in). |
| Permissions | `permissions.ts` | green runs; amber needs approval (blocked at autonomy < 2); red never runs. No red tools exist. |
| Memory (LARA) | `memory.ts` | local JSON + BM25. Only explicit "remember …" is stored. Secrets/IDs rejected. List + delete via API. |
| Audit | `audit.ts` | hash-chained JSONL; `GET /v1/jarvis/audit/verify` detects edits/deletions. Keys are redacted. |
| Models | `llm.ts` | OpenRouter free models → Ollama fallback. Fast model by default. |

Autonomy: `JARVIS_AUTONOMY` 0-4 (default 2). Level 3 auto-runs only tools named in `JARVIS_AUTO_APPROVE`.

## API (all under `/v1/jarvis`, behind the existing auth + rate limit)

`GET /status` · `POST /chat {message, session_id?}` · `GET /approvals` · `POST /approvals/:id/approve|deny` · `GET /audit` · `GET /audit/verify` · `GET /memory[?q=]` · `DELETE /memory/:id`

## Verified (automated, `npm run jarvis:test`)

Policy matrix, approval single-use + persistence, audit tamper/deletion detection and key redaction, calculator injection resistance, SSRF (incl. redirect-to-private), path traversal, owner allowlist, memory ranking/dedupe/privacy filter, ZEUS happy path, approval pause/approve/deny, autonomy levels 1 and 3, allowlist refusal, fabricated-link detection, tool failure, step exhaustion, model outage, NOVA failure fallback, bad planner output, invented agents, HTTP validation and CRUD. Safeguard tests were mutation-checked (breaking the approval rule or SSRF guard makes them fail).

## NOT verified — read this before trusting it

- **No real model has been run through it.** Tests use a scripted LLM. Free models may follow the JSON tool protocol poorly; expect to tune `JARVIS_FAST_MODEL`. Default model IDs may be stale — OpenRouter renames them.
- **Live web search is untested.** `web_search` parses DuckDuckGo's HTML (fixture-tested only); DDG may rate-limit or change markup. Swap in a search API if it breaks.
- **`public/jarvis.html` was not opened in a browser.** Voice uses the browser Web Speech API (needs Chrome/Edge/Safari + mic permission; recognition may send audio to the browser vendor's cloud). No whisper.cpp/Piper yet.
- Memory search is keyword-based, not semantic. No pgvector/Qdrant yet.
- Chat history is in-process (lost on restart); audit, memory and approvals persist to `JARVIS_DATA_DIR`.
- SENTINEL catches unsupported links and asks a model to fact-check; it cannot prove truth.
- A prompt-injected web page can still influence an agent's *reasoning*. What it can't do: call tools outside that agent's allowlist, or run amber tools without approval.
- Not implemented: browser/computer control, email/calendar, trading integration (live trading is intentionally absent), the other GitHub repos' skills.

## Licence

GODMODE3 is AGPL-3.0; this module inherits it. Anything you serve over a network from this code must offer its source.
