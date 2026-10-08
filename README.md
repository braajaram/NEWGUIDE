# CyberGuard AI

CyberGuard AI is a production-oriented security analysis platform for URLs, files, and email messages. The repository contains a FastAPI service and a Next.js/React client. Analysis is evidence-based: unavailable integrations are reported as `Data unavailable` and no synthetic scores or threat findings are generated.

## Run locally

1. Copy `.env.example` to `.env` and change `SECRET_KEY`.
2. Start with `docker compose up --build`.
3. Open [http://localhost:3000](http://localhost:3000). API docs are at [http://localhost:8000/docs](http://localhost:8000/docs).

The API creates the schema on startup for a first local run. PostgreSQL and Redis are included in Compose. External reputation and AI providers are optional; configure their keys in `.env` when available.

The first implementation keeps the local URL/file/email analyzers synchronous because their safe checks are bounded. Redis is provisioned for the background-job boundary; a production deployment should move provider calls and heavier sandbox work to a worker queue.

For a backend-only run, install `backend/requirements.txt`, set `DATABASE_URL` and `REDIS_URL`, then run `uvicorn app.main:app --reload --app-dir backend`.

## Security notes

- URL fetching blocks loopback, link-local, private, reserved, multicast, and cloud metadata destinations, resolves DNS immediately before connecting, limits redirects, and only performs a GET after validation.
- Uploaded files are stored under an isolated temporary directory with randomized names and are never executed. Hashes and safe metadata are collected; optional reputation providers are explicit.
- Auth uses PBKDF2 password hashing, signed HttpOnly session cookies, CSRF checks for browser writes, rate limiting, and role checks.
- The built-in Copilot only receives persisted scan evidence and responds with an unavailable message when no scan context exists.

## Tests

Run `pytest -q backend/tests`. The tests cover SSRF rejection, hashing, email parsing, and the API health endpoint.

The current client exposes dashboard, URL, file, email, history detail, and JSON report flows. Account verification/reset delivery, TOTP enrollment, GitHub OAuth, and provider calls are intentionally configuration-bound follow-ons; the API reports unavailable integrations rather than fabricating them.
