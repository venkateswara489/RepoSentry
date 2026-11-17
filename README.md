# RepoSentry

A website that reviews **public GitHub repositories without login** for security risks, code quality gaps, dependency advisories, and unfinished work.

Paste a repository URL, scan a pinned commit, inspect file/line evidence, filter findings, and export a JSON report. No GitHub OAuth app, credentials, or model API key is needed.

## Run locally

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://localhost:8000 and paste a public GitHub repository URL.

Windows PowerShell: activate with `.venv\Scripts\Activate.ps1`, then run the same `python -m uvicorn` command.

To try fixed sample data without network access:

```bash
DEMO_MODE=true python -m uvicorn app:app --port 8000
```

On PowerShell, set `$env:DEMO_MODE="true"` first. Sample mode always analyzes a fixed fixture regardless of the URL. No sign-in is required in either mode.

## Deploy on Render

1. Create a Docker web service from this repository using `main` and `./Dockerfile`.
2. Mount a persistent disk at `/data` for scan history.
3. Set `BASE_URL` to your exact HTTPS Render origin, `DATA_DIR=/data`, and `DEMO_MODE=false`.
4. Use `/api/config` as the health check. The Dockerfile listens on port 8000.
5. Run one service instance and one Uvicorn process; background jobs use an in-process pool.

**GitHub OAuth has been removed.** Delete `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `ENCRYPTION_KEY` from Render's environment settings. They are no longer read. Existing authorizations on GitHub must be revoked separately under GitHub Settings → Applications → Authorized OAuth Apps if desired. Removing code does not revoke provider-side grants.

The Google Search Console verification tag is retained. This change does not itself clear Chrome Safe Browsing warnings; Google must assess the review request.

## Docker Compose

```bash
cp .env.example .env
# Set BASE_URL to your deployed origin when using HTTPS.
docker compose up --build
```

The `.env` file is loaded by Compose. Direct Python launches require exported environment variables.

## What changed from the OAuth version

- Public repository scans work without signing in.
- GitHub login, callback, account listing, private repository scans, and PR creation are removed.
- Reports are isolated per browser through an opaque HttpOnly session cookie and CSRF-protected mutations. History is available for seven days in that browser; clearing cookies loses access.
- Existing OAuth sessions and stored encrypted tokens are invalidated on startup. Old private reports are not exposed through the new API. Previously stored records remain in their legacy database table and can be removed by the operator under their retention policy.
- Suggested remediation is informational; the website does not write changes to GitHub.

## Agent workflow

**Discover → acquire → select checks → analyze → normalize → recommend.**

The agent validates a GitHub owner/repository, reads the default branch and commit SHA, then downloads a bounded source archive from GitHub's fixed archive host. It inspects content in memory without extracting, executing, building, or installing repository code. Checks are selected from file types and dependency manifests. Results include evidence, review priority, recommendations, and coverage limits.

| Category | Checks |
| --- | --- |
| Security | Possible hardcoded credentials (redacted), eval, selected shell calls, disabled TLS verification, debug mode |
| Dependencies | OSV advisories for exact requirements.txt pins and npm package-lock v2/v3 |
| Code quality | Python syntax, functions with more than 10 branching constructs, repeated eight-line blocks |
| Loose ends | TODO/FIXME/HACK, unimplemented patterns, empty Python functions, swallowed exceptions |

## Limits

- Findings are review candidates. Generic patterns may flag comments, examples, or intentional behavior. No findings does not establish security.
- No private repository access, OAuth, GitHub tokens, automatic commits, or pull requests are supported.
- Unauthenticated GitHub API requests have a shared rate limit (typically 60 requests/hour per server IP). Each live scan requires repository metadata and commit requests; GitHub may impose additional limits. Rate-limit errors are shown to users.
- Two in-process workers; six globally queued/running jobs; ten scans per browser session per hour. Browser limits are not an account-based abuse control. Public production deployments should add edge rate limiting.
- 25 MB compressed archive; 20,000 ZIP entries; 20 MB analyzed text; 2,000 files; 500 KB/file. Vendor/build directories are excluded. `.gitignore` is not interpreted.
- Dependency lookup is capped at 300 pins. OSV receives package names/versions, not repository source. Missing advisory service coverage is reported. Medium dependency priority is not an authoritative CVSS severity.
- Reports older than seven days are removed when a new scan starts. Source archives exist only in worker memory. Interrupted jobs are marked failed on restart.
- HTML export, suppressions, distributed queues, and full multi-language syntax parsing are not implemented.

## API

Interactive documentation: `/api/docs`.

- `GET /api/config` — public-only and sample-mode settings
- `GET /api/session` — initialize browser cookie and obtain CSRF token automatically
- `POST /api/scans` — `{ "repo": "owner/repository" }`, with `X-CSRF-Token`
- `GET /api/scans` — this browser's history
- `GET /api/scans/{id}` — this browser's report

No account login is required. Anonymous session isolation protects reports from other browsers and is not a GitHub authorization flow.

## Verify

```bash
python -m pytest -q
node --check static/app.js
```

Tests cover browser sessions, CSRF, report isolation, public scans without credentials, private repository rejection, removed OAuth endpoints, URL validation, finding redaction, dependency normalization, and sample scans. External services are mocked in tests.
