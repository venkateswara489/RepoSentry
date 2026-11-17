# RepoSentry

A web-based repository review agent for security vulnerabilities, code quality gaps, and unfinished work. Scan public or authorized private GitHub repositories, inspect commit-pinned evidence, and open draft pull requests for selected fixes.

## Quick start: sample mode

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
DEMO_MODE=true python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

On Windows PowerShell use `.venv\Scripts\Activate.ps1`, then `$env:DEMO_MODE="true"` before running `python -m uvicorn app:app --port 8000`.

Open http://localhost:8000, click **Explore the sample scan**, and submit the prefilled repository. Sample mode analyzes a fixed fixture regardless of the input URL; it does not access GitHub or create PRs.

## Enable real GitHub access

Create a GitHub OAuth App under Settings → Developer settings → OAuth Apps. For local development:

- Homepage: `http://localhost:8000`
- Callback: `http://localhost:8000/auth/callback`

Export configuration before starting the app:

```bash
export GITHUB_CLIENT_ID="your-client-id"
export GITHUB_CLIENT_SECRET="your-client-secret"
export BASE_URL="http://localhost:8000"
export DEMO_MODE="false"
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

For PowerShell use `$env:VARIABLE="value"` instead of `export VARIABLE="value"`.

Click **Connect GitHub** and authorize access. The OAuth `repo` scope supports private repository reads and branch/PR writes. GitHub OAuth uses this broad scope; separate read-only authorization is not provided. Organizations may require OAuth approval or SSO authorization.

Tokens are encrypted in SQLite. Sessions expire after eight hours and use HttpOnly, SameSite cookies. Scan ownership uses GitHub user IDs across logins. For production, configure a persistent `ENCRYPTION_KEY`, use HTTPS, set the exact `BASE_URL`, and leave `DEMO_MODE=false`. Generate a key with:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Never commit credentials. Direct Python launches do not automatically read `.env`; export variables into the shell.

## Docker deployment

```bash
cp .env.example .env
# Configure GitHub credentials, BASE_URL, and ENCRYPTION_KEY in .env.
docker compose up --build
```

Compose reads `.env`. Keep `DATA_DIR=/data` for the persistent volume. Deploy the container to a VM/container host behind an HTTPS reverse proxy. The Python backend requires a server runtime; static-only and Cloudflare Worker-only hosting are not supported.

## Agent workflow

**Discover → acquire → plan checks → analyze → normalize → review → propose fixes.**

1. Validate GitHub URL, detect the default branch, and pin a commit SHA.
2. Read a bounded archive from GitHub's fixed archive host in memory; never execute source, builds, or installation scripts.
3. Select generic checks by source files, Python AST checks for Python, and dependency checks by supported manifests.
4. Return file/line evidence, priority, recommendations, and coverage limitations.
5. Filter findings, export JSON, and follow source links to the scanned commit.
6. Select available fixes and inspect the diff. Create a **draft PR** from the scanned commit. Nothing is automatically merged.

This deterministic agent needs no model API key and sends no source code to an LLM.

## Implemented features

| Area | Coverage |
| --- | --- |
| Login | GitHub OAuth with encrypted server-side tokens |
| Repositories | Public and authorized private repositories; accessible-repository suggestions |
| Security | Possible credentials (redacted), eval, selected shell calls, disabled TLS verification, debug mode |
| Dependencies | OSV advisories for exact requirements.txt pins and npm package-lock v2/v3 |
| Quality | Python syntax, functions with more than 10 branching constructs, repeated eight-line blocks |
| Loose ends | TODO/FIXME/HACK, selected unimplemented patterns, empty Python functions, swallowed exceptions |
| Fixes | Enable TLS verification and disable debug mode; review before creating a draft PR |
| Dashboard | Severity/category filters, progress, scan history, source links, JSON export |

## Limits and tradeoffs

- Heuristics can flag examples, comments, tests, or intentional code. Treat findings as review candidates. A clean report does not establish security.
- Automatic fixes are narrow and can change runtime behavior. Review and test resulting PRs. Credential rotation and dependency upgrades require manual action.
- Draft PRs require write access to the repository. Fork-based PR creation is not implemented. Failed GitHub requests can leave a branch; inspect before retrying.
- File executable modes are preserved; automatic fixes to symlinks or truncated Git trees are blocked.
- OSV receives package names/versions, including from private repositories, but no source or GitHub credentials. Dependency lookup is limited to 300 supported pins; truncation/failure is reported. Advisory findings use medium review priority, not an authoritative CVSS severity.
- Two in-process workers, six globally queued/running scans, ten scans/account/hour. Run one Uvicorn process. Jobs are not durable; interrupted scans fail on restart.
- Archive limits: 25 MB compressed, 20,000 entries, 20 MB analyzed text, 2,000 source files, 500 KB/file. Generated/vendor folders are excluded. `.gitignore` is not interpreted.
- Reports persist in SQLite; records older than seven days are removed on the next new scan. Downloaded sources exist only in memory. Protect the data volume and encryption key.
- HTML export, suppression rules, full multi-language parsing, distributed queues, and Semgrep/Gitleaks integrations are future work.
- Source is untrusted and not executed. The container runs as a non-root user, with dropped capabilities. This app is not a sandbox for arbitrary builds.

## API

Interactive documentation: `/api/docs`.

- `GET /auth/github`, `GET /auth/callback`
- `GET /api/me`, `POST /api/logout`
- `GET /api/repos`
- `POST /api/scans` with `{ "repo": "owner/repository" }`
- `GET /api/scans`, `GET /api/scans/{id}`
- `POST /api/scans/{id}/pull-request` with selected finding IDs

Mutations require `X-CSRF-Token` from `/api/me`. Reports are owner-restricted. Browser rendering escapes source content and uses a restrictive content security policy. Repository URLs cannot target arbitrary hosts.

## Verification

```bash
python -m pytest -q
node --check static/app.js
```

Tests cover session authentication, CSRF, account isolation, URL validation, demo scans, redaction, clean-code handling, OAuth state rejection, response security headers, OSV normalization, and draft PR creation through a mocked GitHub transport. No tests perform real GitHub writes. Live OAuth and PR integration require an OAuth App configured by the operator.

## Hackathon demo

1. Start sample mode and scan `sample/storefront`.
2. Inspect security and loose-end findings and filter by severity.
3. Export JSON and reopen the scan from history.
4. Configure OAuth and scan a repository you own.
5. Review an available fix and create a draft PR; run project tests before merging.
