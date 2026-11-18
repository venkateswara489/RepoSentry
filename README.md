# RepoSentry

A website that reviews **public GitHub repositories without login** for security risks, code quality gaps, dependency advisories, and unfinished work.

Paste a repository URL, scan a pinned commit, inspect file/line evidence, filter findings, and export a JSON report. No visitor login, GitHub OAuth app, or model API key is needed. An optional server token raises the GitHub API quota.

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
- No private repository access, visitor OAuth, automatic commits, or pull requests are supported. An optional operator token is used only by the server for API reads.
- Without `PUBLIC_GITHUB_TOKEN`, unauthenticated GitHub API requests have a shared rate limit (typically 60 requests/hour per server IP). Each live scan requires repository metadata and commit requests; GitHub may impose additional limits. Rate-limit errors are shown to users.
- Two in-process workers; six globally queued/running jobs; ten scans per browser session per hour. Browser limits are not an account-based abuse control. Public production deployments should add edge rate limiting.
- 25 MB compressed archive; 20,000 ZIP entries; 20 MB analyzed text; 2,000 files; 500 KB/file. Vendor/build directories are excluded. `.gitignore` is not interpreted.
- Dependency lookup is capped at 300 pins. OSV receives package names/versions, not repository source. Missing advisory service coverage is reported. Medium dependency priority is not an authoritative CVSS severity.
- Reports older than seven days are removed when a new scan starts. Source archives exist only in worker memory. Interrupted jobs are marked failed on restart.
- Suppressions, distributed queues, and full multi-language syntax parsing are not implemented.

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

## Avoid shared-IP GitHub API limits on Render

A first scan can fail because unauthenticated GitHub API quota belongs to the server IP, not the visitor. Render outbound IP addresses can be shared. A generic 403 is now distinguished from a confirmed rate limit; when GitHub returns reset headers, the report shows an approximate retry interval.

1. Open GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token.
2. Choose a short expiration and **Public repositories (read-only)**. Do not grant private repository access or write permissions.
3. Copy the token directly into Render → this service → Environment as `PUBLIC_GITHUB_TOKEN`. Do not paste it into chat, source files, or the website.
4. Save and redeploy. Visitors still scan without login.

Authenticated REST requests typically allow 5,000 requests/hour for a personal account, subject to GitHub policies and secondary limits. The quota is still shared across visitors. Invalid credentials and denied requests have separate error messages. The token is not returned by `/api/config` and is sent only to `api.github.com`, never to archive downloads, OSV, or the browser. The worker explicitly rejects repository metadata marked private even if an incorrectly configured token can access it.

## Reviewer-ready reporting (v2)

- **Package-level action areas:** many dependency advisory records become one review card per manifest/package/version. Source findings remain separate.
- **Alias-aware issue groups:** OSV ID/alias overlaps are merged transitively when details are available. Detail requests use eight workers and are capped at 40 records per scan; coverage reports exactly how many were enriched. Unenriched entries are retained.
- **Honest severity:** published database severity is used where present, otherwise Unknown. CVSS vectors are not computed. Package severity is the highest available published label, not an exploitability claim or proof that every advisory was assessed.
- **Readable recommendations:** every card has “What this means” and “What to do next,” expandable advisory evidence, and an explanation of its severity basis. Advisory fixed versions are evidence for the matched package and may belong to different release branches; users must choose a version addressing all applicable issues and test it.
- **Legacy compatibility:** old flat reports are grouped on read and default dependency severity becomes Unknown. No unverified alias deduplication is claimed for old records.
- **Search and exports:** filter by severity/category, search package/file/rule text, download JSON or a script-free standalone HTML report.
- **One-click offline sample:** Try sample scan works in a live deployment without GitHub or OSV requests. Source fixtures cover security, quality, and unfinished work.

See [DEMO.md](DEMO.md) for a three-minute presentation script. The versioned JSON includes `schema_version: 2`, summary counts, raw advisory counts, and grouped findings.

No external model or analytics service is used.

## Optional Groq explanations

Set `GROQ_API_KEY` in Render's Environment settings and redeploy. Do not commit a key. `GROQ_MODEL` optionally overrides the default `llama-3.3-70b-versatile` (model availability depends on your Groq account). No new SDK is needed; the server uses Groq's OpenAI-compatible HTTPS API through httpx.

On a completed report, click **Explain with Groq** on a finding. It returns four beginner-friendly sections: Issue, Why it matters, Suggested fix, and How to verify. AI text is explicitly labeled and escaped as plain text. It cannot change source findings, severity, or code. Exporting JSON/HTML includes explanations generated in the currently open report. Reloading requires clicking again; successful results are served from the server cache when still valid.

Clicking shares a bounded, redacted finding summary and up to five advisory summaries with Groq. No full repository, GitHub token, or Groq key is included in model messages. Credential-like lines are suppressed before transmission, but automated redaction is not a guarantee against all sensitive content. Repository/advisory text is treated as untrusted evidence in the prompt. Do not request explanations for material you cannot share with an external provider.

Responses must match a four-field schema. Missing/invalid credentials, quota limits, network errors, and malformed responses fall back to built-in guidance. There are no automatic retries. Groq errors and credentials are never returned verbatim to the browser. Generated recommendations are unverified and may be inaccurate: consult source evidence and test any changes. Patched versions and exploitability must not be inferred solely from model text.

Successful explanations are cached per browser owner, redacted evidence fingerprint, prompt version, and model for seven days. Limits are 20 uncached requests/browser/hour, 60 globally/hour, and two concurrent requests/process. Public deployments should also enforce edge rate limits; browser-session limits are not identity-based abuse controls. Changing or removing the key disables further generation; deleting provider-side credentials must be done separately in Groq.

API: `POST /api/scans/{scan_id}/findings/{finding_id}/explain`, using the same browser cookie and CSRF header as scans. Ownership and completed-scan checks apply. Scanning itself still works without Groq.

### Troubleshooting explanation display

The homepage and static assets use no-store headers and versioned URLs to avoid stale interfaces. The report has a prominent Explain report with Groq button that processes up to ten unexplained action areas sequentially; it stops on fallback or an API error. Individual buttons remain available. Explanations are requested only when clicked and share redacted finding summaries with Groq. Model rejection, timeout, unavailable service, and invalid response formats have distinct messages. If Groq rejects a model/request, configure `GROQ_MODEL` to an active chat model in your Groq console and redeploy; never share your API key.

## Code review studio / expanded source coverage

The interface now uses a responsive charcoal/lime review workspace, with source-first review order and separate All findings, Source code, Dependencies, Code quality, and Loose ends lenses. Source evidence is not hidden behind dependency counts. The Groq report action also prioritizes source findings. There is no synthetic security score.

New Python AST checks identify returned exception strings, empty error sentinels, bare except handlers, possibly unused imports, mutable collection defaults, HTTP calls without explicit timeouts, unsafe deserializer calls, runtime NLTK/spaCy downloads, interpolated SQL candidates, and functions longer than 60 lines. Import aliases are resolved for these call checks. JavaScript/TypeScript/HTML text checks identify HTML injection sinks, empty catch blocks, and Function constructors. HTML, CSS, Vue, and Svelte files now enter the supported archive scope; these do not receive full syntax or data-flow analysis.

Every new source finding explains the observed construct, why it may matter, and a review step. “Possibly unused,” DOM sink, deserializer, and SQL findings require context: intentional re-exports, side effects, trusted input, or safe data flow may make them acceptable. Error-string returns may be internal functions rather than web responses. These are review candidates, not proven vulnerabilities.

Each new report records language counts, analyzed file paths/line counts, check families, and test-named files observed. Test naming is a heuristic over the bounded analyzed set; absence is not proof that the repository has no tests. Tests are never executed. Old reports without inventory explain that a rescan is necessary. Existing saved reports do not retroactively gain new source checks.

A local static recheck of the two current Python files in the example resume-matcher project produced seven source review candidates (two security, four quality, one loose end) without dependency lookups. Your results can vary with the scanned commit and newly included HTML files. Do not assume new findings until you run a fresh scan.

For local browser preview only, install the Python `.venv`, then use `npm run dev -- --host 127.0.0.1 --port 8000`. Node is optional and no npm packages are required; production still runs through Uvicorn/Docker. The preview command uses sample mode.
