# Three-minute reviewer walkthrough

## Problem (30 seconds)

Repository review tools can flood users with advisory rows. RepoSentry turns source risks, dependency issues, and unfinished work into understandable action areas. It works with public repositories across application architectures and never executes project code.

## Demonstrate (90 seconds)

1. Click **Try sample scan**. This works without GitHub access, a token, or live advisory services.
2. Watch the queued → reading snapshot → analysis stages.
3. Inspect security, code quality, and loose-end findings. Each explains what matched and what to do next.
4. Search for `debug` and inspect the suggested change. Explain that suggestions are not automatically applied or tested.
5. Export the standalone HTML report and JSON evidence.
6. Scan a small public repository. For dependencies, expand a package to see published summaries, related IDs, available fixed releases, and evidence links.

## Explain the differentiator (30 seconds)

A real saved report with 174 entries becomes seven action areas: one source setting and six dependency groups. Source records stay visible. Known advisory aliases are combined when details are available; unknown severity stays unknown rather than being mislabeled medium.

## Architecture (30 seconds)

Browser → FastAPI → bounded background worker → pinned GitHub snapshot → language/file-based static checks + OSV → versioned explanatory report → browser/HTML/JSON.

Core scanning has no LLM dependency. Optional Groq explanations turn a finding into issue, impact, fix, and verification guidance; click Explain with Groq to demonstrate when configured. No repository execution, GitHub visitor login, or write permissions. A deployment-only public-read token is optional for API quota. Reports are isolated by browser session.

## Be candid

This is a static review assistant, not a security certification. Dependency enrichment is capped at 40 records, so alias/severity coverage can be partial. GitHub and OSV availability affect live scans. Jobs run in-process; horizontal scaling needs a durable queue. Legacy reports cannot retrospectively establish advisory aliases or severity. No automatic PRs or private scans are included in this public-only edition.

## Studio edition: show the breadth

Start with the sample review and switch between Source code, Code quality, Loose ends, and Dependencies. Explain that source findings are sorted before package advisories in the review queue. Open What we looked at to show language coverage, analyzed files, and test-file signals. Explain why a missing test signal is not proof of missing tests.

A fresh scan is required to gain the new source checks. For the resume-matcher example, point to returned exception text, runtime NLP downloads, and possibly unused imports alongside the existing debug flag. Do not describe dependency advisories as the only check family. Call out false-positive possibilities and static-analysis limits before demonstrating Groq as an explanation layer.
