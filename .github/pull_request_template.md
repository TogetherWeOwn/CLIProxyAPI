<!--
Title: Conventional Commits header, e.g. `fix(auth): refuse expired sudo sessions`.
Types: feat fix perf refactor test docs build ci chore revert style security. Max 100 chars, no trailing period.
This repo is public. Do not put internal ticket ids, instance links, localhost or private-network
addresses in the title, the body, a commit message or the branch name. Name the branch after the change,
for example `docs/pr-template`. Link only public GitHub issues (`Fixes #123`).
Write short, plain sentences. Fill in every section.
Full contributor rules: AGENTS.md.
-->

## Thinking Path

<!--
  Required. Trace your reasoning from the project down to this change, as a blockquote.
  Start with what this repo is, narrow through the subsystem and the problem, and end with
  why this PR exists. Aim for 5-8 steps; keep at least 3 real ones.
-->

> - CLIProxyAPI is a Go proxy server providing OpenAI/Gemini/Claude/Codex compatible APIs
> - [Which subsystem or capability is involved]
> - [What problem or gap exists]
> - [Why it needs to be addressed]
> - This pull request ...
> - The benefit is ...

## Linked Issues or Issue Description

<!--
  Required for feat, fix, perf, refactor and security. Pick ONE:
  (A) A public GitHub issue exists: `Fixes #123`, `Closes #123` or `Refs #123`.
  (B) No issue exists: describe the problem here in your own words (what happened, what you expected,
      how to reproduce it, or the motivation and proposed solution for a feature).
-->

-

## What Changed

<!-- One bullet per logical unit. -->

-

## Verification

<!-- Commands you ran and their results, so a reviewer can repeat them (e.g. `go build ./...`, `go test ./...`). -->

-

## Risks

<!-- Migration safety, breaking changes, behaviour shifts. "Low risk" if genuinely minor. -->

-

## Model Used

<!--
  Required. Provider, exact model ID or version, context window, reasoning mode and tool use if known.
  If no AI model was used, write "None - human-authored".
-->

-

## Checklist

- [ ] I wrote a thinking path that runs from the project to this change
- [ ] I named the model used, with its version
- [ ] I searched for duplicate or related PRs and linked them above
- [ ] I ran the build and tests locally and they pass (`go build ./...`, `go test ./...`)
- [ ] I added or updated tests where applicable
- [ ] I updated the documentation this change touches
- [ ] No secret, token or credential is in the diff, the title, the body or the branch name
- [ ] No internal ticket id, instance link or private host is in the title, body, commits or branch name
- [ ] CI is green on the exact head before I ask for review
