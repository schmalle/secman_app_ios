# Agent guardrails

The app is read-only and talks only to SecMan's DMZ relay. Preserve the absence of a direct SecMan connection, local snapshot persistence, and third-party runtime dependencies.

## Branches

- `dev` is the default and only branch for agent-authored commits unless the user explicitly names another branch.
- Verify `git branch --show-current` is `dev` before editing and before committing. Never commit directly to `main` or `master` by inference.

## Skills

- Any contributor or automation skill must be available to both harnesses: `.claude/skills/<name>/` for Claude Code and `.agents/skills/<name>/` for Codex.
- Create, update, or delete both renderings in the same commit. Translate harness-specific mechanics and paths; do not leave one tree stale.

## Verification

- Run `swift test` for relay-kit changes. Run `xcodegen generate` and an Xcode build for app/UI changes when the local toolchain supports them.
- Reconcile relay paths, section names, and snapshot schema versions against the SecMan repository before changing the wire model.
