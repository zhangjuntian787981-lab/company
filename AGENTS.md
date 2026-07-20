# Repository instructions

1. Think before coding. State prerequisites, inputs, outputs, alternatives, and acceptance criteria before changing code. Ask when a material choice is ambiguous.
2. Prefer the smallest implementation that solves the current request. Do not add speculative features or abstractions.
3. Make surgical changes only. Do not reformat, refactor, or optimize unrelated stable code.
4. Deliver against explicit acceptance criteria and run proportionate tests before declaring completion.

Safety boundaries:

- Default validation must remain loopback-only and synthetic-credential-only.
- Never connect to or bind production port `8317` during cloud validation.
- Do not load, print, commit, or upload real OAuth credentials, API keys, local production baselines, caches, run directories, or candidate binaries.
- Real upstream requests, production launchd changes, credential rotation, and production switching require separate explicit approval.
- The release source is the pinned upstream commit plus the ordered patch manifest, not an edited vendor checkout.
