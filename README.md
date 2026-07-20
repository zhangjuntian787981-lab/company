# CLIProxyAPI v7.2.80 Claude Code compatibility

This repository builds and validates a patched CLIProxyAPI v7.2.80 candidate for
Claude Code. The certified path is:

```text
Claude Code 2.1.215
  -> invocation-scoped loopback gateway and safe wrapper
  -> CLIProxyAPI v7.2.80 candidate
  -> Codex Responses
```

The default source, bottle, OAuth-synthetic, Claude Code, and soak workflows are
zero-cost and loopback-only. They do not connect to production port 8317, load real
OAuth credentials, install a wrapper, modify shell startup, or operate a production
launchd service.

## Cloud operation

The repository is designed for two complementary cloud paths:

- Codex Cloud checks out the repository for interactive development. Set its setup
  script to `./scripts/setup-cloud.sh`; the script installs the pinned Go and Claude
  Code versions, reconstructs the ignored upstream checkout, and downloads public Go
  modules during the setup phase.
- GitHub Actions runs durable validation. `Cloud validation` runs on every push to
  `main`; `Formal cloud soak` is manually dispatched and includes the complete
  validation chain plus the 7200-second soak and final report.

Both paths reconstruct `vendor/CLIProxyAPI-v7.2.80` from the manifest. Local caches,
run evidence, production metadata, and binaries are intentionally excluded from Git.
Cloud workflows use `baseline/cloud.lock.json`, which requires port 8317 and all listed
production files to remain absent before and after every test.

## Source and artifact identity

- `vendor/CLIProxyAPI-v7.2.80` is the clean pinned upstream checkout.
- `patches/v7.2.80/manifest.json` defines the source commit, ordered patches, exact
  repository, patch digests, touched paths, and contract mappings.
- `patches/v7.2.80/contracts.json` classifies supported, translated, and explicitly
  rejected behavior. Silent field dropping blocks PASS.
- `scripts/build_reproducible_candidate.py` creates two detached worktrees, applies
  the manifest offline, builds twice with deterministic flags, compares both binary
  hashes, and only then publishes the candidate artifacts.
- Every trusted bottle, OAuth, Claude Code, build, and soak report binds itself to the
  source commit, patch-set digest, and applicable binary digests.

The repair checkout is an implementation workspace, not a release source. Candidate
artifacts are always reconstructed from the pinned commit and manifest.

## Safety boundaries

- Test services bind to `127.0.0.1` on OS-selected dynamic ports; port 8317 is denied.
- Runs use private temporary HOME/XDG/TMP directories and `umask 077`.
- Test processes have closed proxy defaults and receive only synthetic credentials.
- Subprocess groups are terminated on bounded deadlines and checked for cleanup.
- Local production checks compare listener/process metadata and file hashes without
  reading credential values. Cloud checks require the production listener and files
  to be absent.
- Reports persist sanitized status, counts, hashes, and shapes. Redaction canaries fail
  report generation if a secret-like value or raw body appears.

There is no per-process OS firewall. Isolation therefore also relies on generated
loopback-only configuration and closed proxy variables.

## Validation sequence

```sh
make cloud-setup
make test
make check-prod
make repair-source-check
make source-validation
make build-candidate
make candidate-bottle-check
make synthetic-oauth-check
make gateway-e2e
make soak-local
make final-report
```

What each gate proves:

- `repair-source-check`: tests the clean baseline, validates every manifest digest,
  path, and contract mapping, applies all patches in order, runs supplemental tests,
  and removes the temporary worktree.
- `source-validation`: runs Python tests and redaction canaries, checks gofmt, runs the
  selected translator/gateway/auth race matrix, runs `go test ./...`, performs a test
  server build, and removes the build output and worktree.
- `build-candidate`: performs the two independent reproducible builds described above.
- `candidate-bottle-check`: exercises JSON/SSE, field policy, catalogs and alias
  round-trips, token counting, parallel tools, errors, retry limits, cleanup, and the
  production guard against the candidate binary.
- `synthetic-oauth-check`: verifies concurrent stale-token singleflight, bounded
  invalid_grant/500/429/timeout behavior, atomic 0600 persistence, failure rollback,
  redaction, and production isolation without using a real credential.
- `gateway-e2e` (aliases: `claude-code-e2e`, `context-e2e`): runs the installed Claude
  Code through the safe wrapper and invocation gateway, covering JSON, stream-json,
  model routing, retry suppression, MCP, subagent routing, launcher parity, signal
  propagation, and the locally achievable compact matrix.
- `soak-local`: runs the formal 7200-second loopback soak across concurrency 1, 4, and
  16. A shorter developer smoke is intentionally reported as FAIL and cannot satisfy
  final policy.
- `final-report`: computes the six-dimension verdict from fresh, identity-matched
  evidence and links the preserved historical FAIL baseline.

`make self-check` remains a fixture and installed-bottle developer check. It is not a
substitute for the candidate sequence above.

## Separate approval gates

The following are not performed by the default sequence:

- `make launchd-isolated-check` deliberately refuses to create a temporary launchd
  label until separate approval is given.
- `make real-upstream` requires separate approval for exact call count, token ceiling,
  cost, and deadline before any real request.
- Natural or real-credential OAuth expiry/concurrency testing requires separate
  approval.
- Installing a wrapper or symlink, changing PATH or shell startup, touching production
  `127.0.0.1:8317`, changing production launchd, rotating credentials, deleting logs,
  or switching production requires separate approval.

No validation command commits or pushes changes.

The real local production baseline and installed-bottle metadata are machine-specific
and ignored by Git. A clean cloud checkout must select `baseline/cloud.lock.json`
through `COMPAT_PROD_BASELINE`, as the included workflows do.
