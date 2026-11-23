# Isolated gateway staging

Use the **CLIProxy isolated staging** workflow on protected `main` for a
gateway image upgrade, a Meta-only change, or both together. The
`cliproxy-staging` GitHub environment needs a deployment branch policy
restricted to `main` and an environment secret named
`CLIPROXY_STAGING_BUNDLE_URL`. Use a private, read-only HTTPS URL and dispatch
with the ZIP's exact SHA-256. The run records that SHA-256 on success.

Create the ZIP with these file entries and no directory entries.

- `release.json` has two objects, `baseline` and `candidate`. Each has the
  full OCI image ID `image`, the Linux amd64 Docker image config digest
  `docker_config` (both with `sha256:`), the binary checksum `executable`
  (hex only), and the Meta SemVer `meta` (for example `0.2.9`).
- `baseline.oci.tar` is the rollback image. Include
  `candidate.oci.tar` when the candidate has a different image ID.
  Each is an uncompressed OCI tar with Docker's compatibility
  `manifest.json` for the same Linux amd64 image (as emitted by `docker save`).
  The workflow verifies both manifest representations before import.
- `baseline/*.so` and `candidate/*.so` are the complete Linux amd64 plugin
  sets, each with a single `meta-v<version>.so`.

Provide image and plugin files only. The runner creates synthetic config and
auth, gives the gateway a loopback-only network, and stages the candidate
after the incumbent serves a mock Meta stream. The rollback starts a fresh
incumbent process with the baseline image, original config bytes and original
plugin set on the same state mount. Both directions must pass executable
readback, registration, health and a Meta stream with final content and a
terminal event. On a disposable local machine with the exact images already
loaded, pass `--preloaded BUNDLE.zip` to `staging.py` to verify the same archive identities and skip Docker import.

This workflow covers isolated staging. Production requires its own protected
deployment binding, request and writer drain, verified rollback on that
binding, release approval, and at least 30 minutes of post-cutover monitoring.
