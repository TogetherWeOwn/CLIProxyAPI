# Fork residuals

Patches we carry on the `tog` release line that upstream has not merged.
Each entry names the **reason** we carry it and the **exit** that removes it.
Drop a residual as soon as its exit condition holds; never let this list grow
without bound.

## Residuals

### meta-passive-subscription-quota (carried since `tog/v8.0.51-tog.1`)

Meta sends per-account quota on every streamed Responses response as
`response.subscription_usage` (a `subscription` object with `window` and
`weekly` usage plus `resets_at` times). The executors recognise that event and
drop it, so Meta accounts stay quota-blind in the `auth-files` listing while
claude/codex/devin show passive quota snapshots.

This residual records the event passively, record-only:

- `internal/runtime/executor/helps/meta_quota.go` parses the event into bounded
  `X-Meta-*` signal headers (percentages pass through verbatim, reset times
  stay unix seconds, unsafe tier values are dropped).
- `internal/runtime/executor/meta_executor_execute.go` (non-stream) and
  `internal/runtime/executor/meta_executor_stream.go` (stream) observe the event
  on the request context; the event itself stays filtered so it never reaches
  the client.
- `sdk/cliproxy/auth/quota_signals.go` adds `meta` to
  `ProviderSupportsQuotaObservation` and gates the six `X-Meta-*` signals to
  the meta provider, so the credential's `quota` shows up in `auth-files`.
- `sdk/cliproxy/auth/conductor_lifecycle.go` keeps the newest observation
  snapshot across credential reloads, which otherwise carry no observation.

What this residual deliberately does **not** do (upstream PR scope we skipped):

- It does not forward `response.subscription_usage` to the client. The stream
  framer and websocket forward paths keep dropping it, so account-specific
  usage never leaks downstream.
- It makes no call to `muse-code/key`, mints no keys, and changes no
  `$TOKEN$`/`$DCA_TOKEN$` resolution. No auth-file download is involved.

**Reason:** upstream issue router-for-me/CLIProxyAPI#7018 asked for exactly
this as a built-in and was closed `not_planned` ("quota storage ... outside
the core responsibilities"); upstream PR router-for-me/CLIProxyAPI#6467
implements it and is still open (dirty). Carrying the record-only slice gives
the connector passive per-account Meta quota with no key-mint endpoint risk.

**Exit:** drop this residual when #6467 or an equivalent merges upstream; keep
only whatever adaptation the merge needs.

**Trade-off:** quota is only as fresh as each account's last request; idle
accounts show stale data.

**Verify:** after one request on a Meta account, its `auth-files` row shows
`quota` with the window and weekly `used_percent`/`resets_at`.
