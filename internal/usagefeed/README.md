# Durable usage feed

The internal Go package `internal/usagefeed` provides an opt-in producer and store
for usage records. Its only entry point is an explicit call from Go. Gateway
startup, configuration, and legacy RESP clients continue on their existing paths.

## Producer and storage

Generate and save a fresh epoch UUID before calling `Create` in a dedicated
PostgreSQL database using the existing pgx driver. Pass that same UUID to
`Open` on restart or to reconcile an ambiguous creation commit. A missing
feed or wrong epoch fails to open. Schema creation is explicit and
transactional. Use a fresh database for a new epoch. Feed writes require
PostgreSQL `fsync` and `full_page_writes` and set `synchronous_commit=on` for each
transaction. The database and its role
must be controlled by the gateway. Keep the same durable database across
restarts. Reusing an epoch after a point-in-time rollback or failover that lost
commits invalidates the sequence contract.

`Accept` takes one prepared usage payload and returns its sequence after commit.
Keep credentials and private request material out of that payload. Sequences
start at 1. The producer configures a capacity of up to 4,096 unacknowledged
records, with at most 64 KiB per record. This caps retained payload bytes as well
as record count. When the spool fills, `Accept` returns `ErrFull` and the caller
can retry after the consumer makes progress. The caller is responsible for
surfacing or handling that backpressure. The asynchronous legacy usage plug-in
interface has no way to return this result upstream.

`ErrCommitUnknown` means a write may have committed without a receipt. On this
result from `Accept`, stop automatic retries and surface the ambiguous event.
The feed identifies committed records by sequence and removes them after
acknowledgment. Retrying the same event safely would require independent
reconciliation in the producer adapter. A committed record remains covered by
the feed's terminal sequence even if the caller did not receive its receipt.
`Ack` and `Seal` can be retried with the same inputs.

`Seal` commits an irreversible end to acceptance for the epoch. An accept racing
with the seal either commits within the terminal sequence or returns
`ErrSealed`. The sealed state and terminal sequence survive restart. They cover
the records accepted into this feed. Gateway request admission and the eventual
producer handoff must establish their own boundary before sealing if they need
to account for every request.

## Keeper contract

- Consume through a trusted adapter. `Replay` provides a consistent snapshot of
  the epoch, highest accepted sequence, highest acknowledged sequence, seal flag,
  and up to 64 records beginning at the first unacknowledged sequence. Replay
  neither releases capacity nor advances the cursor.
- Use the epoch and sequence as the inbox idempotency key. Commit each contiguous
  batch and its highest committed sequence in the same durable inbox
  transaction. When replay overlaps the committed cursor, skip records already
  committed for that epoch. Stop reconciliation on an unexpected epoch or if the
  source has acknowledged past the local committed cursor or reports an
  accepted sequence below it.
- Send `Ack(epoch, committed)` only after the inbox commit succeeds. The gateway
  trusts the consumer to attest to that commit. Acknowledging a duplicate or
  older prefix of the same epoch is harmless. A different epoch, negative
  sequence, or acknowledgment above the accepted watermark is rejected.
- Confirm drain only after observing a sealed epoch and reconciling its terminal
  sequence with the durable inbox cursor and the source acknowledgment. An
  unsealed snapshot records progress only. A zero sequence is a valid terminal
  for an empty sealed epoch.

## Synthetic fixture

With PostgreSQL server binaries and the `sqlite3` CLI installed, run
`USAGE_FEED_REQUIRE_FIXTURE=1 go test -race -count=1 ./internal/usagefeed`.
The fixture starts PostgreSQL in a temporary directory on a private Unix socket
and uses a disposable SQLite inbox. A fixture trigger verifies that feed writes
override the asynchronous database default. It injects a deferred constraint violation at
the last SQLite commit, crashes and restarts the disposable producer database,
and verifies replay, the reopened inbox contents, a lost acknowledgment, and
bounded acceptance.
