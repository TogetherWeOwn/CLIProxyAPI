// Package usagefeed implements the dormant, acknowledged usage producer spool.
package usagefeed

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
)

const (
	maxCapacity = 4096
	maxPayload  = 64 << 10
	maxBatch    = 64
)

var (
	ErrFull          = errors.New("usage feed capacity reached")
	ErrPayload       = errors.New("usage feed payload size out of range")
	ErrBatch         = errors.New("usage feed replay limit out of range")
	ErrEpoch         = errors.New("usage feed epoch mismatch")
	ErrAck           = errors.New("usage feed acknowledgment out of range")
	ErrSealed        = errors.New("usage feed sealed")
	ErrCommitUnknown = errors.New("usage feed write commit outcome unknown")
)

// State is a consistent snapshot of the source's progress. Accepted is a terminal
// sequence only once Sealed is true. Sequences start at 1.
type State struct {
	Epoch    uuid.UUID
	Accepted int64
	Acked    int64
	Sealed   bool
}

type Record struct {
	Sequence int64
	Payload  []byte
}

// Feed owns one epoch in the supplied PostgreSQL database. The caller owns db.
type Feed struct {
	db    *sql.DB
	epoch uuid.UUID
}

// Create explicitly provisions a new feed. Existing state is never overwritten.
func Create(ctx context.Context, db *sql.DB, epoch uuid.UUID, capacity int) (*Feed, error) {
	if epoch == uuid.Nil {
		return nil, ErrEpoch
	}
	if capacity < 1 || capacity > maxCapacity {
		return nil, fmt.Errorf("usage feed capacity must be in [1, %d]", maxCapacity)
	}
	feed := &Feed{db: db, epoch: epoch}
	err := feed.write(ctx, func(tx *sql.Tx) error {
		for _, ddl := range schema {
			if _, errExec := tx.ExecContext(ctx, ddl); errExec != nil {
				return fmt.Errorf("create usage feed schema: %w", errExec)
			}
		}
		_, errInsert := tx.ExecContext(ctx,
			`INSERT INTO cli_proxy_usage_feed.progress (epoch, capacity) VALUES ($1, $2)`,
			epoch, capacity)
		return errInsert
	})
	if err != nil {
		return nil, err
	}
	return feed, nil
}

// Open resumes an explicitly identified feed after restart. It cannot create a
// new feed in place of a missing one.
func Open(ctx context.Context, db *sql.DB, epoch uuid.UUID) (*Feed, error) {
	feed := &Feed{db: db, epoch: epoch}
	if _, _, err := feed.progress(db.QueryRowContext(ctx, progressQuery)); err != nil {
		return nil, err
	}
	return feed, nil
}

// Accept durably appends one record, or returns an error without a receipt. Full
// feeds reject new records so the caller can retry after consumer progress.
func (f *Feed) Accept(ctx context.Context, payload []byte) (int64, error) {
	if len(payload) == 0 || len(payload) > maxPayload {
		return 0, ErrPayload
	}
	var sequence int64
	err := f.write(ctx, func(tx *sql.Tx) error {
		state, capacity, errProgress := f.lockProgress(ctx, tx)
		if errProgress != nil {
			return errProgress
		}
		if state.Sealed {
			return ErrSealed
		}
		if state.Accepted == math.MaxInt64 {
			return errors.New("usage feed sequence exhausted")
		}
		if state.Accepted-state.Acked >= int64(capacity) {
			return ErrFull
		}
		sequence = state.Accepted + 1
		if _, errInsert := tx.ExecContext(ctx,
			`INSERT INTO cli_proxy_usage_feed.records (sequence, payload) VALUES ($1, $2)`,
			sequence, payload); errInsert != nil {
			return fmt.Errorf("append usage feed record: %w", errInsert)
		}
		_, errUpdate := tx.ExecContext(ctx,
			`UPDATE cli_proxy_usage_feed.progress SET accepted = $1 WHERE singleton`, sequence)
		return errUpdate
	})
	if err != nil {
		return 0, err
	}
	return sequence, nil
}

// Replay returns up to limit records from the earliest unacknowledged sequence,
// with progress from the same snapshot. Reads never acknowledge records.
func (f *Feed) Replay(ctx context.Context, limit int) (State, []Record, error) {
	if limit < 1 || limit > maxBatch {
		return State{}, nil, ErrBatch
	}
	tx, err := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return State{}, nil, fmt.Errorf("begin usage feed replay: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	state, _, err := f.progress(tx.QueryRowContext(ctx, progressQuery))
	if err != nil {
		return State{}, nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT sequence, payload FROM cli_proxy_usage_feed.records
		WHERE sequence > $1 AND sequence <= $2 ORDER BY sequence LIMIT $3`, state.Acked, state.Accepted, limit)
	if err != nil {
		return State{}, nil, fmt.Errorf("read usage feed records: %w", err)
	}
	defer rows.Close()
	expected := int(min(int64(limit), state.Accepted-state.Acked))
	records := make([]Record, 0, expected)
	for rows.Next() {
		var record Record
		if errScan := rows.Scan(&record.Sequence, &record.Payload); errScan != nil {
			return State{}, nil, fmt.Errorf("decode usage feed record: %w", errScan)
		}
		if record.Sequence != state.Acked+int64(len(records))+1 {
			return State{}, nil, errors.New("gap in usage feed replay")
		}
		records = append(records, record)
	}
	if errRows := rows.Err(); errRows != nil {
		return State{}, nil, fmt.Errorf("replay usage feed records: %w", errRows)
	}
	if len(records) != expected {
		return State{}, nil, errors.New("incomplete usage feed replay")
	}
	return state, records, nil
}

// Ack removes a committed prefix. The trusted consumer calls it only after its
// durable inbox and committed cursor have been committed together.
func (f *Feed) Ack(ctx context.Context, epoch uuid.UUID, through int64) error {
	if epoch != f.epoch {
		return ErrEpoch
	}
	if through < 0 {
		return ErrAck
	}
	return f.write(ctx, func(tx *sql.Tx) error {
		state, _, err := f.lockProgress(ctx, tx)
		if err != nil {
			return err
		}
		if through > state.Accepted {
			return ErrAck
		}
		if through <= state.Acked {
			return nil
		}
		result, err := tx.ExecContext(ctx,
			`DELETE FROM cli_proxy_usage_feed.records WHERE sequence > $1 AND sequence <= $2`,
			state.Acked, through)
		if err != nil {
			return fmt.Errorf("prune usage feed records: %w", err)
		}
		count, err := result.RowsAffected()
		if err != nil || count != through-state.Acked {
			return errors.New("incomplete usage feed acknowledgment")
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE cli_proxy_usage_feed.progress SET acked = $1 WHERE singleton`, through)
		return err
	})
}

// Seal permanently closes acceptance for this epoch and returns its terminal
// sequence. Replay and acknowledgments remain available. Calling Seal again is safe.
func (f *Feed) Seal(ctx context.Context) (State, error) {
	var state State
	err := f.write(ctx, func(tx *sql.Tx) error {
		progress, _, errProgress := f.lockProgress(ctx, tx)
		if errProgress != nil {
			return errProgress
		}
		state = progress
		if state.Sealed {
			return nil
		}
		state.Sealed = true
		_, errUpdate := tx.ExecContext(ctx,
			`UPDATE cli_proxy_usage_feed.progress SET sealed = TRUE WHERE singleton`)
		return errUpdate
	})
	if err != nil {
		return State{}, err
	}
	return state, nil
}

const progressQuery = `SELECT epoch, accepted, acked, sealed, capacity FROM cli_proxy_usage_feed.progress WHERE singleton`

func (f *Feed) lockProgress(ctx context.Context, tx *sql.Tx) (State, int, error) {
	return f.progress(tx.QueryRowContext(ctx, progressQuery+` FOR UPDATE`))
}

func (f *Feed) progress(row *sql.Row) (State, int, error) {
	var state State
	var capacity int
	if err := row.Scan(&state.Epoch, &state.Accepted, &state.Acked, &state.Sealed, &capacity); err != nil {
		return State{}, 0, fmt.Errorf("read usage feed progress: %w", err)
	}
	if state.Epoch != f.epoch || state.Epoch == uuid.Nil {
		return State{}, 0, ErrEpoch
	}
	return state, capacity, nil
}

func (f *Feed) write(ctx context.Context, apply func(*sql.Tx) error) error {
	tx, err := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin usage feed write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var durable bool
	if errQuery := tx.QueryRowContext(ctx, `SELECT current_setting('fsync') = 'on'
		AND current_setting('full_page_writes') = 'on'`).Scan(&durable); errQuery != nil {
		return fmt.Errorf("check usage feed storage durability: %w", errQuery)
	}
	if !durable {
		return errors.New("usage feed requires fsync and full_page_writes")
	}
	if _, errSet := tx.ExecContext(ctx, `SET LOCAL synchronous_commit = on`); errSet != nil {
		return fmt.Errorf("set usage feed synchronous commit: %w", errSet)
	}
	if errApply := apply(tx); errApply != nil {
		return fmt.Errorf("write usage feed: %w", errApply)
	}
	if errCommit := tx.Commit(); errCommit != nil {
		return fmt.Errorf("%w: %w", ErrCommitUnknown, errCommit)
	}
	return nil
}

var schema = []string{
	`CREATE SCHEMA cli_proxy_usage_feed`,
	`CREATE TABLE cli_proxy_usage_feed.progress (
		singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
		epoch uuid NOT NULL,
		capacity integer NOT NULL CHECK (capacity BETWEEN 1 AND 4096),
		accepted bigint NOT NULL DEFAULT 0,
		acked bigint NOT NULL DEFAULT 0 CHECK (acked >= 0 AND acked <= accepted),
		sealed boolean NOT NULL DEFAULT FALSE,
		CHECK (accepted - acked <= capacity)
	)`,
	`CREATE TABLE cli_proxy_usage_feed.records (
		sequence bigint PRIMARY KEY CHECK (sequence > 0),
		payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 65536)
	)`,
}
