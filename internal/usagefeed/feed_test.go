package usagefeed

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestFeedInterruptedFinalCommit(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		requireFixtureTool(t, "sqlite3")
	}
	db, restart := fixturePostgres(t)
	ctx := t.Context()
	epoch := uuid.New()
	feed, err := Create(ctx, db, epoch, 4)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := int64(1); sequence <= 4; sequence++ {
		if got, err := feed.Accept(ctx, []byte(fmt.Sprintf("synthetic-%d", sequence))); got != sequence || err != nil {
			t.Fatalf("accept %d = %d, %v", sequence, got, err)
		}
	}
	terminal, err := feed.Seal(ctx)
	if err != nil || terminal != (State{Epoch: epoch, Accepted: 4, Sealed: true}) {
		t.Fatalf("seal = %+v, %v", terminal, err)
	}

	inbox := filepath.Join(t.TempDir(), "inbox.sqlite")
	runSQLite := func(query string) (string, error) {
		cmd := exec.CommandContext(ctx, sqlite, "-batch", "-bail", "-init", os.DevNull, inbox)
		cmd.Stdin = strings.NewReader("PRAGMA foreign_keys = ON;\n" + query)
		out, errRun := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), errRun
	}
	mustSQLite := func(query string) string {
		t.Helper()
		out, errRun := runSQLite(query)
		if errRun != nil {
			t.Fatalf("synthetic inbox: %v: %s", errRun, out)
		}
		return out
	}
	mustSQLite(`
		CREATE TABLE inbox(epoch TEXT, sequence INTEGER, payload BLOB, PRIMARY KEY(epoch, sequence));
		CREATE TABLE cursor(epoch TEXT PRIMARY KEY, committed INTEGER NOT NULL);
		CREATE TABLE parent(id INTEGER PRIMARY KEY);
		CREATE TABLE violation(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_final AFTER INSERT ON inbox WHEN NEW.sequence = 4
		BEGIN INSERT INTO violation VALUES (4); END;
	`)
	// Each transaction uses a new SQLite process. Only an observed successful
	// COMMIT permits acknowledgment.
	commit := func(records []Record) (string, error) {
		var statements strings.Builder
		statements.WriteString("BEGIN;\n")
		for _, record := range records {
			fmt.Fprintf(&statements, "INSERT INTO inbox VALUES ('%s', %d, X'%x') ON CONFLICT(epoch, sequence) DO NOTHING;\n",
				epoch, record.Sequence, record.Payload)
		}
		fmt.Fprintf(&statements, "INSERT INTO cursor VALUES ('%s', %d) ON CONFLICT(epoch) DO UPDATE SET committed = MAX(cursor.committed, excluded.committed);\nCOMMIT;\n",
			epoch, records[len(records)-1].Sequence)
		return runSQLite(statements.String())
	}
	checkBatch := func(f *Feed, expected State, start int64) []Record {
		t.Helper()
		state, records, errReplay := f.Replay(ctx, 2)
		if state != expected || len(records) != 2 || errReplay != nil {
			t.Fatalf("replay = %+v, %v, %v", state, records, errReplay)
		}
		for i, record := range records {
			sequence := start + int64(i)
			if record.Sequence != sequence || string(record.Payload) != fmt.Sprintf("synthetic-%d", sequence) {
				t.Fatalf("unexpected replay record %+v", record)
			}
		}
		return records
	}
	first := checkBatch(feed, terminal, 1)
	if out, errCommit := commit(first); errCommit != nil {
		t.Fatalf("first inbox commit: %v: %s", errCommit, out)
	}
	if err = feed.Ack(ctx, epoch, 2); err != nil {
		t.Fatal(err)
	}
	pending := terminal
	pending.Acked = 2
	final := checkBatch(feed, pending, 3)
	if out, errCommit := commit(final); errCommit == nil || !strings.Contains(out, "FOREIGN KEY constraint failed") {
		t.Fatalf("final inbox commit should fail with the injected constraint: %v: %s", errCommit, out)
	}
	if got := mustSQLite("SELECT count(*) FROM inbox; SELECT committed FROM cursor;"); got != "2\n2" {
		t.Fatalf("failed commit left partial consumer state: %q", got)
	}

	// Crash the fixture database, run WAL recovery, and reopen the producer
	// with a new connection pool pinned to the same epoch.
	db = restart()
	feed, err = Open(ctx, db, epoch)
	if err != nil {
		t.Fatal(err)
	}
	checkBatch(feed, pending, 3)
	if state, errSeal := feed.Seal(ctx); errSeal != nil || state != pending {
		t.Fatalf("sealed boundary after restart = %+v, %v", state, errSeal)
	}

	mustSQLite("DROP TRIGGER fail_final;")
	if out, errCommit := commit(checkBatch(feed, pending, 3)); errCommit != nil {
		t.Fatalf("replayed inbox commit: %v: %s", errCommit, out)
	}
	// Simulate loss of the acknowledgment after a successful inbox commit.
	if out, errCommit := commit(checkBatch(feed, pending, 3)); errCommit != nil {
		t.Fatalf("duplicate delivery after successful commit: %v: %s", errCommit, out)
	}
	if got := mustSQLite("SELECT committed FROM cursor; SELECT sequence || ':' || CAST(payload AS TEXT) FROM inbox ORDER BY sequence;"); got != "4\n1:synthetic-1\n2:synthetic-2\n3:synthetic-3\n4:synthetic-4" {
		t.Fatalf("reopened consumer database has unexpected contents: %q", got)
	}
	for _, ack := range []int64{4, 4, 2, 0} {
		if errAck := feed.Ack(ctx, epoch, ack); errAck != nil {
			t.Fatalf("ack %d: %v", ack, errAck)
		}
	}
	state, records, err := feed.Replay(ctx, 2)
	if err != nil || !state.Sealed || state.Epoch != epoch || state.Accepted != 4 || state.Acked != 4 || len(records) != 0 {
		t.Fatalf("final replay = %+v, %v, %v", state, records, err)
	}
	var retained int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM cli_proxy_usage_feed.records`).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("retained rows after acknowledgment = %d, %v", retained, err)
	}
}

func TestFeedBounds(t *testing.T) {
	db, _ := fixturePostgres(t)
	ctx := t.Context()
	if _, err := Open(ctx, db, uuid.New()); err == nil {
		t.Fatal("open provisioned a missing feed")
	}
	epoch := uuid.New()
	if _, err := Create(ctx, db, uuid.Nil, 1); !errors.Is(err, ErrEpoch) {
		t.Fatalf("create with a missing epoch = %v", err)
	}
	for _, capacity := range []int{0, maxCapacity + 1} {
		if _, err := Create(ctx, db, epoch, capacity); err == nil {
			t.Fatalf("created feed with capacity %d", capacity)
		}
	}
	feed, err := Create(ctx, db, epoch, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Create(ctx, db, uuid.New(), 1); err == nil {
		t.Fatal("replaced existing feed")
	}
	if _, err = Open(ctx, db, uuid.New()); !errors.Is(err, ErrEpoch) {
		t.Fatalf("open on stale epoch = %v", err)
	}
	other, err := Open(ctx, db, epoch)
	if err != nil {
		t.Fatal(err)
	}

	for _, payload := range [][]byte{nil, make([]byte, maxPayload+1)} {
		if _, err = feed.Accept(ctx, payload); !errors.Is(err, ErrPayload) {
			t.Fatalf("accept oversized or empty payload = %v", err)
		}
	}
	if first, errAccept := feed.Accept(ctx, make([]byte, maxPayload)); first != 1 || errAccept != nil {
		t.Fatalf("accept max-size payload = %d, %v", first, errAccept)
	}
	if _, err = other.Accept(ctx, []byte("retry")); !errors.Is(err, ErrFull) {
		t.Fatalf("accept on full feed = %v", err)
	}
	if err = feed.Ack(ctx, uuid.New(), 1); !errors.Is(err, ErrEpoch) {
		t.Fatalf("stale epoch ack = %v", err)
	}
	for _, through := range []int64{-1, 2} {
		if err = feed.Ack(ctx, epoch, through); !errors.Is(err, ErrAck) {
			t.Fatalf("invalid ack %d = %v", through, err)
		}
	}
	for _, limit := range []int{0, maxBatch + 1} {
		if _, _, err = feed.Replay(ctx, limit); !errors.Is(err, ErrBatch) {
			t.Fatalf("invalid limit %d = %v", limit, err)
		}
	}
	state, records, err := feed.Replay(ctx, maxBatch)
	if err != nil || state != (State{Epoch: epoch, Accepted: 1}) || len(records) != 1 ||
		records[0].Sequence != 1 || len(records[0].Payload) != maxPayload {
		t.Fatalf("replay after rejected append and acks = %+v, %d records, %v", state, len(records), err)
	}
	if err = feed.Ack(ctx, epoch, 1); err != nil {
		t.Fatal(err)
	}

	if sequence, errAccept := other.Accept(ctx, []byte("retry")); sequence != 2 || errAccept != nil {
		t.Fatalf("retry after ack = %d, %v", sequence, errAccept)
	}
	if err = feed.Ack(ctx, epoch, 2); err != nil {
		t.Fatal(err)
	}

	// Separate handles compete to append and seal after capacity reopens.
	var wg sync.WaitGroup
	var sequence int64
	var terminal State
	var acceptErr, sealErr error
	start := make(chan struct{})
	wg.Go(func() {
		<-start
		sequence, acceptErr = other.Accept(ctx, []byte("racing append"))
	})
	wg.Go(func() {
		<-start
		terminal, sealErr = feed.Seal(ctx)
	})
	close(start)
	wg.Wait()
	if sealErr != nil || !terminal.Sealed || terminal.Acked != 2 || terminal.Epoch != epoch {
		t.Fatalf("seal under concurrent append = %+v, %v", terminal, sealErr)
	}
	switch {
	case acceptErr == nil:
		if sequence != 3 || terminal.Accepted != 3 {
			t.Fatalf("terminal omitted successful append %d: %+v", sequence, terminal)
		}
	case errors.Is(acceptErr, ErrSealed):
		if sequence != 0 || terminal.Accepted != 2 {
			t.Fatalf("failed append advanced the terminal: %d, %+v", sequence, terminal)
		}
	default:
		t.Fatalf("concurrent append = %v", acceptErr)
	}
	if _, err = feed.Accept(ctx, []byte("too late")); !errors.Is(err, ErrSealed) {
		t.Fatalf("append after terminal boundary = %v", err)
	}
}

func requireFixtureTool(t *testing.T, name string) {
	t.Helper()
	if os.Getenv("USAGE_FEED_REQUIRE_FIXTURE") == "1" {
		t.Fatalf("%s is required for the usage feed fixture", name)
	}
	t.Skipf("%s is required for the usage feed fixture", name)
}

func fixturePostgres(t *testing.T) (*sql.DB, func() *sql.DB) {
	t.Helper()
	initdb, err := exec.LookPath("initdb")
	if err != nil {
		if out, errConfig := exec.Command("pg_config", "--bindir").Output(); errConfig == nil {
			initdb, err = exec.LookPath(filepath.Join(strings.TrimSpace(string(out)), "initdb"))
		}
	}
	if err != nil {
		requireFixtureTool(t, "PostgreSQL server binaries")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	pgctl := filepath.Join(filepath.Dir(initdb), "pg_ctl")
	run := func(program string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Dir = root
		if out, errRun := cmd.CombinedOutput(); errRun != nil {
			t.Fatalf("%s: %v: %s", filepath.Base(program), errRun, out)
		}
	}
	run(initdb, "-D", data, "-A", "trust", "-U", "usage_fixture", "--no-locale", "--no-instructions")
	start := func() {
		run(pgctl, "-D", data, "-l", filepath.Join(root, "postgres.log"), "-w", "-t", "15",
			"-o", "-c listen_addresses= -c unix_socket_directories=. -c unix_socket_permissions=0700", "start")
	}
	t.Cleanup(func() {
		run(pgctl, "-D", data, "-m", "immediate", "-w", "-t", "15", "stop")
	})
	start()
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGPASSWORD", "")
	connect := func() *sql.DB {
		t.Helper()
		params := url.Values{
			"host":     {data},
			"port":     {"5432"},
			"sslmode":  {"disable"},
			"passfile": {os.DevNull},
		}
		cfg, errParse := pgx.ParseConfig("postgresql://usage_fixture@/postgres?" + params.Encode())
		if errParse != nil {
			t.Fatal(errParse)
		}
		db := stdlib.OpenDB(*cfg)
		t.Cleanup(func() {
			if errClose := db.Close(); errClose != nil {
				t.Errorf("close fixture database: %v", errClose)
			}
		})
		if errPing := db.PingContext(t.Context()); errPing != nil {
			t.Fatal(errPing)
		}
		return db
	}
	db := connect()
	return db, func() *sql.DB {
		if errClose := db.Close(); errClose != nil {
			t.Fatal(errClose)
		}
		run(pgctl, "-D", data, "-m", "immediate", "-w", "-t", "15", "stop")
		start()
		db = connect()
		return db
	}
}
