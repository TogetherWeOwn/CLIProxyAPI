package executor

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

func metaPCKConfig() *config.Config {
	return &config.Config{Meta: config.MetaConfig{
		ReasoningReplay: config.MetaReasoningReplayConfig{Enabled: true},
	}}
}

func metaPCKSessionContext(session string) context.Context {
	return util.WithSessionID(context.Background(), session)
}

func metaPCKOptions(session string) cliproxyexecutor.Options {
	opts := museReplayClaudeOptions()
	if session != "" {
		opts.Headers = http.Header{"X-Claude-Code-Session-Id": []string{session}}
	}
	return opts
}

func metaPCKExecute(t *testing.T, exec *MetaExecutor, auth *cliproxyauth.Auth, session string) error {
	t.Helper()
	_, err := exec.Execute(context.Background(), auth,
		cliproxyexecutor.Request{Model: museReplayModel, Payload: newMuseReplayConversation(t).payload()},
		metaPCKOptions(session))
	return err
}

func metaPCKUpstreamKey(t *testing.T, upstream *museReplayUpstream, callIndex int) string {
	t.Helper()
	calls := upstream.recorded()
	if callIndex >= len(calls) {
		t.Fatalf("upstream saw %d requests, want at least %d", len(calls), callIndex+1)
	}
	return strings.TrimSpace(gjson.GetBytes(calls[callIndex].body, "prompt_cache_key").String())
}

func TestMetaPromptCacheKey_Derivation(t *testing.T) {
	a := metaPromptCacheKeyForSession("sess-1")
	b := metaPromptCacheKeyForSession("sess-1")
	c := metaPromptCacheKeyForSession("sess-2")
	if a == "" || len(a) != 32 {
		t.Fatalf("key = %q, want 32 hex chars", a)
	}
	for _, r := range a {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("key = %q, want lowercase hex", a)
		}
	}
	if a != b {
		t.Fatal("same session derived different keys across calls")
	}
	if a == c {
		t.Fatal("different sessions derived the same key")
	}
	if got := metaPromptCacheKeyForSession(""); got != "" {
		t.Fatalf("empty session derived %q, want empty", got)
	}
	if got := metaPromptCacheKeyForSession("   "); got != "" {
		t.Fatalf("blank session derived %q, want empty", got)
	}
}

// The key needs no setting: a zero-value config and every Meta credential get it.
func TestMetaPromptCacheKey_AlwaysSentForEveryAuth(t *testing.T) {
	upstream := newMuseReplayUpstream(t, "a", "b")
	exec := NewMetaExecutor(&config.Config{})
	for _, account := range []string{"a", "b"} {
		if err := metaPCKExecute(t, exec, upstream.auth(account), "sess-1"); err != nil {
			t.Fatal(err)
		}
	}
	first, second := metaPCKUpstreamKey(t, upstream, 0), metaPCKUpstreamKey(t, upstream, 1)
	if first == "" || second == "" {
		t.Fatalf("keys = %q %q, want both present", first, second)
	}
	if first != second {
		t.Fatalf("same session sent %q then %q across credentials, want the same key", first, second)
	}
}

func TestMetaPromptCacheKey_SessionlessStillDeterministic(t *testing.T) {
	upstream := newMuseReplayUpstream(t, "a")
	auth := upstream.auth("a")
	exec := NewMetaExecutor(metaPCKConfig())
	if err := metaPCKExecute(t, exec, auth, ""); err != nil {
		t.Fatal(err)
	}
	if err := metaPCKExecute(t, exec, auth, ""); err != nil {
		t.Fatal(err)
	}
	first, second := metaPCKUpstreamKey(t, upstream, 0), metaPCKUpstreamKey(t, upstream, 1)
	if first == "" {
		t.Fatal("sessionless request sent no prompt_cache_key")
	}
	if first != second {
		t.Fatalf("identical sessionless requests sent %q then %q, want deterministic", first, second)
	}
}

func TestMetaPromptCacheKey_NoResolvableSessionSetsNothing(t *testing.T) {
	exec := NewMetaExecutor(metaPCKConfig())
	got := string(exec.applyMetaPromptCacheKey(context.Background(),
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{}, []byte(`{"model":"muse-spark-1.3","input":[]}`)))
	if key := strings.TrimSpace(gjson.GetBytes([]byte(got), "prompt_cache_key").String()); key != "" {
		t.Fatalf("empty context session sent prompt_cache_key = %q, want absent", key)
	}
}

func TestMetaPromptCacheKey_StableWithinSessionDifferentAcross(t *testing.T) {
	upstream := newMuseReplayUpstream(t, "a")
	auth := upstream.auth("a")
	exec := NewMetaExecutor(metaPCKConfig())

	if err := metaPCKExecute(t, exec, auth, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if err := metaPCKExecute(t, exec, auth, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if err := metaPCKExecute(t, exec, auth, "sess-2"); err != nil {
		t.Fatal(err)
	}
	first, second, third := metaPCKUpstreamKey(t, upstream, 0), metaPCKUpstreamKey(t, upstream, 1), metaPCKUpstreamKey(t, upstream, 2)
	if first == "" || second == "" || third == "" {
		t.Fatalf("keys = %q %q %q, want all present", first, second, third)
	}
	if first != second {
		t.Fatalf("same session sent %q then %q, want stable", first, second)
	}
	if first == third {
		t.Fatalf("different sessions shared prompt_cache_key = %q", first)
	}
}

func TestMetaPromptCacheKey_DoesNotOverrideClientValue(t *testing.T) {
	exec := NewMetaExecutor(metaPCKConfig())
	ctx := metaPCKSessionContext("sess-1")
	body := []byte(`{"model":"muse-spark-1.3","input":[]}`)

	got := string(exec.applyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3","prompt_cache_key":"client-key-1"}`)},
		cliproxyexecutor.Options{}, body))
	if key := gjson.GetBytes([]byte(got), "prompt_cache_key").String(); key != "client-key-1" {
		t.Fatalf("client payload value not carried over: got %q, want client-key-1", key)
	}

	withClientKey := []byte(`{"model":"muse-spark-1.3","prompt_cache_key":"client-key-2","input":[]}`)
	got = string(exec.applyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{}, withClientKey))
	if key := gjson.GetBytes([]byte(got), "prompt_cache_key").String(); key != "client-key-2" {
		t.Fatalf("translated client value overwritten: got %q, want client-key-2", key)
	}

	got = string(exec.applyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{OriginalRequest: []byte(`{"prompt_cache_key":"client-key-3"}`)}, body))
	if key := gjson.GetBytes([]byte(got), "prompt_cache_key").String(); key != "client-key-3" {
		t.Fatalf("original-request client value not carried over: got %q, want client-key-3", key)
	}

	got = string(exec.applyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{}, body))
	want := metaPromptCacheKeyForSession("sess-1")
	if key := gjson.GetBytes([]byte(got), "prompt_cache_key").String(); key != want {
		t.Fatalf("key = %q, want derived %q", key, want)
	}
}
