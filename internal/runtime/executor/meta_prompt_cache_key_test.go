package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// metaPCKUpstream records every request body the Meta executor sends.
type metaPCKUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
}

func newMetaPCKUpstream(t *testing.T) *metaPCKUpstream {
	t.Helper()
	u := &metaPCKUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Errorf("read body: %v", errRead)
			return
		}
		u.mu.Lock()
		u.bodies = append(u.bodies, body)
		u.mu.Unlock()
		writeMetaResponsesOK(w, "ok")
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *metaPCKUpstream) auth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "meta",
		Attributes: map[string]string{
			"api_key":  "meta-token",
			"base_url": u.server.URL,
		},
	}
}

func (u *metaPCKUpstream) keyAt(t *testing.T, callIndex int) string {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if callIndex >= len(u.bodies) {
		t.Fatalf("upstream saw %d requests, want at least %d", len(u.bodies), callIndex+1)
	}
	return strings.TrimSpace(gjson.GetBytes(u.bodies[callIndex], "prompt_cache_key").String())
}

func (u *metaPCKUpstream) bodyAt(t *testing.T, callIndex int) []byte {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if callIndex >= len(u.bodies) {
		t.Fatalf("upstream saw %d requests, want at least %d", len(u.bodies), callIndex+1)
	}
	return u.bodies[callIndex]
}

func metaPCKExecute(t *testing.T, exec *MetaExecutor, upstream *metaPCKUpstream, ctx context.Context, payload string) {
	t.Helper()
	_, err := exec.Execute(ctx, upstream.auth(), cliproxyexecutor.Request{
		Model:   "muse-spark-1.3",
		Payload: []byte(payload),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

const metaPCKPayload = `{"model":"muse-spark-1.3","messages":[{"role":"user","content":"hello"}]}`

// The key needs no setting: a zero-value config sends it, stable within a
// session and distinct across sessions.
func TestMetaPromptCacheKey_StableWithinSessionDifferentAcross(t *testing.T) {
	upstream := newMetaPCKUpstream(t)
	exec := NewMetaExecutor(&config.Config{})

	metaPCKExecute(t, exec, upstream, util.WithSessionID(context.Background(), "sess-1"), metaPCKPayload)
	metaPCKExecute(t, exec, upstream, util.WithSessionID(context.Background(), "sess-1"), metaPCKPayload)
	metaPCKExecute(t, exec, upstream, util.WithSessionID(context.Background(), "sess-2"), metaPCKPayload)

	first, second, third := upstream.keyAt(t, 0), upstream.keyAt(t, 1), upstream.keyAt(t, 2)
	if first == "" || second == "" || third == "" {
		t.Fatalf("keys = %q %q %q, want all present", first, second, third)
	}
	if first != second {
		t.Fatalf("same session sent %q then %q, want stable", first, second)
	}
	if first == third {
		t.Fatalf("different sessions shared prompt_cache_key = %q", first)
	}
	if want := helps.MetaPromptCacheKeyForSession("sess-1"); first != want {
		t.Fatalf("key = %q, want derived %q", first, want)
	}
}

// The key follows the session, not the credential: rotating credentials
// mid-session must not move the session to a different cache bucket.
func TestMetaPromptCacheKey_SameAcrossCredentials(t *testing.T) {
	upstream := newMetaPCKUpstream(t)
	exec := NewMetaExecutor(&config.Config{})
	ctx := util.WithSessionID(context.Background(), "sess-1")

	metaPCKExecute(t, exec, upstream, ctx, metaPCKPayload)
	other := upstream.auth()
	other.Attributes["api_key"] = "other-token"
	if _, err := exec.Execute(ctx, other, cliproxyexecutor.Request{
		Model:   "muse-spark-1.3",
		Payload: []byte(metaPCKPayload),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")}); err != nil {
		t.Fatalf("Execute() with second credential error = %v", err)
	}

	first, second := upstream.keyAt(t, 0), upstream.keyAt(t, 1)
	if first == "" || first != second {
		t.Fatalf("same session sent %q then %q across credentials, want the same key", first, second)
	}
}

// Without an explicit session the canonical session identity still resolves
// deterministically, so identical conversations share one key.
func TestMetaPromptCacheKey_SessionlessStillDeterministic(t *testing.T) {
	upstream := newMetaPCKUpstream(t)
	exec := NewMetaExecutor(&config.Config{})

	metaPCKExecute(t, exec, upstream, context.Background(), metaPCKPayload)
	metaPCKExecute(t, exec, upstream, context.Background(), metaPCKPayload)

	first, second := upstream.keyAt(t, 0), upstream.keyAt(t, 1)
	if first == "" {
		t.Fatal("sessionless request sent no prompt_cache_key")
	}
	if first != second {
		t.Fatalf("identical sessionless requests sent %q then %q, want deterministic", first, second)
	}
}

func TestMetaPromptCacheKey_StreamingAlsoSent(t *testing.T) {
	upstream := newMetaPCKUpstream(t)
	exec := NewMetaExecutor(&config.Config{})

	result, err := exec.ExecuteStream(util.WithSessionID(context.Background(), "sess-1"), upstream.auth(), cliproxyexecutor.Request{
		Model:   "muse-spark-1.3",
		Payload: []byte(metaPCKPayload),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai"), Stream: true})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error: %v", chunk.Err)
		}
	}
	if key := upstream.keyAt(t, 0); key != helps.MetaPromptCacheKeyForSession("sess-1") {
		t.Fatalf("streamed key = %q, want derived", key)
	}
}

// A prompt_cache_key the client sent itself is carried through untouched,
// even when a session-derived key is available.
func TestMetaPromptCacheKey_ClientValuePreserved(t *testing.T) {
	upstream := newMetaPCKUpstream(t)
	exec := NewMetaExecutor(&config.Config{})

	metaPCKExecute(t, exec, upstream, util.WithSessionID(context.Background(), "sess-1"),
		`{"model":"muse-spark-1.3","prompt_cache_key":"client-key","messages":[{"role":"user","content":"hello"}]}`)

	if key := upstream.keyAt(t, 0); key != "client-key" {
		t.Fatalf("key = %q, want client-supplied client-key", key)
	}
}

// The derived key is a built-in injection, so it is applied before user
// payload rules: an override rule replaces it and a filter rule removes it,
// and nothing afterwards restores it.
func TestMetaPromptCacheKey_PayloadRulesRemainFinalBarrier(t *testing.T) {
	ctx := util.WithSessionID(context.Background(), "sess-1")

	t.Run("override wins over derived key", func(t *testing.T) {
		upstream := newMetaPCKUpstream(t)
		cfg := &config.Config{Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "muse-spark-1.3"}},
				Params: map[string]any{"prompt_cache_key": "configured-key"},
			}},
		}}
		metaPCKExecute(t, NewMetaExecutor(cfg), upstream, ctx, metaPCKPayload)
		if key := upstream.keyAt(t, 0); key != "configured-key" {
			t.Fatalf("key = %q, want payload-rule value configured-key", key)
		}
	})

	t.Run("filter removes derived key", func(t *testing.T) {
		upstream := newMetaPCKUpstream(t)
		cfg := &config.Config{Payload: config.PayloadConfig{
			Filter: []config.PayloadFilterRule{{
				Models: []config.PayloadModelRule{{Name: "muse-spark-1.3"}},
				Params: []string{"prompt_cache_key"},
			}},
		}}
		metaPCKExecute(t, NewMetaExecutor(cfg), upstream, ctx, metaPCKPayload)
		if gjson.GetBytes(upstream.bodyAt(t, 0), "prompt_cache_key").Exists() {
			t.Fatalf("filtered prompt_cache_key was restored after payload rules: %s", upstream.bodyAt(t, 0))
		}
	})
}
