package helps

import (
	"context"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

func TestMetaPromptCacheKeyForSession_Derivation(t *testing.T) {
	a := MetaPromptCacheKeyForSession("sess-1")
	b := MetaPromptCacheKeyForSession("sess-1")
	c := MetaPromptCacheKeyForSession("sess-2")
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
	if got := MetaPromptCacheKeyForSession(""); got != "" {
		t.Fatalf("empty session derived %q, want empty", got)
	}
	if got := MetaPromptCacheKeyForSession("   "); got != "" {
		t.Fatalf("blank session derived %q, want empty", got)
	}
}

func TestApplyMetaPromptCacheKey_NoResolvableSessionSetsNothing(t *testing.T) {
	got := ApplyMetaPromptCacheKey(context.Background(),
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{}, []byte(`{"model":"muse-spark-1.3","input":[]}`))
	if key := strings.TrimSpace(gjson.GetBytes(got, "prompt_cache_key").String()); key != "" {
		t.Fatalf("empty context session sent prompt_cache_key = %q, want absent", key)
	}
}

func TestApplyMetaPromptCacheKey_DoesNotOverrideClientValue(t *testing.T) {
	ctx := util.WithSessionID(context.Background(), "sess-1")
	body := []byte(`{"model":"muse-spark-1.3","input":[]}`)

	got := ApplyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3","prompt_cache_key":"client-key-1"}`)},
		cliproxyexecutor.Options{}, body)
	if key := gjson.GetBytes(got, "prompt_cache_key").String(); key != "client-key-1" {
		t.Fatalf("client payload value not carried over: got %q, want client-key-1", key)
	}

	withClientKey := []byte(`{"model":"muse-spark-1.3","prompt_cache_key":"client-key-2","input":[]}`)
	got = ApplyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{}, withClientKey)
	if key := gjson.GetBytes(got, "prompt_cache_key").String(); key != "client-key-2" {
		t.Fatalf("translated client value overwritten: got %q, want client-key-2", key)
	}

	got = ApplyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{OriginalRequest: []byte(`{"prompt_cache_key":"client-key-3"}`)}, body)
	if key := gjson.GetBytes(got, "prompt_cache_key").String(); key != "client-key-3" {
		t.Fatalf("original-request client value not carried over: got %q, want client-key-3", key)
	}

	got = ApplyMetaPromptCacheKey(ctx,
		cliproxyexecutor.Request{Payload: []byte(`{"model":"muse-spark-1.3"}`)},
		cliproxyexecutor.Options{}, body)
	want := MetaPromptCacheKeyForSession("sess-1")
	if key := gjson.GetBytes(got, "prompt_cache_key").String(); key != want {
		t.Fatalf("key = %q, want derived %q", key, want)
	}
}
