package helps

import (
	"context"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/signature"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestMetaReasoningReplay_AccountPolicyDoc(t *testing.T) {
	const accountKey = "0123456789abcdef"
	doc := ojson.NewDocString(`{"input":[{"type":"reasoning","encrypted_content":""},{"type":"reasoning","encrypted_content":"legacy","summary":[{"type":"summary_text","text":"keep me"}]},{"type":"reasoning","encrypted_content":"legacy","summary":[]},{"type":"message","role":"user","content":"hello"}]}`)
	_ = doc.Set("input.0.encrypted_content", signature.TagMetaReasoning(accountKey, "owned"))
	_ = doc.Set("model", "normalized-before-replay")
	replay := MetaReasoningReplay{Enabled: true, AccountKey: accountKey, Stats: &MetaReasoningReplayStats{}}
	if !replay.ApplyAccountPolicyDoc(context.Background(), doc) {
		t.Fatal("account policy did not report a mutation")
	}
	if got := doc.Get("model").String(); got != "normalized-before-replay" {
		t.Fatalf("earlier document mutation was lost: model = %q", got)
	}
	items := doc.Get("input").Array()
	if len(items) != 3 || items[0].Get("encrypted_content").String() != "owned" || items[1].Get("encrypted_content").Exists() || items[1].Get("summary.0.text").String() != "keep me" || items[2].Get("content").String() != "hello" {
		t.Fatalf("account policy rebuilt input incorrectly: %s", doc.Bytes())
	}
	if replay.Stats.Kept != 1 || replay.Stats.DroppedUntagged != 2 {
		t.Fatalf("unexpected account policy stats: %+v", replay.Stats)
	}
}

func TestMetaReasoningReplay_TagResponseDoc(t *testing.T) {
	const accountKey = "0123456789abcdef"
	replay := MetaReasoningReplay{Enabled: true, AccountKey: accountKey}
	event := []byte(`{"type":"response.completed","response":{"output":[{"type":"reasoning","encrypted_content":"first"},{"type":"message","content":[]},{"type":"reasoning","encrypted_content":"second"}]}}`)
	tagged := replay.TagResponseEvent(event)
	for index, want := range map[string]string{"0": "first", "2": "second"} {
		key, envelope, ok := signature.ParseMetaReasoningTag(ojson.GetBytes(tagged, "response.output."+index+".encrypted_content").String())
		if !ok || key != accountKey || envelope != want {
			t.Fatalf("output %s: tag = (%q, %q, %v)", index, key, envelope, ok)
		}
	}
	if got := ojson.GetBytes(tagged, "response.output.1.type").String(); got != "message" {
		t.Fatalf("non-reasoning item changed: %s", tagged)
	}
}

func TestMetaReasoningAccountKey(t *testing.T) {
	a := MetaReasoningAccountKey(&cliproxyauth.Auth{ID: "meta-a"})
	if a == "" || a != MetaReasoningAccountKey(&cliproxyauth.Auth{ID: "meta-a", Attributes: map[string]string{"api_key": "rotated"}}) {
		t.Fatalf("account key must depend on identity only and survive token rotation, got %q", a)
	}
	if a == MetaReasoningAccountKey(&cliproxyauth.Auth{ID: "meta-b"}) {
		t.Fatal("distinct accounts share a key")
	}
	if _, _, ok := signature.ParseMetaReasoningTag(signature.TagMetaReasoning(a, "x")); !ok {
		t.Fatalf("account key %q is not a valid tag key", a)
	}
	if got := MetaReasoningAccountKey(nil); got != "" {
		t.Fatalf("nil auth produced key %q", got)
	}
	if got := MetaReasoningAccountKey(&cliproxyauth.Auth{}); got != "" {
		t.Fatalf("anonymous auth produced key %q", got)
	}
	if got := MetaReasoningAccountKey(&cliproxyauth.Auth{Attributes: map[string]string{"api_key": "k"}}); got != "" {
		t.Fatalf("a key must never be derived from the API key, got %q", got)
	}
}
