package executor

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestMetaPromptCacheKey_ChatClientCarryoverRequiresOptIn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   *config.Config
		label string
		want  string
	}{
		{"disabled", metaPCKConfig(false), "meta5", ""},
		{"outside canary", metaPCKConfig(true, "meta5"), "meta6", ""},
		{"canary", metaPCKConfig(true, "meta5"), "meta5", "client-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`{"model":"muse-spark-1.3","messages":[{"role":"user","content":"hello"}],"prompt_cache_key":"client-key"}`)
			req := cliproxyexecutor.Request{Model: "muse-spark-1.3", Payload: payload}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")}
			for _, stream := range []bool{false, true} {
				prepared, err := NewMetaExecutor(tc.cfg).prepareResponsesRequest(metaPCKSessionContext("sess"), &cliproxyauth.Auth{Label: tc.label}, req, opts, stream)
				if err != nil {
					t.Fatal(err)
				}
				if got := gjson.GetBytes(prepared.body, "prompt_cache_key").String(); got != tc.want {
					t.Errorf("stream=%v: got %q, want %q; body %s", stream, got, tc.want, prepared.body)
				}
			}
		})
	}
}

func TestMetaPromptCacheKey_PayloadRulesAreFinal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload config.PayloadConfig
		want    string
	}{
		{"filter", config.PayloadConfig{Filter: []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"prompt_cache_key"}}}}, ""},
		{"override", config.PayloadConfig{Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"prompt_cache_key": "configured"}}}}, "configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := metaPCKConfig(true)
			cfg.Payload = tc.payload
			req := cliproxyexecutor.Request{Model: "muse-spark-1.3", Payload: []byte(`{"model":"muse-spark-1.3","messages":[{"role":"user","content":"hello"}],"prompt_cache_key":"client-key"}`)}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")}
			for _, stream := range []bool{false, true} {
				prepared, err := NewMetaExecutor(cfg).prepareResponsesRequest(metaPCKSessionContext("sess"), &cliproxyauth.Auth{Label: "meta5"}, req, opts, stream)
				if err != nil {
					t.Fatal(err)
				}
				if got := gjson.GetBytes(prepared.body, "prompt_cache_key").String(); got != tc.want {
					t.Errorf("stream=%v: got %q, want %q; body %s", stream, got, tc.want, prepared.body)
				}
			}
		})
	}
}

func TestMetaPromptCacheKey_OriginalRequestCarryoverRequiresOptIn(t *testing.T) {
	for _, cfg := range []*config.Config{metaPCKConfig(false), metaPCKConfig(true, "meta5")} {
		body := []byte(`{"model":"muse-spark-1.3"}`)
		got := NewMetaExecutor(cfg).applyMetaPromptCacheKey(context.Background(), cliproxyexecutor.Request{}, cliproxyexecutor.Options{OriginalRequest: []byte(`{"prompt_cache_key":"client-key"}`)}, body, &cliproxyauth.Auth{Label: "meta6"})
		if string(got) != string(body) {
			t.Errorf("ineligible auth changed body: %s", got)
		}
	}
}
