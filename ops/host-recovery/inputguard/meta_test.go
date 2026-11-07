package inputguard

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const metaConfig = "plugins:\n  enabled: true\n  configs:\n    meta:\n      enabled: true\n      priority: 2\n      reasoning-replay: {enabled: true, models: ['muse-spark-*', 'muse-wonder-*']}\n"

func metaRequest(t *testing.T, inputs []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"schema": "host-recovery-meta-input-request-v1", "producer_config": MetaConfigProfile, "inputs": json.RawMessage(inputs)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMetaConfigSourcePin(t *testing.T) {
	raw, err := os.ReadFile("testdata/meta-config/config.go.txt")
	if err != nil || rawHash(raw) != "4665020ba0b2688dda79578f3f8717878a50212c8fd092f856c728c563ddbfd8" || !strings.Contains(MetaConfigProfile, rawHash(raw)) {
		t.Fatal("inert reviewed config source no longer matches the profile")
	}
}

func TestMetaConfigStrictSourceProjection(t *testing.T) {
	for _, raw := range []string{metaConfig, strings.Replace(metaConfig, "priority: 2", "priority: -1", 1),
		"plugins: {enabled: true, configs: {meta: {enabled: true}}}",
		"plugins: {enabled: true, configs: {meta: {enabled: true, reasoning-replay: {}}}}",
		"plugins: {enabled: true, configs: {meta: {enabled: true, reasoning-replay: {enabled: false, models: []}}}}"} {
		if err := validateMetaConfig([]byte(raw), true); err != nil {
			t.Fatalf("supported shape refused: %v", err)
		}
	}
	// These are shape checks, not replay/policy enablement or canary coverage.
	if validateMetaConfig([]byte("port: 8317"), false) != nil {
		t.Fatal("plugin-free baseline refused")
	}
	if validateMetaConfig([]byte("port: 8317"), true) != errMeta {
		t.Fatal("missing candidate plugin accepted")
	}
}

func TestMetaConfigRejectsCoercionUnknownAndMalformedOptions(t *testing.T) {
	for _, option := range []string{
		"false", "null", "[]", "{enabled: 'true'}", "{enabled: 1}", "{enabled: null}",
		"{Enabled: true}", "{enabled: true, unknown: secret}", "{models: null}", "{models: one}",
		"{models: [1]}", "{models: [true]}", "{models: [null]}", "{models: [{}]}",
		"{enabled: true, enabled: false}", "{models: [*missing]}",
	} {
		raw := []byte("plugins: {enabled: true, configs: {meta: {enabled: true, reasoning-replay: " + option + "}}}")
		for _, candidate := range []bool{false, true} {
			if err := validateMetaConfig(raw, candidate); err != errMeta {
				t.Fatalf("malformed option accepted: %q (%v)", option, err)
			}
		}
	}
	for _, item := range []string{"null", "false", "[]", "{enabled: true, reasoning_replay: {enabled: true}}",
		"{enabled: true, store: {version: '0.2.4'}}", "{enabled: 'true'}", "{enabled: true, priority: '2'}"} {
		if validateMetaConfig([]byte("plugins: {enabled: true, configs: {meta: "+item+"}}"), true) != errMeta {
			t.Fatal("unsupported Meta subtree accepted")
		}
	}
}

func TestMetaRequiresExplicitCandidateActivationAndPreservesOtherPlugins(t *testing.T) {
	for _, raw := range []string{"plugins: {enabled: false, configs: {meta: {enabled: true}}}",
		"plugins: {configs: {meta: {enabled: true}}}", "plugins: {enabled: true, configs: {meta: {}}}",
		"plugins: {enabled: true, configs: {meta: {enabled: false}}}"} {
		if validateMetaConfig([]byte(raw), true) != errMeta {
			t.Fatal("implicit or disabled candidate accepted")
		}
	}
	raw := []byte(metaConfig + "    another: {plugin-owned-option: {keep: [1, true, opaque]}}\n")
	before := append([]byte(nil), raw...)
	if validateMetaConfig(raw, true) != nil || !bytes.Equal(raw, before) {
		t.Fatal("unrelated plugin interpreted or input mutated")
	}
}

func TestMetaComposesAllInputChecksAndBothConfigSides(t *testing.T) {
	bundle, env := composeFixture(t)
	bundle.Config = Pair{Before: []byte(metaConfig), After: []byte(metaConfig), BeforeSHA256: rawHash([]byte(metaConfig)), AfterSHA256: rawHash([]byte(metaConfig))}
	if VerifyMetaRequest(bytes.NewReader(metaRequest(t, composeRequest(t, bundle, env, env)))) != nil {
		t.Fatal("valid composed request refused")
	}
	for _, side := range []string{"before", "after"} {
		bad := bundle
		data := []byte(strings.Replace(metaConfig, "models: [", "models: [1, ", 1))
		// Explicit synthetic delta approvals make the older opaque-plugin gate
		// succeed; each side independently reaches the Meta shape validator.
		bad.Config = Pair{Before: data, After: []byte(metaConfig), BeforeSHA256: rawHash(data), AfterSHA256: rawHash([]byte(metaConfig)),
			Changes: []Change{{Path: []string{"plugins", "configs", "meta", "reasoning-replay", "models"}, Before: semantic(t, "[1, 'muse-spark-*', 'muse-wonder-*']"), After: semantic(t, "['muse-spark-*', 'muse-wonder-*']")}}}
		if side == "after" {
			bad.Config.Before, bad.Config.After = bad.Config.After, bad.Config.Before
			bad.Config.BeforeSHA256, bad.Config.AfterSHA256 = bad.Config.AfterSHA256, bad.Config.BeforeSHA256
			bad.Config.Changes[0].Before, bad.Config.Changes[0].After = bad.Config.Changes[0].After, bad.Config.Changes[0].Before
		}
		inputs := composeRequest(t, bad, env, env)
		if VerifyComposeRequest(bytes.NewReader(inputs)) != nil {
			t.Fatal("fixture must pass opaque-plugin Compose gate")
		}
		if VerifyMetaRequest(bytes.NewReader(metaRequest(t, inputs))) != errMeta {
			t.Fatal("invalid source-pinned plugin config accepted")
		}
	}
	bad := bundle
	bad.FrozenRenderedCompose = bad.ComposeSource
	if VerifyMetaRequest(bytes.NewReader(metaRequest(t, composeRequest(t, bad, env, env)))) != errMeta {
		t.Fatal("Meta schema replaced Compose correspondence")
	}
	bad = bundle
	bad.Config.BeforeSHA256 = strings.Repeat("0", 64)
	if VerifyMetaRequest(bytes.NewReader(metaRequest(t, composeRequest(t, bad, env, env)))) != errMeta {
		t.Fatal("Meta schema replaced byte pins")
	}
}

func TestMetaProtocolDowngradeAndSecretFreeReceipt(t *testing.T) {
	bundle, env := composeFixture(t)
	bundle.Config = Pair{Before: []byte(metaConfig), After: []byte(metaConfig), BeforeSHA256: rawHash([]byte(metaConfig)), AfterSHA256: rawHash([]byte(metaConfig))}
	inputs := composeRequest(t, bundle, env, env)
	raw := metaRequest(t, inputs)
	var output bytes.Buffer
	if !ServeMeta(bytes.NewReader(raw), &output) || !strings.Contains(output.String(), `"meta_config_validated":true`) || !strings.Contains(output.String(), `"start_authorized":false`) {
		t.Fatal("missing distinct receipt")
	}
	for _, bad := range [][]byte{inputs, append(raw, raw...), []byte("secret malformed input"),
		bytes.Replace(raw, []byte(MetaConfigProfile), []byte("wrong-source"), 1),
		bytes.Replace(raw, []byte(`"producer_config":`), []byte(`"producer_config":"duplicate","producer_config":`), 1),
		bytes.Replace(raw, []byte(`"producer_config":`), []byte(`"Producer_config":`), 1)} {
		output.Reset()
		if ServeMeta(bytes.NewReader(bad), &output) || !strings.Contains(output.String(), `"meta_config_validated":false`) || bytes.Contains(output.Bytes(), []byte("secret")) || output.Len() > 256 {
			t.Fatal("bad envelope accepted or diagnostic leaked")
		}
	}
	if ServeMeta(bytes.NewReader(raw), shortWriter{}) {
		t.Fatal("short receipt write accepted")
	}
}

func FuzzMetaConfigShape(f *testing.F) {
	for _, seed := range []string{metaConfig, "plugins: {configs: {meta: null}}", "plugins: null"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		before := append([]byte(nil), raw...)
		err := validateMetaConfig(raw, true)
		if !bytes.Equal(raw, before) || err != nil && err != errMeta {
			t.Fatal("mutated input or unsafe error")
		}
	})
}
