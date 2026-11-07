package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryConfigAcceptsActualHostTypesInBothLayouts(t *testing.T) {
	for _, raw := range []string{
		"port: 8317\nauth-dir: /not-opened\nplugins: {enabled: true, dir: /not-loaded, configs: {meta: {enabled: true, priority: 1, plugin-owned: {arbitrary: true}}}}\n",
		"config-version: 8\nserver: {port: 8317}\noauth: {auth-dir: /not-opened}\nplugins: {enabled: true, configs: {meta: {enabled: true, priority: 1, plugin-owned: {arbitrary: true}}}}\n",
		"config-version: 8\nserver: {}\nrequests: {payload: {override: [{params: {some-field: {arbitrary: true}}}]}}\n",
		"disable-image-generation: true\ncredential-concurrency: {cpa-heartbeat-timeout: 3s}\n",
		"config-version: 8\napi-keys: {codex: [{name: example, base-url: 'https://invalid.example', keys: [{api-key: synthetic}]}]}\n",
		"config-version: 8\napi-keys: {codex: [{name: empty, base-url: 'https://invalid.example', keys: []}]}\n",
		"config-version: 8\napi-keys: {openai-compatibility: [{name: example, base-url: 'https://invalid.example', keys: [{api-key: synthetic}]}]}\n",
		"config-version: 8\nclient: {codex: {web-search-result-cache: {enabled: true, ttl: 30, limit: 10}}}\n",
	} {
		if err := ValidateRecoveryConfigBytes([]byte(raw)); err != nil {
			t.Errorf("supported config rejected: %s: %v", raw, err)
		}
	}
}

func TestRecoveryConfigRejectsUnknownMistypedAndMixedHostFields(t *testing.T) {
	for _, raw := range []string{
		"unknown-host-option: true\n",
		"port: '8317'\n", "host: 123\n", "port: [8317]\n", "port: null\n",
		"tls: {enable: 'true'}\n", "tls: {typo: true}\n",
		"credential-concurrency: {typo: 1}\n",
		"codex: {live-media-relay: {typo: 1}}\n",
		"plugins: []\n", "plugins: {configs: {meta: true}}\n",
		"plugins: {configs: {meta: {enabled: 'true'}}}\n",
		"plugins: {configs: {meta: {priority: '1'}}}\n",
		"plugins: {configs: {meta: {enabled: true, enabled: false}}}\n",
		"plugins: {enabled: true, typo: 1}\n",
		"config-version: 8\nserver: {port: '8317'}\n",
		"config-version: 8\nserver: {port: 8317}\nport: 8318\n",
		"config-version: 8\nserver: {unexpected-empty: {}}\n",
		"config-version: 8\ncredentials: {concurrency: {typo: 1}}\n",
		"config-version: 8\nclient: {codex: {web-search-result-cache: {typo: 1}}}\n",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateRecoveryConfigBytes([]byte(raw)); err != errRecoveryConfig {
				t.Fatalf("got %v, want fixed refusal", err)
			}
		})
	}
}

func TestRecoveryConfigUsesIntrinsicValidatorsWithoutSanitizing(t *testing.T) {
	for _, raw := range []string{
		"trusted-proxies: [not-a-network]\n",
		"credential-concurrency: {cpa-heartbeat-timeout: 0s}\n",
		"credential-concurrency: {busy-retry-min: 2s, busy-retry-max: 1s}\n",
		"credential-in-flight: {max-part-count: 0}\n",
		"codex-api-key: [{api-key: synthetic, weight: 1000001}]\n",
		"config-version: 8\ncredentials: {in-flight: {max-part-count: 0}}\n",
		"config-version: 8\nclient: {codex: {web-search-result-cache: {ttl: -1}}}\n",
	} {
		if err := ValidateRecoveryConfigBytes([]byte(raw)); err != errRecoveryConfig {
			t.Errorf("invalid intrinsic value accepted: %s: %v", raw, err)
		}
	}
}

func TestRecoveryConfigRejectsGroupValuesHiddenByRuntimeExpansion(t *testing.T) {
	for _, raw := range []string{
		"config-version: 8\napi-keys: {codex: [{name: hidden, base-url: [invalid], keys: []}]}\n",
		"config-version: 8\napi-keys: {codex: [{headers: [invalid], keys: [{api-key: synthetic, headers: {valid: override}}]}]}\n",
		"config-version: 8\napi-keys: {codex: [{keys: [{api-key: synthetic, secret-unknown: null}]}]}\n",
		"config-version: 8\napi-keys: {openai-compatibility: [{name: example, api-key-entries: invalid, keys: [{api-key: synthetic}]}]}\n",
	} {
		if err := ValidateV8Config([]byte(raw)); err != nil {
			t.Fatalf("fixture must reach the runtime expansion gap: %v", err)
		}
		if err := ValidateRecoveryConfigBytes([]byte(raw)); err != errRecoveryConfig {
			t.Errorf("hidden source value accepted: %s: %v", raw, err)
		}
	}
}

func TestRecoveryConfigDoesNotHashSecretsOrResolveOrWriteFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent")
	raw := []byte("port: 8317\nremote-management: {secret-key: '" + strings.Repeat("synthetic", 20) + "'}\nplugins: {enabled: true, dir: '" + path + "'}\nauth-dir: '" + path + "'\n")
	before := bytes.Clone(raw)
	t.Setenv("HOME", path)
	if err := ValidateRecoveryConfigBytes(raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("input changed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected filesystem change: %v, %d entries", err, len(entries))
	}
}

func TestRecoveryConfigEnvelopeAndErrors(t *testing.T) {
	for _, raw := range [][]byte{
		nil, []byte("[]"), []byte("null"), []byte("port: [secret-malformed"),
		[]byte("port: 8317\n---\nport: 8318\n"), []byte("port: 8317\n---\n"),
		bytes.Repeat([]byte(" "), (4<<20)+1), []byte("secret-host-key: secret-value"),
	} {
		if err := ValidateRecoveryConfigBytes(raw); err == nil || err.Error() != "recovery-config-invalid" {
			t.Fatalf("got %v, want fixed redacted refusal", err)
		}
	}
}
