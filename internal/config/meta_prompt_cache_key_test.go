package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The former meta.prompt-cache-key switch is gone: the key is always sent. A
// config that still carries the old block must keep loading (and keep every
// other Meta setting) so an image upgrade never depends on a config edit.
func TestMetaStalePromptCacheKeyBlockIsIgnored(t *testing.T) {
	legacy := []byte("meta:\n  reasoning-replay: {enabled: true, models: ['muse-spark-1.3*']}\n  prompt-cache-key: {enabled: true, auths: ['meta5']}\n")
	canonical := []byte("upstream:\n  meta:\n    reasoning-replay: {enabled: true, models: ['muse-spark-1.3*']}\n    prompt-cache-key:\n      enabled: true\n      auths: ['meta5']\n")
	want := MetaReasoningReplayConfig{Enabled: true, Models: []string{"muse-spark-1.3*"}}
	for name, raw := range map[string][]byte{"legacy": legacy, "upstream": canonical} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfigBytes(raw)
			if err != nil {
				t.Fatalf("stale prompt-cache-key block broke parsing: %v", err)
			}
			if !reflect.DeepEqual(cfg.Meta.ReasoningReplay, want) {
				t.Fatalf("reasoning-replay = %+v, want %+v", cfg.Meta.ReasoningReplay, want)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig with stale prompt-cache-key block: %v", err)
			}
			if !reflect.DeepEqual(loaded.Meta.ReasoningReplay, want) {
				t.Fatalf("loaded reasoning-replay = %+v, want %+v", loaded.Meta.ReasoningReplay, want)
			}
			migrated, _, errMigrate := NormalizeConfigLayout(raw, true)
			if errMigrate != nil {
				t.Fatalf("layout migration: %v", errMigrate)
			}
			if errValidate := ValidateV8Config(migrated); errValidate != nil {
				t.Fatalf("v8 validation rejected the stale block: %v", errValidate)
			}
		})
	}
}
