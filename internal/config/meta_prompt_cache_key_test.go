package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMetaPromptCacheKeyDefaultsOff(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("port: 8317\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Meta.PromptCacheKey.Enabled || len(cfg.Meta.PromptCacheKey.Auths) != 0 {
		t.Fatalf("meta prompt cache key must default to off, got %+v", cfg.Meta.PromptCacheKey)
	}
}

func TestMetaPromptCacheKeyConfigSurvivesLayoutMigration(t *testing.T) {
	legacy := []byte("meta: {prompt-cache-key: {enabled: true, auths: ['meta5']}}\n")
	canonical := []byte("upstream:\n  meta:\n    prompt-cache-key:\n      enabled: true\n      auths: ['meta5']\n")
	want := MetaPromptCacheKeyConfig{Enabled: true, Auths: []string{"meta5"}}
	for name, raw := range map[string][]byte{"legacy": legacy, "upstream": canonical} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfigBytes(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.Meta.PromptCacheKey, want) {
				t.Fatalf("parsed %+v, want %+v", cfg.Meta.PromptCacheKey, want)
			}
			if got := cfg.CloneForRuntime().Meta.PromptCacheKey; !reflect.DeepEqual(got, want) {
				t.Fatalf("clone changed the setting: %+v", got)
			}
			migrated, _, err := NormalizeConfigLayout(raw, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateV8Config(migrated); err != nil {
				t.Fatal(err)
			}
			restored, err := ParseConfigBytes(migrated)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored.Meta.PromptCacheKey, want) {
				t.Fatalf("migration changed the setting: %+v", restored.Meta.PromptCacheKey)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := SaveConfigPreserveComments(path, cfg, true); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := ParseConfigBytes(saved)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reloaded.Meta.PromptCacheKey, want) {
				t.Fatalf("save/reload changed the setting: %+v\n%s", reloaded.Meta.PromptCacheKey, saved)
			}
		})
	}
}
