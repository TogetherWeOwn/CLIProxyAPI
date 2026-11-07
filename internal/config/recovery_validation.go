package config

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var errRecoveryConfig = errors.New("recovery-config-invalid")

// ValidateRecoveryConfigBytes checks host-owned config types and intrinsic
// validators without loading files, resolving paths, hashing secrets, sanitizing,
// logging or persisting. Callers must first enforce their strict YAML subset and
// byte/node bounds. Legacy and v8 layouts are supported, but mixed layouts refuse.
// Plugin-owned options remain opaque: this is not plugin schema validation,
// authenticated policy, rendering, operational readiness or permission to start.
func ValidateRecoveryConfigBytes(data []byte) error {
	if len(data) == 0 || len(data) > 4<<20 {
		return errRecoveryConfig
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc, extra yaml.Node
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 || decoder.Decode(&extra) != io.EOF {
		return errRecoveryConfig
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return errRecoveryConfig
	}
	flat := root
	if IsV8ConfigLayout(root) {
		if ValidateV8Config(data) != nil || !recoveryAPIKeyGroups(root) {
			return errRecoveryConfig
		}
		var err error
		flat, err = flattenV8(root)
		if err != nil {
			return errRecoveryConfig
		}
		deleteYAMLPath(flat, "config-version")
		// Match the existing v8 validator's removal of structural containers,
		// not arbitrary empty user maps such as plugin options or headers.
		for _, path := range v8Paths {
			parts := strings.Split(path.current, ".")
			for end := len(parts) - 1; end > 0; end-- {
				container := strings.Join(parts[:end], ".")
				if value := yamlPath(flat, container); value != nil && value.Kind == yaml.MappingNode && len(value.Content) == 0 {
					deleteYAMLPath(flat, container)
				}
			}
		}
	}
	// KnownFields alone is insufficient: custom UnmarshalYAML implementations
	// call Node.Decode, losing its setting. Walk the actual declared field types
	// before invoking those same runtime decoders, including their custom scalars.
	if !recoveryConfigShape(flat, reflect.TypeOf(legacyConfig{}), 0) || validateCredentialWeightYAML(data) != nil {
		return errRecoveryConfig
	}
	cfg := Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
	decoded := legacyConfig(cfg)
	if flat.Decode(&decoded) != nil {
		return errRecoveryConfig
	}
	cfg = Config(decoded)
	if cfg.Models.Validate() != nil || validateTrustedProxies(cfg.TrustedProxies) != nil ||
		cfg.CredentialInFlight.Validate() != nil || cfg.ValidateCredentialWeights() != nil ||
		ValidateCredentialConcurrency(cfg.CredentialConcurrency.WithDefaults()) != nil || cfg.Codex.LiveMediaRelay.Validate() != nil ||
		cfg.Client.Codex.WebSearchResultCache.Validate() != nil {
		return errRecoveryConfig
	}
	return nil
}

// Validate each source group and key before expansion: empty key lists, per-key
// overrides and skipped nulls must not conceal mistyped/unknown source fields.
func recoveryAPIKeyGroups(root *yaml.Node) bool {
	providers := yamlPath(root, "api-keys")
	if providers == nil {
		return true
	}
	if providers.Kind != yaml.MappingNode {
		return false
	}
	fields := make(map[string]reflect.Type)
	recoveryConfigFields(reflect.TypeOf(legacyConfig{}), fields)
	for _, family := range v8KeyFamilies {
		groups := yamlPath(providers, family.current)
		if groups == nil {
			continue
		}
		if groups.Kind != yaml.SequenceNode {
			return false
		}
		typ := fields[family.old].Elem()
		for _, group := range groups.Content {
			if group.Kind != yaml.MappingNode {
				return false
			}
			if family.current == "openai-compatibility" {
				if yamlPath(group, "api-key-entries") != nil {
					return false
				}
				copy := deepCopyNode(group)
				keys := yamlPath(copy, "keys")
				if keys == nil {
					return false
				}
				deleteYAMLPath(copy, "keys")
				setYAMLPath(copy, "api-key-entries", keys)
				if !recoveryConfigShape(copy, typ, 0) {
					return false
				}
				continue
			}
			groupFields := make(map[string]reflect.Type)
			recoveryConfigFields(typ, groupFields)
			for i := 0; i < len(group.Content); i += 2 {
				key, node := group.Content[i].Value, group.Content[i+1]
				switch key {
				case "name":
					if !recoveryConfigShape(node, reflect.TypeOf(""), 0) {
						return false
					}
				case "keys":
					if !recoveryConfigShape(node, reflect.SliceOf(typ), 0) {
						return false
					}
				default:
					field, ok := groupFields[key]
					if !ok || !recoveryConfigShape(node, field, 0) {
						return false
					}
				}
			}
		}
	}
	return true
}

func recoveryConfigShape(node *yaml.Node, typ reflect.Type, depth int) bool {
	if node == nil || depth > 64 || node.Alias != nil || node.Anchor != "" || node.Tag == "!!null" {
		return false
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(time.Duration(0)) {
		return node.Kind == yaml.ScalarNode && node.Tag == "!!str"
	}
	if typ == reflect.TypeOf(DisableImageGenerationMode(0)) {
		var mode DisableImageGenerationMode
		return node.Decode(&mode) == nil
	}
	if typ == reflect.TypeOf(CodexWebSearchResultCacheConfig{}) {
		// This strict custom decoder supports both duration strings and integer seconds.
		var cache CodexWebSearchResultCacheConfig
		return node.Decode(&cache) == nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode || node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return false
		}
		fields := make(map[string]reflect.Type)
		recoveryConfigFields(typ, fields)
		plugin := typ == reflect.TypeOf(PluginInstanceConfig{})
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
			field, ok := fields[key.Value]
			if !ok {
				if plugin {
					continue // Only enabled/priority are host-owned; never invent a plugin schema.
				}
				return false
			}
			if !recoveryConfigShape(node.Content[i+1], field, depth+1) {
				return false
			}
		}
		return true
	case reflect.Map:
		if node.Kind != yaml.MappingNode || node.Tag != "!!map" || len(node.Content)%2 != 0 || typ.Key().Kind() != reflect.String {
			return false
		}
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] || !recoveryConfigShape(node.Content[i+1], typ.Elem(), depth+1) {
				return false
			}
			seen[key.Value] = true
		}
		return true
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode || node.Tag != "!!seq" {
			return false
		}
		for _, item := range node.Content {
			if !recoveryConfigShape(item, typ.Elem(), depth+1) {
				return false
			}
		}
		return true
	case reflect.Interface:
		return true // Payload maps are intentionally open; strict YAML is the caller's prerequisite.
	case reflect.String:
		return node.Kind == yaml.ScalarNode && node.Tag == "!!str"
	case reflect.Bool:
		return node.Kind == yaml.ScalarNode && node.Tag == "!!bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return node.Kind == yaml.ScalarNode && node.Tag == "!!int"
	case reflect.Float32, reflect.Float64:
		return node.Kind == yaml.ScalarNode && (node.Tag == "!!float" || node.Tag == "!!int")
	default:
		return false
	}
}

func recoveryConfigFields(typ reflect.Type, fields map[string]reflect.Type) {
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tags := strings.Split(field.Tag.Get("yaml"), ",")
		if tags[0] == "-" {
			continue
		}
		if len(tags) > 1 && tags[1] == "inline" && field.Type.Kind() == reflect.Struct {
			recoveryConfigFields(field.Type, fields)
			continue
		}
		key := tags[0]
		if key == "" {
			key = strings.ToLower(field.Name)
		}
		fields[key] = field.Type
	}
}
