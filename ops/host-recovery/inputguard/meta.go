package inputguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// MetaConfigProfile binds a conservative projection of the reviewed producer's
// config.go, not a loaded library, artifact identity or replay-behavior assertion.
const MetaConfigProfile = "meta@c54c8c86989032f269ebfb49e95c6fb16fb9f2db:config.go@4665020ba0b2688dda79578f3f8717878a50212c8fd092f856c728c563ddbfd8:strict-replay-v1"

var errMeta = errors.New("recovery-input-meta-config-unconfirmed")

// validateMetaConfig checks the pinned producer's only plugin-owned option:
// reasoning-replay {enabled: bool, models: []string}. The source parser ignores
// decode errors, so accepting its returned zero value would not validate input.
// This version refuses unknown fields, nulls and coercions instead. Host-owned
// enabled/priority are already checked by VerifyApplicationBundle. Store metadata
// and future plugin options need a separately reviewed profile, not a bypass.
func validateMetaConfig(raw []byte, candidate bool) error {
	root, err := parse(raw, true)
	if err != nil {
		return errMeta
	}
	plugins := root.Mapping["plugins"]
	var item *value
	if plugins != nil && plugins.Kind == "map" {
		if configs := plugins.Mapping["configs"]; configs != nil && configs.Kind == "map" {
			item = configs.Mapping["meta"]
		}
	}
	if candidate && (plugins == nil || !trueValue(plugins.Mapping["enabled"]) || item == nil) {
		return errMeta
	}
	if item == nil {
		return nil // The baseline may have no Meta plugin.
	}
	if item.Kind != "map" || (candidate && !trueValue(item.Mapping["enabled"])) {
		return errMeta
	}
	for name, field := range item.Mapping {
		switch name {
		case "enabled":
			if field.Kind != "!!bool" {
				return errMeta
			}
		case "priority":
			if field.Kind != "!!int" {
				return errMeta
			}
		case "reasoning-replay":
			if field.Kind != "map" {
				return errMeta
			}
			for key, option := range field.Mapping {
				switch key {
				case "enabled":
					if option.Kind != "!!bool" {
						return errMeta
					}
				case "models":
					if option.Kind != "sequence" {
						return errMeta
					}
					for _, model := range option.Sequence {
						if model.Kind != "!!str" {
							return errMeta
						}
					}
				default:
					return errMeta
				}
			}
		default:
			return errMeta
		}
	}
	return nil
}

func trueValue(v *value) bool {
	return v != nil && v.Kind == "!!bool" && v.Scalar == "true"
}

// VerifyMetaRequest composes the source-pinned Meta shape with all existing
// application, exact-delta and restricted Compose model checks. It authenticates
// neither the policy nor which installed artifact owns the selected subtree.
// Replay enablement/pattern preservation and full approved stanza still require
// the independently authenticated exact-input policy; schema shape is not policy.
func VerifyMetaRequest(reader io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes {
		return errMeta
	}
	request, err := exactObject(raw, "schema", "producer_config", "inputs")
	if err != nil {
		return errMeta
	}
	var schema, profile string
	if json.Unmarshal(request["schema"], &schema) != nil || schema != "host-recovery-meta-input-request-v1" ||
		json.Unmarshal(request["producer_config"], &profile) != nil || profile != MetaConfigProfile ||
		VerifyComposeRequest(bytes.NewReader(request["inputs"])) != nil {
		return errMeta
	}
	compose, err := exactObject(request["inputs"], "schema", "renderer", "project_name", "inputs", "before_environment", "after_environment")
	if err != nil {
		return errMeta
	}
	bundle, err := decodeRequest(bytes.NewReader(compose["inputs"]))
	if err != nil || validateMetaConfig(bundle.Config.Before, false) != nil || validateMetaConfig(bundle.Config.After, true) != nil {
		return errMeta
	}
	return nil
}

// ServeMeta emits only a fixed receipt. A valid shape does not prove migration
// policy, producer execution, replay/drain completeness or permission to start.
func ServeMeta(reader io.Reader, writer io.Writer) bool {
	validated := VerifyMetaRequest(reader) == nil
	line := "{\"schema\":\"host-recovery-meta-input-result-v1\",\"matched\":false,\"application_validated\":false,\"compose_validated\":false,\"meta_config_validated\":false,\"start_authorized\":false}\n"
	if validated {
		line = "{\"schema\":\"host-recovery-meta-input-result-v1\",\"matched\":true,\"application_validated\":true,\"compose_validated\":true,\"meta_config_validated\":true,\"start_authorized\":false}\n"
	}
	n, err := io.WriteString(writer, line)
	return validated && err == nil && n == len(line)
}
