package inputguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// RollbackSource identifies the inspected replay layout, not the running image
// or a full rollback application schema. No rollback code is loaded or executed.
const RollbackSource = "b4c6bf0e7a0b610983ad21d343aff6a7bef5fb24"

var (
	errBaseline    = errors.New("recovery-baseline-input-unconfirmed")
	imageReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}@sha256:[0-9a-f]{64}$`)
)

// VerifyBaselineRequest checks restored input semantics separately from candidate
// validation. Raw pins and replay policy require independent authentication. It
// does not inspect mounts, containers, plugin files, readiness or writer fencing.
func VerifyBaselineRequest(reader io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes {
		return errBaseline
	}
	request, err := exactObject(raw, "schema", "config", "compose_source", "frozen_rendered_compose", "environment", "policy")
	if err != nil {
		return errBaseline
	}
	var schema string
	if json.Unmarshal(request["schema"], &schema) != nil || schema != "host-recovery-baseline-input-v1" {
		return errBaseline
	}
	inputs := make(map[string][]byte, 3)
	for _, name := range []string{"config", "compose_source", "frozen_rendered_compose"} {
		fields, err := exactObject(request[name], "bytes", "sha256")
		if err != nil {
			return errBaseline
		}
		var text, pin string
		if json.Unmarshal(fields["bytes"], &text) != nil || len(text) > base64.StdEncoding.EncodedLen(maxBytes) ||
			json.Unmarshal(fields["sha256"], &pin) != nil || !validHash(pin) {
			return errBaseline
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != text || rawHash(decoded) != pin {
			return errBaseline
		}
		if _, err := parse(decoded, true); err != nil {
			return errBaseline
		}
		inputs[name] = decoded
	}
	policy, err := exactObject(request["policy"], "rollback_source", "renderer", "project_name", "replay_sha256", "service", "image")
	if err != nil {
		return errBaseline
	}
	values := make(map[string]string, len(policy))
	for name, raw := range policy {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return errBaseline
		}
		values[name] = text
	}
	if values["rollback_source"] != RollbackSource || values["renderer"] != ComposeRenderer ||
		!validHash(values["replay_sha256"]) || !imageReference.MatchString(values["image"]) ||
		values["service"] == "" || len(values["service"]) > 128 {
		return errBaseline
	}
	config, err := parse(inputs["config"], true)
	if err != nil || config.Mapping["plugins"] != nil {
		return errBaseline // This version supports the original no-plugin baseline only.
	}
	legacy := config.Mapping["meta"]
	var canonical *value
	if upstream := config.Mapping["upstream"]; upstream != nil {
		if upstream.Kind != "map" {
			return errBaseline
		}
		canonical = upstream.Mapping["meta"]
	}
	if (legacy == nil) == (canonical == nil) {
		return errBaseline // Do not guess precedence between legacy and canonical layouts.
	}
	meta := legacy
	if canonical != nil {
		meta = canonical
	}
	if meta.Kind != "map" || len(meta.Mapping) != 1 {
		return errBaseline
	}
	replay := meta.Mapping["reasoning-replay"]
	if replay == nil || replay.Kind != "map" || replay.Mapping["enabled"] == nil ||
		replay.Mapping["enabled"].Kind != "!!bool" || hashValue(replay) != values["replay_sha256"] {
		return errBaseline
	}
	for name, field := range replay.Mapping {
		switch name {
		case "enabled":
		case "models":
			if field.Kind != "sequence" || len(field.Sequence) > 256 {
				return errBaseline
			}
			for _, model := range field.Sequence {
				if model.Kind != "!!str" || len(model.Scalar) > 1024 {
					return errBaseline
				}
			}
		default:
			return errBaseline
		}
	}
	environment, err := decodeEnvironment(request["environment"])
	if err != nil {
		return errBaseline
	}
	rendered, err := RenderCompose(inputs["compose_source"], environment, values["project_name"])
	if err != nil || Verify(rendered, inputs["frozen_rendered_compose"], nil) != nil {
		return errBaseline
	}
	model, err := parse(rendered, true)
	if err != nil {
		return errBaseline
	}
	services := model.Mapping["services"]
	if services == nil || services.Kind != "map" {
		return errBaseline
	}
	service := services.Mapping[values["service"]]
	if service == nil || service.Kind != "map" {
		return errBaseline
	}
	image := service.Mapping["image"]
	if image == nil || image.Kind != "!!str" || image.Scalar != values["image"] {
		return errBaseline
	}
	return nil
}

// ServeBaseline emits only fixed facts about these input bytes. In particular a
// successful receipt cannot replace the independent stopped/running-state oracle.
func ServeBaseline(reader io.Reader, writer io.Writer) bool {
	matched := VerifyBaselineRequest(reader) == nil
	line := []byte("{\"schema\":\"host-recovery-baseline-input-result-v1\",\"baseline_inputs_validated\":false,\"start_authorized\":false}\n")
	if matched {
		line = bytes.Replace(line, []byte("validated\":false"), []byte("validated\":true"), 1)
	}
	n, err := writer.Write(line)
	return matched && err == nil && n == len(line)
}
