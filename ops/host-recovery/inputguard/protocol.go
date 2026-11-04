package inputguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// MaxRequestBytes bounds six base64-encoded YAML documents and their policy.
// This is an input bound, not a hard parser memory or execution-time guarantee.
const MaxRequestBytes = 36 << 20

var errProtocol = errors.New("recovery-input-request-invalid")

// VerifyRequest consumes one exact JSON request from a restricted byte transport.
// It never opens files, renders inputs, authenticates policy or authorizes a start.
// Duplicate, unknown, differently cased and missing fields are all refused.
func VerifyRequest(reader io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes {
		return errProtocol
	}
	request, err := exactObject(raw, "schema", "config", "compose_source", "frozen_rendered_compose")
	if err != nil {
		return errProtocol
	}
	var schema string
	if json.Unmarshal(request["schema"], &schema) != nil || schema != "host-recovery-input-request-v1" {
		return errProtocol
	}
	var bundle Bundle
	for name, pair := range map[string]*Pair{
		"config": &bundle.Config, "compose_source": &bundle.ComposeSource,
		"frozen_rendered_compose": &bundle.FrozenRenderedCompose,
	} {
		if err := decodePair(request[name], pair); err != nil {
			return errProtocol
		}
	}
	return VerifyBundle(bundle)
}

// exactObject checks keys before decoding values; encoding/json's usual struct
// decoding accepts duplicate and case-insensitive keys, which is inappropriate here.
func exactObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errProtocol
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	result := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || result[key] != nil {
			return nil, errProtocol
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errProtocol
		}
		result[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || len(result) != len(keys) {
		return nil, errProtocol
	}
	var extra json.RawMessage
	if decoder.Decode(&extra) != io.EOF {
		return nil, errProtocol
	}
	return result, nil
}

func decodePair(raw []byte, pair *Pair) error {
	fields, err := exactObject(raw, "before", "after", "before_sha256", "after_sha256", "changes")
	if err != nil {
		return errProtocol
	}
	for name, dest := range map[string]*[]byte{"before": &pair.Before, "after": &pair.After} {
		var text string
		if json.Unmarshal(fields[name], &text) != nil || len(text) > base64.StdEncoding.EncodedLen(maxBytes) {
			return errProtocol
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
			return errProtocol
		}
		*dest = decoded
	}
	if json.Unmarshal(fields["before_sha256"], &pair.BeforeSHA256) != nil ||
		json.Unmarshal(fields["after_sha256"], &pair.AfterSHA256) != nil {
		return errProtocol
	}
	var changes []json.RawMessage
	if json.Unmarshal(fields["changes"], &changes) != nil || len(changes) > 256 {
		return errProtocol
	}
	for _, rawChange := range changes {
		fields, err := exactObject(rawChange, "path", "before", "after")
		if err != nil {
			return errProtocol
		}
		var change Change
		if json.Unmarshal(fields["path"], &change.Path) != nil ||
			json.Unmarshal(fields["before"], &change.Before) != nil ||
			json.Unmarshal(fields["after"], &change.After) != nil {
			return errProtocol
		}
		pair.Changes = append(pair.Changes, change)
	}
	return nil
}

// Serve writes one fixed, secret-free receipt, including on invalid input. A true
// result means comparison only, never schema approval, rendering or start authority.
func Serve(reader io.Reader, writer io.Writer) bool {
	matched := VerifyRequest(reader) == nil
	line := "{\"schema\":\"host-recovery-input-result-v1\",\"matched\":false,\"start_authorized\":false}\n"
	if matched {
		line = "{\"schema\":\"host-recovery-input-result-v1\",\"matched\":true,\"start_authorized\":false}\n"
	}
	n, err := io.WriteString(writer, line)
	return matched && err == nil && n == len(line)
}
