package inputguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func requestFixture(t *testing.T) []byte {
	t.Helper()
	before, after := []byte("selected: old\nunrelated: keep\n"), []byte("selected: new\nunrelated: keep\n")
	oldHash, _ := SemanticHash([]byte("old"))
	newHash, _ := SemanticHash([]byte("new"))
	pair := map[string]any{
		"before": base64.StdEncoding.EncodeToString(before), "after": base64.StdEncoding.EncodeToString(after),
		"before_sha256": rawHash(before), "after_sha256": rawHash(after),
		"changes": []any{map[string]any{"path": []string{"selected"}, "before": oldHash, "after": newHash}},
	}
	raw, err := json.Marshal(map[string]any{"schema": "host-recovery-input-request-v1",
		"config": pair, "compose_source": pair, "frozen_rendered_compose": pair})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRequestExactBundle(t *testing.T) {
	raw := requestFixture(t)
	var output bytes.Buffer
	if !Serve(bytes.NewReader(raw), &output) || output.String() != "{\"schema\":\"host-recovery-input-result-v1\",\"matched\":true,\"start_authorized\":false}\n" {
		t.Fatalf("comparison receipt missing: %q", output.String())
	}
}

func TestRequestProtocolRefusals(t *testing.T) {
	good := string(requestFixture(t))
	for name, raw := range map[string]string{
		"empty": "", "array": "[]", "null": "null", "trailing": good + "{}",
		"duplicate-root":   strings.Replace(good, "{", "{\"schema\":\"host-recovery-input-request-v1\",", 1),
		"case-root":        strings.Replace(good, "\"config\":", "\"Config\":", 1),
		"unknown-root":     strings.Replace(good, "{", "{\"secret-unknown-field\":1,", 1),
		"missing-role":     strings.Replace(good, "\"config\":", "\"unused\":", 1),
		"schema":           strings.Replace(good, "host-recovery-input-request-v1", "other", 1),
		"null-pair":        strings.Replace(good, "\"config\":{", "\"config\":null,\"unused\":{", 1),
		"duplicate-pair":   strings.Replace(good, "\"config\":{", "\"config\":{\"changes\":[],", 1),
		"case-pair":        strings.Replace(good, "\"before_sha256\":", "\"Before_sha256\":", 1),
		"duplicate-change": strings.Replace(good, "\"path\":[", "\"before\":\"\",\"path\":[", 1),
		"unknown-change":   strings.Replace(good, "\"path\":[", "\"unknown\":true,\"path\":[", 1),
		"null-changes":     strings.Replace(good, "\"changes\":[", "\"changes\":null,\"unused\":[", 1),
		"null-path":        strings.Replace(good, "\"path\":[\"selected\"]", "\"path\":null", 1),
		"unbounded-change": strings.Replace(good, "\"path\":[\"selected\"]", "\"path\":[]", 1),
		"not-base64":       strings.Replace(good, "\"before\":\"c2", "\"before\":\"!2", 1),
		"null-pin":         strings.Replace(good, "\"before_sha256\":\"", "\"unused\":\"", 1),
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if Serve(strings.NewReader(raw), &output) {
				t.Fatal("invalid protocol accepted")
			}
			if output.String() != "{\"schema\":\"host-recovery-input-result-v1\",\"matched\":false,\"start_authorized\":false}\n" {
				t.Fatal("rejection receipt changed or exposed input")
			}
		})
	}
}

func TestRequestEveryRoleAndRawPin(t *testing.T) {
	for _, role := range []string{"config", "compose_source", "frozen_rendered_compose"} {
		for _, field := range []string{"before_sha256", "after_sha256", "after"} {
			t.Run(role+"/"+field, func(t *testing.T) {
				var request map[string]any
				if err := json.Unmarshal(requestFixture(t), &request); err != nil {
					t.Fatal(err)
				}
				pair := request[role].(map[string]any)
				pair[field] = strings.Repeat("0", 64)
				raw, _ := json.Marshal(request)
				if VerifyRequest(bytes.NewReader(raw)) == nil {
					t.Fatal("role pin or YAML mismatch accepted")
				}
			})
		}
	}
}

func TestRequestNullAndMistypedFields(t *testing.T) {
	for _, role := range []string{"config", "compose_source", "frozen_rendered_compose"} {
		for _, field := range []string{"pair", "before", "after", "before_sha256", "after_sha256", "changes", "path", "change_before", "change_after"} {
			for _, invalid := range []any{nil, false} {
				var request map[string]any
				if err := json.Unmarshal(requestFixture(t), &request); err != nil {
					t.Fatal(err)
				}
				pair := request[role].(map[string]any)
				switch field {
				case "pair":
					request[role] = invalid
				case "path", "change_before", "change_after":
					change := pair["changes"].([]any)[0].(map[string]any)
					change[strings.TrimPrefix(field, "change_")] = invalid
				default:
					pair[field] = invalid
				}
				raw, _ := json.Marshal(request)
				if err := VerifyRequest(bytes.NewReader(raw)); err == nil {
					t.Fatalf("null or mistyped %s/%s accepted", role, field)
				}
			}
		}
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("secret-storage-error") }

type shortWriter struct{}

func (shortWriter) Write(raw []byte) (int, error) { return len(raw) - 1, nil }

func TestRequestBoundsAndTransportErrors(t *testing.T) {
	for _, reader := range []io.Reader{failedReader{}, strings.NewReader(strings.Repeat(" ", MaxRequestBytes+1))} {
		if err := VerifyRequest(reader); err != errProtocol {
			t.Fatal("transport error must be a fixed protocol refusal")
		}
	}
	if Serve(bytes.NewReader(requestFixture(t)), shortWriter{}) {
		t.Fatal("short receipt write accepted")
	}
}

func TestRequestCanonicalBase64(t *testing.T) {
	good := string(requestFixture(t))
	// The standard decoder ignores CR/LF; the protocol must not accept this alias.
	if err := VerifyRequest(strings.NewReader(strings.Replace(good, "c2Vs", "c2\\nVs", 1))); err != errProtocol {
		t.Fatal("noncanonical base64 accepted")
	}
}

func FuzzVerifyRequest(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("{\"schema\":null}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		var result bytes.Buffer
		Serve(bytes.NewReader(raw), &result)
		if !strings.HasPrefix(result.String(), "{\"schema\":\"host-recovery-input-result-v1\",") || result.Len() > 128 {
			t.Fatal("unbounded or unstructured receipt")
		}
	})
}
