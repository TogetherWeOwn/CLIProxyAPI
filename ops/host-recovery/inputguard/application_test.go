package inputguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func applicationFixture(t *testing.T, before, after []byte, changes []Change) Bundle {
	t.Helper()
	unchanged := []byte("services: {proxy: {image: 'synthetic@sha256:abc'}}\n")
	pair := Pair{Before: unchanged, After: unchanged, BeforeSHA256: rawHash(unchanged), AfterSHA256: rawHash(unchanged)}
	return Bundle{Config: Pair{Before: before, After: after, BeforeSHA256: rawHash(before), AfterSHA256: rawHash(after), Changes: changes},
		ComposeSource: pair, FrozenRenderedCompose: pair}
}

func applicationRequest(t *testing.T, bundle Bundle) []byte {
	t.Helper()
	request := map[string]any{"schema": "host-recovery-input-request-v1"}
	for role, pair := range map[string]Pair{"config": bundle.Config, "compose_source": bundle.ComposeSource, "frozen_rendered_compose": bundle.FrozenRenderedCompose} {
		changes := make([]any, 0, len(pair.Changes))
		for _, change := range pair.Changes {
			changes = append(changes, map[string]any{"path": change.Path, "before": change.Before, "after": change.After})
		}
		request[role] = map[string]any{"before": base64.StdEncoding.EncodeToString(pair.Before), "after": base64.StdEncoding.EncodeToString(pair.After),
			"before_sha256": pair.BeforeSHA256, "after_sha256": pair.AfterSHA256, "changes": changes}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestApplicationBundleChecksBothLayoutsAndIndependentExactDeltas(t *testing.T) {
	old, next := semantic(t, "8317"), semantic(t, "8318")
	bundle := applicationFixture(t, []byte("port: 8317\n"), []byte("port: 8318\n"), []Change{{Path: []string{"port"}, Before: old, After: next}})
	if err := VerifyApplicationBundle(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Config.After = []byte("port: 8318\ndebug: true\n")
	bundle.Config.AfterSHA256 = rawHash(bundle.Config.After)
	if err := VerifyApplicationBundle(bundle); err != errMismatch {
		t.Fatalf("unapproved but valid config accepted: %v", err)
	}
	for _, raw := range []string{"config-version: 8\nserver: {port: 8317}\n", "port: 8317\nplugins: {enabled: false}\n"} {
		value := []byte(raw)
		if err := VerifyApplicationBundle(applicationFixture(t, value, value, nil)); err != nil {
			t.Fatalf("valid layout refused: %v", err)
		}
	}
}

func TestApplicationRefusesPinnedInvalidOriginalAndCandidate(t *testing.T) {
	good := []byte("port: 8317\n")
	for _, bad := range []string{"secret-value", "'8317'"} {
		for _, after := range []bool{false, true} {
			before, candidate := good, []byte("port: "+bad+"\n")
			if !after {
				before, candidate = candidate, before
			}
			left, _ := parse(before, true)
			right, _ := parse(candidate, true)
			changes := []Change{{Path: []string{"port"}, Before: optionalHash(left.Mapping["port"]), After: optionalHash(right.Mapping["port"])}}
			bundle := applicationFixture(t, before, candidate, changes)
			if err := VerifyBundle(bundle); err != nil {
				t.Fatalf("exact comparison must reach schema check: %v", err)
			}
			if err := VerifyApplicationBundle(bundle); err != errApplication {
				t.Fatalf("valid other side concealed invalid config: %v", err)
			}
		}
	}
	for _, bad := range []string{"plugins: {configs: {meta: false}}\n", "config-version: 8\ncredentials: {concurrency: {secret-unknown: 1}}\n"} {
		bundle := applicationFixture(t, []byte(bad), []byte(bad), nil)
		if VerifyBundle(bundle) != nil || VerifyApplicationBundle(bundle) != errApplication {
			t.Fatal("pinned unchanged invalid config accepted")
		}
	}
}

func TestApplicationStillRequiresEveryComposeAndRawPin(t *testing.T) {
	good := []byte("port: 8317\n")
	for _, role := range []string{"config", "compose", "render"} {
		bundle := applicationFixture(t, good, good, nil)
		pair := map[string]*Pair{"config": &bundle.Config, "compose": &bundle.ComposeSource, "render": &bundle.FrozenRenderedCompose}[role]
		pair.AfterSHA256 = strings.Repeat("0", 64)
		if VerifyApplicationBundle(bundle) == nil {
			t.Fatalf("%s raw pin not checked", role)
		}
	}
}

func TestApplicationReceiptAndProtocolRefusals(t *testing.T) {
	good := []byte("port: 8317\n")
	raw := applicationRequest(t, applicationFixture(t, good, good, nil))
	var output bytes.Buffer
	if !ServeApplication(bytes.NewReader(raw), &output) || output.String() != "{\"schema\":\"host-recovery-application-input-result-v1\",\"matched\":true,\"application_validated\":true,\"start_authorized\":false}\n" {
		t.Fatalf("application receipt: %s", output.String())
	}
	for _, reader := range []io.Reader{failedReader{}, strings.NewReader("{}"), bytes.NewReader(requestFixture(t)),
		strings.NewReader(strings.Replace(string(raw), "\"config\":", "\"Config\":", 1)),
		strings.NewReader(strings.Repeat(" ", MaxRequestBytes+1))} {
		output.Reset()
		if ServeApplication(reader, &output) || output.String() != "{\"schema\":\"host-recovery-application-input-result-v1\",\"matched\":false,\"application_validated\":false,\"start_authorized\":false}\n" {
			t.Fatal("refusal changed or leaked input")
		}
	}
	if ServeApplication(bytes.NewReader(raw), shortWriter{}) {
		t.Fatal("short application receipt write accepted")
	}
}

func TestApplicationOpaquePluginOptionsAreNotPluginSchemaAcceptance(t *testing.T) {
	raw := []byte("plugins: {enabled: true, configs: {meta: {enabled: true, not-a-proven-plugin-option: [1, 2]}}}\n")
	if err := VerifyApplicationBundle(applicationFixture(t, raw, raw, nil)); err != nil {
		t.Fatal("host cannot invent the plugin-owned schema")
	}
}

func FuzzApplicationConfig(f *testing.F) {
	for _, raw := range []string{"port: 8317\n", "plugins: {configs: {meta: false}}\n", "config-version: 8\napi-keys: {codex: [{base-url: [bad], keys: []}]}\n"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		before := bytes.Clone(raw)
		bundle := applicationFixture(t, raw, raw, nil)
		err := VerifyApplicationBundle(bundle)
		if err != nil && err != errInput && err != errApplication {
			t.Fatalf("unexpected error class: %v", err)
		}
		if !bytes.Equal(raw, before) {
			t.Fatal("validation mutated source bytes")
		}
	})
}

func FuzzApplicationReceipt(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("{\"schema\":null}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		var output bytes.Buffer
		ServeApplication(bytes.NewReader(raw), &output)
		if !strings.HasPrefix(output.String(), "{\"schema\":\"host-recovery-application-input-result-v1\",") || output.Len() > 256 {
			t.Fatal("unbounded or unstructured receipt")
		}
	})
}
