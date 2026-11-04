package inputguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const baselineConfig = "meta: {reasoning-replay: {enabled: true, models: ['muse-spark-*']}}\n"

func baselineRequest(t *testing.T) map[string]any {
	t.Helper()
	image := "synthetic.example/proxy@sha256:" + strings.Repeat("a", 64)
	frozen := `{"name":"recovery-test","networks":{"default":{"name":"recovery-test_default"}},"services":{"proxy":{"image":"` + image + `","networks":{"default":null}}}}`
	request := map[string]any{"schema": "host-recovery-baseline-input-v1",
		"environment": map[string]string{"IMAGE": image},
		"policy": map[string]string{"rollback_source": RollbackSource, "renderer": ComposeRenderer,
			"project_name": "recovery-test", "service": "proxy", "image": image,
			"replay_sha256": semantic(t, "{enabled: true, models: ['muse-spark-*']}")}}
	setBaselineInput(request, "config", []byte(baselineConfig))
	setBaselineInput(request, "compose_source", []byte("services: {proxy: {image: '${IMAGE:?required}'}}"))
	setBaselineInput(request, "frozen_rendered_compose", []byte(frozen))
	return request
}

func setBaselineInput(request map[string]any, name string, raw []byte) {
	request[name] = map[string]string{"bytes": base64.StdEncoding.EncodeToString(raw), "sha256": rawHash(raw)}
}

func encodeBaseline(t *testing.T, request map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBaselineOriginalReplayLayoutsAndFrozenImage(t *testing.T) {
	for _, config := range []string{baselineConfig, "upstream:\n  meta: {reasoning-replay: {enabled: true, models: ['muse-spark-*']}}\n"} {
		request := baselineRequest(t)
		setBaselineInput(request, "config", []byte(config))
		raw := encodeBaseline(t, request)
		var output bytes.Buffer
		if !ServeBaseline(bytes.NewReader(raw), &output) || output.String() != "{\"schema\":\"host-recovery-baseline-input-result-v1\",\"baseline_inputs_validated\":true,\"start_authorized\":false}\n" {
			t.Fatalf("valid restored inputs refused: %s", output.String())
		}
	}
}

func TestBaselineSemanticFailuresDespiteMatchingRawPins(t *testing.T) {
	for name, config := range map[string]string{
		"disabled":               strings.Replace(baselineConfig, "true", "false", 1),
		"wrong-model":            strings.Replace(baselineConfig, "muse-spark-*", "unapproved", 1),
		"plugin":                 baselineConfig + "plugins: {enabled: true, configs: {meta: {enabled: true}}}\n",
		"disabled-plugin-stanza": baselineConfig + "plugins: {enabled: false}\n",
		"ambiguous-layout":       baselineConfig + "upstream: {meta: {reasoning-replay: {enabled: false}}}\n",
		"wrong-replay-location":  "replay: {enabled: true}\n",
		"duplicate":              baselineConfig + baselineConfig,
		"anchor":                 "meta: &m {reasoning-replay: {enabled: true}}\n",
		"multidoc":               baselineConfig + "---\nport: 8317\n",
		"scalar-meta":            "meta: false\n",
		"scalar-upstream":        "upstream: false\n" + baselineConfig,
	} {
		t.Run(name, func(t *testing.T) {
			request := baselineRequest(t)
			setBaselineInput(request, "config", []byte(config)) // Synthetic approval reaches semantic checks.
			if VerifyBaselineRequest(bytes.NewReader(encodeBaseline(t, request))) == nil {
				t.Fatal("semantic baseline mismatch accepted")
			}
		})
	}
}

func TestBaselineReplayShapeNotJustApprovedHash(t *testing.T) {
	for _, replay := range []string{"{enabled: 'true'}", "{enabled: 1}", "{}", "{enabled: true, models: [1]}",
		"{enabled: true, models: null}", "{enabled: true, extra: true}", "{enabled: true, models: ['" + strings.Repeat("a", 1025) + "']}"} {
		request := baselineRequest(t)
		setBaselineInput(request, "config", []byte("meta: {reasoning-replay: "+replay+"}"))
		request["policy"].(map[string]string)["replay_sha256"] = semantic(t, replay)
		if VerifyBaselineRequest(bytes.NewReader(encodeBaseline(t, request))) == nil {
			t.Fatal("unsupported replay shape accepted")
		}
	}
}

func TestBaselineComposeMustRenderAndMatchFrozenImage(t *testing.T) {
	for _, source := range []string{"services: {proxy: {image: mutable:tag}}", "services: {other: {image: '${IMAGE}'}}",
		"services: {proxy: {image: '${UNCAPTURED}'}}", "include: [/never-read]\nservices: {proxy: {image: '${IMAGE}'}}",
		"services: {proxy: {image: '${IMAGE}', env_file: /never-read}}"} {
		request := baselineRequest(t)
		setBaselineInput(request, "compose_source", []byte(source))
		if VerifyBaselineRequest(bytes.NewReader(encodeBaseline(t, request))) == nil {
			t.Fatal("incorrect/unsupported baseline Compose accepted")
		}
	}
	request := baselineRequest(t)
	setBaselineInput(request, "frozen_rendered_compose", []byte("services: {proxy: {image: mutable:tag}}"))
	if VerifyBaselineRequest(bytes.NewReader(encodeBaseline(t, request))) == nil {
		t.Fatal("wrong frozen model accepted")
	}
}

func TestBaselinePolicyIdentityAndDigestPins(t *testing.T) {
	for key, value := range map[string]string{"rollback_source": strings.Repeat("b", 40), "renderer": "unapproved",
		"project_name": "../wrong", "replay_sha256": strings.Repeat("0", 64), "service": "missing", "image": "mutable:tag"} {
		request := baselineRequest(t)
		request["policy"].(map[string]string)[key] = value
		if VerifyBaselineRequest(bytes.NewReader(encodeBaseline(t, request))) == nil {
			t.Fatalf("incorrect policy %s accepted", key)
		}
	}
	for _, role := range []string{"config", "compose_source", "frozen_rendered_compose"} {
		request := baselineRequest(t)
		request[role].(map[string]string)["sha256"] = strings.Repeat("0", 64)
		if VerifyBaselineRequest(bytes.NewReader(encodeBaseline(t, request))) == nil {
			t.Fatal("raw pin mismatch accepted")
		}
	}
}

func TestBaselineStrictProtocolAndSecretFreeRefusal(t *testing.T) {
	raw := encodeBaseline(t, baselineRequest(t))
	for _, bad := range [][]byte{nil, []byte(`{"secret":"not-receipted"}`), append(append([]byte{}, raw...), raw...),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`"environment":{`), []byte(`"environment":{"IMAGE":"duplicate",`), 1),
		bytes.Replace(raw, []byte(`"bytes":`), []byte(`"bytes":null,"bytes":`), 1),
		bytes.Replace(raw, []byte(`"policy":{`), []byte(`"policy":{"unexpected":true,`), 1)} {
		var output bytes.Buffer
		if ServeBaseline(bytes.NewReader(bad), &output) || output.String() != "{\"schema\":\"host-recovery-baseline-input-result-v1\",\"baseline_inputs_validated\":false,\"start_authorized\":false}\n" {
			t.Fatal("protocol refusal was not fixed and secret-free")
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic-transport-failure") }

func TestBaselineServeWriteFailuresRefuse(t *testing.T) {
	raw := encodeBaseline(t, baselineRequest(t))
	if ServeBaseline(bytes.NewReader(raw), shortWriter{}) || ServeBaseline(bytes.NewReader(raw), failingWriter{}) {
		t.Fatal("failed receipt write accepted")
	}
}

func FuzzBaselineNeverAcceptsUnknownProtocol(f *testing.F) {
	f.Add([]byte(`{"schema":"unknown"}`))
	f.Add([]byte(`{"schema":"host-recovery-baseline-input-v1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var output bytes.Buffer
		accepted := ServeBaseline(bytes.NewReader(raw), &output)
		if accepted && VerifyBaselineRequest(bytes.NewReader(raw)) != nil {
			t.Fatal("serve accepted invalid input")
		}
		if bytes.Contains(output.Bytes(), []byte(`"start_authorized":true`)) {
			t.Fatal("input verification granted startup")
		}
	})
}
