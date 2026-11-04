package inputguard

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

const composeSource = "services:\n  proxy:\n    image: '${IMAGE:?required}'\n    environment:\n      TOKEN: '${TOKEN:-offline}'\n      LITERAL: '$$TOKEN'\n    ports: ['127.0.0.1:${PORT:-8317}:8317']\n"

func composeFixture(t *testing.T) (Bundle, map[string]string) {
	t.Helper()
	env := map[string]string{"IMAGE": "synthetic:old"}
	frozen, err := RenderCompose([]byte(composeSource), env, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	bundle := applicationFixture(t, []byte("port: 8317\n"), []byte("port: 8317\n"), nil)
	bundle.ComposeSource = Pair{Before: []byte(composeSource), After: []byte(composeSource), BeforeSHA256: rawHash([]byte(composeSource)), AfterSHA256: rawHash([]byte(composeSource))}
	bundle.FrozenRenderedCompose = Pair{Before: frozen, After: frozen, BeforeSHA256: rawHash(frozen), AfterSHA256: rawHash(frozen)}
	return bundle, env
}

func composeRequest(t *testing.T, bundle Bundle, before, after map[string]string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"schema": "host-recovery-compose-request-v1", "renderer": ComposeRenderer,
		"project_name": "recovery-test", "inputs": json.RawMessage(applicationRequest(t, bundle)),
		"before_environment": before, "after_environment": after})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestComposeCanonicalInterpolationSchemaAndDefaults(t *testing.T) {
	t.Setenv("TOKEN", "host-value-must-not-be-read")
	rendered, err := RenderCompose([]byte(composeSource), map[string]string{"IMAGE": "synthetic:old"}, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	// Expected normalized fields are written independently of RenderCompose.
	var model map[string]any
	if err := json.Unmarshal(rendered, &model); err != nil {
		t.Fatal(err)
	}
	proxy := model["services"].(map[string]any)["proxy"].(map[string]any)
	env := proxy["environment"].(map[string]any)
	port := proxy["ports"].([]any)[0].(map[string]any)
	if model["name"] != "recovery-test" || proxy["image"] != "synthetic:old" || env["TOKEN"] != "offline" || env["LITERAL"] != "$TOKEN" ||
		port["target"] != float64(8317) || port["published"] != "8317" || port["host_ip"] != "127.0.0.1" || port["protocol"] != "tcp" {
		t.Fatalf("incorrect synthetic canonical model: %s", rendered)
	}
	if bytes.Contains(rendered, []byte("host-value-must-not-be-read")) {
		t.Fatal("ambient environment leaked")
	}
}

func TestComposeSimpleIndependentFrozenModel(t *testing.T) {
	rendered, err := RenderCompose([]byte("services: {proxy: {image: '${IMAGE:?required}'}}"), map[string]string{"IMAGE": "synthetic:old"}, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte(`{"name":"recovery-test","networks":{"default":{"name":"recovery-test_default"}},"services":{"proxy":{"image":"synthetic:old","networks":{"default":null}}}}`)
	actualHash, err := SemanticHash(rendered)
	expectedHash, errExpected := SemanticHash(expected)
	if err != nil || errExpected != nil || actualHash != expectedHash {
		t.Fatalf("unexpected synthetic model: %s", rendered)
	}
}

func TestComposeRejectsUnsupportedAndInvalidSources(t *testing.T) {
	for name, source := range map[string]string{
		"duplicate":         "services: {proxy: {image: one, image: two}}",
		"anchor":            "services: {proxy: &base {image: one}}",
		"multidoc":          "services: {proxy: {image: one}}\n---\nservices: {}",
		"include":           "include: [/never-read-this]\nservices: {proxy: {image: one}}",
		"remote":            "include: [https://invalid.test/never]\nservices: {}",
		"extends":           "services: {proxy: {extends: {file: /never-read-this, service: x}}}",
		"env-file":          "services: {proxy: {image: one, env_file: /never-read-this}}",
		"labels-file":       "services: {proxy: {image: one, label_file: /never-read-this}}",
		"build":             "services: {proxy: {build: /never-read-this}}",
		"hidden":            "x-hidden: {env_file: /never-read-this}\nservices: {proxy: {image: one}}",
		"bad-property":      "services: {proxy: {image: one, misspelled: true}}",
		"bad-type":          "services: {proxy: {image: [one]}}",
		"bad-port":          "services: {proxy: {image: one, ports: [bad-port]}}",
		"name-replaced":     "name: other\nservices: {proxy: {image: one}}",
		"missing-variable":  "services: {proxy: {image: '${NOT_PRESENT}'}}",
		"required-variable": "services: {proxy: {image: '${NOT_PRESENT:?reason-secret}'}}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderCompose([]byte(source), map[string]string{}, "recovery-test"); err != errCompose {
				t.Fatalf("invalid input accepted or diagnostic escaped: %v", err)
			}
		})
	}
}

func TestComposeRefusesNestedFallbackAndUnresolvedPassthrough(t *testing.T) {
	for _, source := range []string{
		"services: {proxy: {image: one, environment: {VALUE: '${ABSENT:-literal}${ALSO_ABSENT}'}}}",
		"services: {proxy: {image: one, environment: {VALUE: '${ABSENT:-$ALSO_ABSENT}'}}}",
		"services: {proxy: {image: one, environment: {VALUE: '${ABSENT:-${ALSO_ABSENT:-nested}}'}}}",
		"services: {proxy: {image: one, environment: [ABSENT]}}",
		"services: {proxy: {image: one, environment: {ABSENT: null}}}",
	} {
		if _, err := RenderCompose([]byte(source), map[string]string{}, "recovery-test"); err != errCompose {
			t.Errorf("unresolved/nested input accepted: %s", source)
		}
	}
	if _, err := RenderCompose([]byte("services: {proxy: {image: one, environment: [PRESENT]}}"), map[string]string{"PRESENT": "explicit"}, "recovery-test"); err != nil {
		t.Fatal("explicit passthrough must resolve")
	}
}

func TestComposeAdjacentFlatExpressionsKeepCanonicalValues(t *testing.T) {
	for _, expression := range []string{"${REGISTRY:-synthetic}/${IMAGE:-old}", "${REGISTRY:-synthetic}/${IMAGE}", "$REGISTRY/${IMAGE}"} {
		raw := []byte("services: {proxy: {image: '" + expression + "'}}")
		result, err := RenderCompose(raw, map[string]string{"REGISTRY": "synthetic", "IMAGE": "old"}, "recovery-test")
		if err != nil || !bytes.Contains(result, []byte(`"image":"synthetic/old"`)) {
			t.Fatalf("valid adjacent flat expressions failed: %s, %v", result, err)
		}
	}
	for _, expression := range []string{"${REGISTRY:-synthetic}/${ABSENT}", "${REGISTRY:-synthetic}/$ABSENT", "${REGISTRY:-synthetic}${ABSENT:?required}"} {
		if _, err := RenderCompose([]byte("services: {proxy: {image: '"+expression+"'}}"), map[string]string{}, "recovery-test"); err != errCompose {
			t.Fatal("missing adjacent variable accepted")
		}
	}
}

func TestComposeClosedEnvironmentAndProjectLimits(t *testing.T) {
	for _, env := range []map[string]string{nil, {"bad-name": "value"}, {"VALUE": "nul\x00"}, {"VALUE": strings.Repeat("v", 4097)}, {"COMPOSE_PROJECT_NAME": "other"}} {
		if _, err := RenderCompose([]byte("services: {proxy: {image: one}}"), env, "recovery-test"); err == nil {
			t.Fatal("bad explicit environment accepted")
		}
	}
	for _, project := range []string{"", "Upper", "../other", strings.Repeat("a", 129)} {
		if _, err := RenderCompose([]byte("services: {proxy: {image: one}}"), map[string]string{}, project); err == nil {
			t.Fatal("bad project identity accepted")
		}
	}
	for _, env := range []string{`{"A":"first","A":"second"}`, `{"A":null}`, `{"A":1}`, `{"A":true}`, `{"A":{}}`, `{"A":"v"} {}`, "A: v"} {
		if _, err := decodeEnvironment([]byte(env)); err == nil {
			t.Fatal("ambiguous environment accepted")
		}
	}
}

func TestComposeExpansionLimit(t *testing.T) {
	source := []byte("services: {proxy: {image: one, environment: {VALUE: '" + strings.Repeat("$EXPAND ", 2048) + "'}}}")
	if _, err := RenderCompose(source, map[string]string{"EXPAND": strings.Repeat("x", 4096)}, "recovery-test"); err != errCompose {
		t.Fatal("oversized expansion accepted")
	}
}

func TestComposeFrozenModelsAreNotReinterpolated(t *testing.T) {
	bundle, env := composeFixture(t)
	if err := VerifyComposeRequest(bytes.NewReader(composeRequest(t, bundle, env, env))); err != nil {
		t.Fatal(err)
	}
	// $$TOKEN renders to a literal $TOKEN; frozen output is compared, never run
	// through the renderer again with a second meaning.
	if !bytes.Contains(bundle.FrozenRenderedCompose.Before, []byte("$TOKEN")) {
		t.Fatal("fixture did not reach literal-dollar case")
	}
}

func TestComposeChecksBothEnvironmentsAndFrozenCorrespondence(t *testing.T) {
	bundle, env := composeFixture(t)
	for _, after := range []bool{false, true} {
		a, b := env, map[string]string{"IMAGE": "synthetic:wrong"}
		if !after {
			a, b = b, a
		}
		if err := VerifyComposeRequest(bytes.NewReader(composeRequest(t, bundle, a, b))); err != errCompose {
			t.Fatal("wrong environment accepted")
		}
	}
	// Even mutually identical and exactly pinned frozen files cannot stand in
	// for a render when their contents did not come from this source.
	bundle.FrozenRenderedCompose = bundle.ComposeSource
	if VerifyApplicationBundle(bundle) != nil {
		t.Fatal("fixture must pass the older gate")
	}
	if err := VerifyComposeRequest(bytes.NewReader(composeRequest(t, bundle, env, env))); err != errCompose {
		t.Fatal("unrendered frozen bytes accepted")
	}
}

func TestComposeAllowsOnlyApprovedImageDelta(t *testing.T) {
	bundle, env := composeFixture(t)
	nextEnv := map[string]string{"IMAGE": "synthetic:new"}
	next, err := RenderCompose(bundle.ComposeSource.After, nextEnv, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	bundle.FrozenRenderedCompose.After = next
	bundle.FrozenRenderedCompose.AfterSHA256 = rawHash(next)
	bundle.FrozenRenderedCompose.Changes = []Change{{Path: []string{"services", "proxy", "image"}, Before: semantic(t, "synthetic:old"), After: semantic(t, "synthetic:new")}}
	if err := VerifyComposeRequest(bytes.NewReader(composeRequest(t, bundle, env, nextEnv))); err != nil {
		t.Fatal(err)
	}
	nextEnv["TOKEN"] = "unapproved-change"
	if err := VerifyComposeRequest(bytes.NewReader(composeRequest(t, bundle, env, nextEnv))); err == nil {
		t.Fatal("unrelated environment mutation accepted")
	}
}

func TestComposeProtocolDowngradeAndSecretFreeReceipt(t *testing.T) {
	bundle, env := composeFixture(t)
	raw := composeRequest(t, bundle, env, env)
	var output bytes.Buffer
	if !ServeCompose(bytes.NewReader(raw), &output) || !strings.Contains(output.String(), `"compose_validated":true`) || !strings.Contains(output.String(), `"start_authorized":false`) {
		t.Fatalf("missing distinct receipt: %s", output.Bytes())
	}
	for _, bad := range [][]byte{applicationRequest(t, bundle), append(raw, raw...),
		bytes.Replace(raw, []byte(ComposeRenderer), []byte("other"), 1),
		bytes.Replace(raw, []byte(`"project_name":`), []byte(`"project_name":"duplicate","project_name":`), 1),
		bytes.Replace(raw, []byte(`"before_environment":`), []byte(`"Before_environment":`), 1)} {
		output.Reset()
		if ServeCompose(bytes.NewReader(bad), &output) || !strings.Contains(output.String(), `"compose_validated":false`) || bytes.Contains(output.Bytes(), []byte("synthetic")) || output.Len() > 256 {
			t.Fatalf("invalid envelope accepted or leaked: %s", output.Bytes())
		}
	}
	if ServeCompose(bytes.NewReader(raw), shortWriter{}) {
		t.Fatal("uncertain receipt write accepted")
	}
	if ServeCompose(io.LimitReader(strings.NewReader("invalid"), 3), io.Discard) {
		t.Fatal("truncated input accepted")
	}
}

func FuzzComposeRendering(f *testing.F) {
	for _, seed := range []string{composeSource, "services: {proxy: {image: one, ports: [8317]}}", "services: {proxy: {image: one, environment: [ABSENT]}}", "services: {}", "include: [https://invalid.test/never]"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		before := append([]byte(nil), raw...)
		model, err := RenderCompose(raw, map[string]string{"IMAGE": "synthetic:old"}, "recovery-test")
		if !bytes.Equal(raw, before) || err != nil && err != errCompose {
			t.Fatal("mutated input or unsafe error")
		}
		if err == nil && (len(model) > maxBytes || !json.Valid(model)) {
			t.Fatal("unbounded or invalid model")
		}
	})
}

func FuzzComposeRequest(f *testing.F) {
	f.Add([]byte(`{"schema":null}`))
	f.Add([]byte(`{"before_environment":{"A":"x","A":"y"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		var output bytes.Buffer
		ServeCompose(bytes.NewReader(raw), &output)
		if output.Len() > 256 || !strings.HasPrefix(output.String(), `{"schema":"host-recovery-compose-result-v1",`) {
			t.Fatal("unbounded or non-protocol output")
		}
	})
}
