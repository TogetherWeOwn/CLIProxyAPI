package inputguard

import (
	"strings"
	"testing"
)

func semantic(t *testing.T, raw string) string {
	t.Helper()
	sum, err := SemanticHash([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func TestExactChangesPreserveUnrelatedMapsAndImages(t *testing.T) {
	before := []byte(`plugins:
  other: {path: keep, enabled: true}
aliases:
  untouched: model-a
  selected: old-model
services:
  proxy: {image: old-image, restart: "no"}
  unrelated: {image: keep-image}
replay: {enabled: true}
`)
	after := []byte(`plugins:
  other: {path: keep, enabled: true}
  meta: {path: pinned-library, enabled: true}
aliases:
  untouched: model-a
  selected: new-model
services:
  proxy: {image: new-image, restart: "no"}
  unrelated: {image: keep-image}
`)
	changes := []Change{
		{Path: []string{"plugins", "meta"}, After: semantic(t, "{path: pinned-library, enabled: true}")},
		{Path: []string{"aliases", "selected"}, Before: semantic(t, "old-model"), After: semantic(t, "new-model")},
		{Path: []string{"services", "proxy", "image"}, Before: semantic(t, "old-image"), After: semantic(t, "new-image")},
		{Path: []string{"replay"}, Before: semantic(t, "{enabled: true}")},
	}
	if err := Verify(before, after, changes); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][2]string{
		{"path: keep", "path: changed"},
		{"untouched: model-a", "untouched: other-model"},
		{"image: keep-image", "image: changed-image"},
		{"restart: \"no\"", "restart: always"},
		{"path: pinned-library", "path: wrong-library"},
	} {
		t.Run(replacement[0], func(t *testing.T) {
			changed := []byte(strings.Replace(string(after), replacement[0], replacement[1], 1))
			if err := Verify(before, changed, changes); err != errMismatch {
				t.Fatalf("unapproved delta accepted: %v", err)
			}
		})
	}
}

func TestExactPolicyCanBeReversedWithoutIgnoringAddedPluginOrReplay(t *testing.T) {
	before := []byte("plugins: {other: keep}\nreplay: {enabled: true}\n")
	after := []byte("plugins: {other: keep, meta: {path: pinned}}\n")
	changes := []Change{
		{Path: []string{"plugins", "meta"}, After: semantic(t, "{path: pinned}")},
		{Path: []string{"replay"}, Before: semantic(t, "{enabled: true}")},
	}
	if err := Verify(before, after, changes); err != nil {
		t.Fatal(err)
	}
	reverse := make([]Change, len(changes))
	for i, change := range changes {
		reverse[i] = Change{Path: change.Path, Before: change.After, After: change.Before}
	}
	if err := Verify(after, before, reverse); err != nil {
		t.Fatal(err)
	}
	if err := Verify(after, []byte("plugins: {other: keep, meta: {path: pinned}}\nreplay: {enabled: true}\n"), reverse); err != errMismatch {
		t.Fatalf("plugin retained through reversal: %v", err)
	}
	if err := Verify(after, []byte("plugins: {other: keep}\nreplay: {enabled: false}\n"), reverse); err != errMismatch {
		t.Fatalf("wrong original replay restored: %v", err)
	}
}

func TestNineAliasesAreExactPathsNotAMapExclusion(t *testing.T) {
	var before, after strings.Builder
	before.WriteString("aliases:\n")
	after.WriteString("aliases:\n")
	changes := make([]Change, 0, 9)
	for i := range 9 {
		key := "selected-" + string(rune('a'+i))
		before.WriteString("  " + key + ": old\n")
		after.WriteString("  " + key + ": new\n")
		changes = append(changes, Change{Path: []string{"aliases", key}, Before: semantic(t, "old"), After: semantic(t, "new")})
	}
	before.WriteString("  unrelated: keep\n")
	after.WriteString("  unrelated: keep\n")
	if err := Verify([]byte(before.String()), []byte(after.String()), changes); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte(before.String()), []byte(after.String()+"  extra: smuggled\n"), changes); err != errMismatch {
		t.Fatalf("unexpected alias accepted: %v", err)
	}
}

func TestFormattingAndMappingOrderAreNotSemanticChanges(t *testing.T) {
	if err := Verify([]byte("a: hello\nb: [1, true, null]\n"), []byte("# comment\nb: [1,true,null]\na: 'hello'\n"), nil); err != nil {
		t.Fatal(err)
	}
}

func TestValueTypesAndSequenceOrderRemainSignificant(t *testing.T) {
	for _, pair := range [][2]string{
		{"v: 1", "v: '1'"}, {"v: true", "v: 'true'"}, {"v: null", "v: 'null'"},
		{"v: {}", "v: []"}, {"v: [a, b]", "v: [b, a]"}, {"v: 1", "v: 1.0"},
		{"v: null", "{}"}, {"v: a", "v: b"},
	} {
		t.Run(pair[1], func(t *testing.T) {
			if err := Verify([]byte(pair[0]), []byte(pair[1]), nil); err != errMismatch {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestAbsentAndExplicitNullHaveDifferentPolicies(t *testing.T) {
	null := semantic(t, "null")
	if err := Verify([]byte("{}"), []byte("v: null"), []Change{{Path: []string{"v"}, After: null}}); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte("v: null"), []byte("v: yes"), []Change{{Path: []string{"v"}, After: semantic(t, "yes")}}); err != errMismatch {
		t.Fatalf("absence matched null: %v", err)
	}
}

func TestStrictYAMLRejectsAmbiguityAndUnsupportedFeatures(t *testing.T) {
	inputs := []string{
		"", "\n", "# empty\n", "v: [", "v: 1\n---\nv: 1", "v: 1\n---\n",
		"v: 1\nv: 1", "v: {x: a, x: b}", "'v': a\n\"v\": b", "{1: a}", "{true: a}",
		"v: &owned value", "v: &owned {x: a}\nw: *owned", "v: *missing",
		"base: &base {x: a}\nv: {<<: *base}", "v: {'<<': {x: a}}", "v: !custom a",
		"v: !!binary YQ==", "v: 2026-11-04", "v: 01", "v: 0x10", "v: 1_000", "v: -0",
		"v: .nan", "v: .inf", "v: 1e9999", "v: 9223372036854775808", "v: True", "v: ~", "v:", "'': a",
		"v: !!int wrong", "v: !!float wrong", "v: !custom {x: a}", "v: !custom [a]",
	}
	for _, raw := range inputs {
		t.Run(raw, func(t *testing.T) {
			if _, err := SemanticHash([]byte(raw)); err != errInput {
				t.Fatalf("unsupported input accepted: %v", err)
			}
			if err := Verify([]byte(raw), []byte("v: valid"), nil); err != errInput {
				t.Fatalf("invalid original accepted: %v", err)
			}
			if err := Verify([]byte("v: valid"), []byte(raw), nil); err != errInput {
				t.Fatalf("invalid candidate accepted: %v", err)
			}
		})
	}
}

func TestSubsetSupportsTypedJSONNumbersAndExplicitStrings(t *testing.T) {
	for _, raw := range []string{"v: -23", "v: 0", "v: 1.25", "v: 1.25e-4", "v: !!str 01", "v: '2026-11-04'", "v: '1e9999'", "v: !!str 1e9999"} {
		if err := Verify([]byte(raw), []byte(raw), nil); err != nil {
			t.Fatalf("supported input refused: %v", err)
		}
	}
}

func TestComparisonRequiresMappingRoots(t *testing.T) {
	for _, raw := range []string{"value", "[a, b]", "null"} {
		if err := Verify([]byte(raw), []byte(raw), nil); err != errInput {
			t.Fatalf("nonmapping root accepted: %v", err)
		}
	}
}

func TestPolicyRejectsOverlapAndMalformedPins(t *testing.T) {
	a, b := semantic(t, "a"), semantic(t, "b")
	for _, changes := range [][]Change{
		{{Before: a, After: b}},
		{{Path: []string{"v"}}},
		{{Path: []string{"v"}, Before: a, After: a}},
		{{Path: []string{"v"}, Before: "not-a-hash", After: b}},
		{{Path: []string{"v"}, Before: a, After: strings.ToUpper(b)}},
		{{Path: []string{""}, Before: a, After: b}},
		{{Path: []string{"<<"}, Before: a, After: b}},
		{{Path: []string{"v"}, Before: a, After: b}, {Path: []string{"v"}, Before: a, After: b}},
		{{Path: []string{"v"}, Before: a, After: b}, {Path: []string{"v", "child"}, Before: a, After: b}},
		{{Path: []string{"v", "child"}, Before: a, After: b}, {Path: []string{"v"}, Before: a, After: b}},
		{{Path: make([]string, maxDepth+1), Before: a, After: b}},
		make([]Change, 257),
	} {
		if err := Verify([]byte("v: a"), []byte("v: b"), changes); err != errPolicy {
			t.Fatalf("malformed policy accepted: %v", err)
		}
	}
}

func TestMissingParentAndSequenceTraversalRefuse(t *testing.T) {
	for _, path := range [][]string{{"missing", "v"}, {"v", "0"}, {"scalar", "child"}} {
		if err := Verify([]byte("v: [a]\nscalar: a"), []byte("v: [b]\nscalar: b"), []Change{
			{Path: path, Before: semantic(t, "a"), After: semantic(t, "b")},
		}); err != errMismatch {
			t.Fatalf("invalid parent accepted: %v", err)
		}
	}
}

func TestOldValuePinIsRequiredAndCannotBeReplacedByCandidatePin(t *testing.T) {
	for _, old := range []string{"", semantic(t, "b"), semantic(t, "wrong")} {
		if err := Verify([]byte("v: a"), []byte("v: b"), []Change{
			{Path: []string{"v"}, Before: old, After: semantic(t, "b")},
		}); err == nil {
			t.Fatal("unapproved baseline accepted")
		}
	}
}

func TestLiteralPathKeysAreNotDottedPathsOrWildcards(t *testing.T) {
	change := Change{Path: []string{"a.b", "*"}, Before: semantic(t, "old"), After: semantic(t, "new")}
	before := []byte("a.b: {'*': old}\na: {b: keep}")
	after := []byte("a.b: {'*': new}\na: {b: keep}")
	if err := Verify(before, after, []Change{change}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(before, []byte("a.b: {'*': new}\na: {b: changed}"), []Change{change}); err != errMismatch {
		t.Fatal("literal path became exclusion")
	}
}

func TestByteDepthAndNodeBounds(t *testing.T) {
	for _, raw := range []string{
		"v: " + strings.Repeat("s", maxBytes),
		"v: " + strings.Repeat("[", maxDepth+1) + "a" + strings.Repeat("]", maxDepth+1),
		"v: [" + strings.Repeat("a,", maxNodes) + "a]",
	} {
		if _, err := SemanticHash([]byte(raw)); err != errInput {
			t.Fatalf("bound not enforced: %v", err)
		}
	}
}

func TestBundleRequiresIndependentSourceAndFrozenRenderPins(t *testing.T) {
	pair := func(before, after string, changes []Change) Pair {
		return Pair{Before: []byte(before), After: []byte(after), BeforeSHA256: rawHash([]byte(before)),
			AfterSHA256: rawHash([]byte(after)), Changes: changes}
	}
	bundle := Bundle{
		Config: pair("plugins: {}", "plugins: {meta: {enabled: true}}", []Change{
			{Path: []string{"plugins", "meta"}, After: semantic(t, "{enabled: true}")},
		}),
		ComposeSource: pair("services: {proxy: {image: '${IMAGE}'}}", "services: {proxy: {image: '${IMAGE}'}}", nil),
		FrozenRenderedCompose: pair("services: {proxy: {image: old}}", "services: {proxy: {image: new}}", []Change{
			{Path: []string{"services", "proxy", "image"}, Before: semantic(t, "old"), After: semantic(t, "new")},
		}),
	}
	if err := VerifyBundle(bundle); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"config", "source", "rendered"} {
		for _, tamper := range []string{"before", "after", "missing", "malformed"} {
			t.Run(role+"-"+tamper, func(t *testing.T) {
				changed := bundle
				p := &changed.Config
				if role == "source" {
					p = &changed.ComposeSource
				} else if role == "rendered" {
					p = &changed.FrozenRenderedCompose
				}
				switch tamper {
				case "before":
					p.Before = append([]byte("# new formatting\n"), p.Before...)
				case "after":
					p.After = append([]byte("# new formatting\n"), p.After...)
				case "missing":
					*p = Pair{}
				case "malformed":
					p.AfterSHA256 = "not-a-pin"
				}
				if err := VerifyBundle(changed); err == nil {
					t.Fatal("unproven source/render input accepted")
				}
			})
		}
	}
	changed := bundle
	changed.FrozenRenderedCompose.After = []byte("services: {proxy: {image: wrong}}")
	changed.FrozenRenderedCompose.AfterSHA256 = rawHash(changed.FrozenRenderedCompose.After)
	if err := VerifyBundle(changed); err != errMismatch {
		t.Fatal("raw pin substituted for exact approved semantic delta")
	}
}

func TestErrorsNeverExposeInputOrPaths(t *testing.T) {
	for _, raw := range []string{"private-value: [", "private-value: a\nprivate-value: b", "private-value: wrong"} {
		err := Verify([]byte("v: original"), []byte(raw), nil)
		if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "original") {
			t.Fatalf("secret-bearing error: %v", err)
		}
	}
}

func FuzzVerifyIdenticalInput(f *testing.F) {
	for _, raw := range []string{"v: true", "v: [a, 1, null]", "v: {x: a}", "a: 1\na: 2", "v: &a [*a]", ""} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := parse(raw, true)
		got := Verify(raw, raw, nil)
		if (err == nil) != (got == nil) {
			t.Fatalf("identical-input mismatch: parse=%v verify=%v", err, got)
		}
	})
}
