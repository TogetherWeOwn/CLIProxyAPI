// Package inputguard compares bounded YAML inputs against exact approved changes.
// Optional application and Compose checks validate host config types and pinned
// single-file Compose model correspondence, not plugin options. No check
// authenticates approval, acquires protected files or grants mutation/start authority.
package inputguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

const (
	maxBytes = 4 << 20
	maxNodes = 65536
	maxDepth = 64
)

var (
	errInput    = errors.New("recovery-input-unsupported-yaml")
	errPolicy   = errors.New("recovery-input-exact-policy-required")
	errMismatch = errors.New("recovery-input-policy-mismatch")
	integer     = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	number      = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
)

// Change binds one exact mapping path to its old and new semantic hashes. An
// empty hash means absent, not null. Paths never index sequences or use wildcards.
// Hashes must be approved independently, not learned from the candidate input.
// Changes may add/remove a subtree but cannot overlap or exclude a whole document.
type Change struct {
	Path   []string
	Before string
	After  string
}

// Pair includes raw-byte pins as well as semantic changes. A formatting-only
// difference still needs its own approved raw pin. Pins establish correspondence,
// not approval authority. Inputs must be acquired through the protected boundary.
type Pair struct {
	Before       []byte
	After        []byte
	BeforeSHA256 string
	AfterSHA256  string
	Changes      []Change
}

// Bundle requires all three independent comparisons. FrozenRenderedCompose must
// contain actual captured render bytes; this API does not run a renderer or prove
// tool/interpolation identity, nor does it prove application/plugin schema validity.
type Bundle struct {
	Config                Pair
	ComposeSource         Pair
	FrozenRenderedCompose Pair
}

type value struct {
	Kind     string            `json:"kind"`
	Scalar   string            `json:"scalar,omitempty"`
	Mapping  map[string]*value `json:"mapping,omitempty"`
	Sequence []*value          `json:"sequence,omitempty"`
}

// VerifyBundle validates every raw pin and exact delta before returning success.
// It returns no parsed values, paths or source text suitable for secret leakage.
func VerifyBundle(bundle Bundle) error {
	for _, pair := range []Pair{bundle.Config, bundle.ComposeSource, bundle.FrozenRenderedCompose} {
		if !validHash(pair.BeforeSHA256) || !validHash(pair.AfterSHA256) {
			return errPolicy
		}
		if rawHash(pair.Before) != pair.BeforeSHA256 || rawHash(pair.After) != pair.AfterSHA256 {
			return errMismatch
		}
		if err := Verify(pair.Before, pair.After, pair.Changes); err != nil {
			return err
		}
	}
	return nil
}

// SemanticHash hashes a single supported YAML document, including its value types.
// It is a provisioning aid only: computing a hash never authenticates its approval.
func SemanticHash(raw []byte) (string, error) {
	parsed, err := parse(raw, false)
	if err != nil {
		return "", err
	}
	return hashValue(parsed), nil
}

// Verify accepts only the listed exact changes and preserves every unrelated
// subtree, including other plugin/alias entries and every other service's image.
// An unchanged listed path is refused; there are no wildcard or ignore regions.
func Verify(before, after []byte, changes []Change) error {
	if len(changes) > 256 {
		return errPolicy
	}
	for i, change := range changes {
		if len(change.Path) == 0 || len(change.Path) > maxDepth || change.Before == change.After ||
			(change.Before != "" && !validHash(change.Before)) || (change.After != "" && !validHash(change.After)) {
			return errPolicy
		}
		for _, key := range change.Path {
			if key == "" || key == "<<" || len(key) > 1024 {
				return errPolicy
			}
		}
		for _, prior := range changes[:i] {
			if prefix(change.Path, prior.Path) || prefix(prior.Path, change.Path) {
				return errPolicy
			}
		}
	}
	old, err := parse(before, true)
	if err != nil {
		return err
	}
	candidate, err := parse(after, true)
	if err != nil {
		return err
	}
	for _, change := range changes {
		oldParent, oldOK := parent(old, change.Path)
		newParent, newOK := parent(candidate, change.Path)
		if !oldOK || !newOK {
			return errMismatch
		}
		key := change.Path[len(change.Path)-1]
		oldValue, newValue := oldParent.Mapping[key], newParent.Mapping[key]
		if optionalHash(oldValue) != change.Before || optionalHash(newValue) != change.After {
			return errMismatch
		}
		if newValue == nil {
			delete(oldParent.Mapping, key)
		} else {
			oldParent.Mapping[key] = newValue
		}
	}
	if hashValue(old) != hashValue(candidate) {
		return errMismatch
	}
	return nil
}

func parent(root *value, path []string) (*value, bool) {
	for _, key := range path[:len(path)-1] {
		if root == nil || root.Kind != "map" {
			return nil, false
		}
		root = root.Mapping[key]
	}
	return root, root != nil && root.Kind == "map"
}

func prefix(first, second []string) bool {
	if len(first) > len(second) {
		return false
	}
	for i, key := range first {
		if key != second[i] {
			return false
		}
	}
	return true
}

func optionalHash(v *value) string {
	if v == nil {
		return ""
	}
	return hashValue(v)
}

func hashValue(v *value) string {
	// value contains only bounded UTF-8 strings, maps and slices; marshaling it
	// cannot fail. Map keys are sorted by encoding/json for stable correspondence.
	raw, _ := json.Marshal(v)
	return rawHash(raw)
}

func rawHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func parse(raw []byte, mapping bool) (*value, error) {
	if len(raw) == 0 || len(raw) > maxBytes {
		return nil, errInput
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil || len(doc.Content) != 1 {
		return nil, errInput
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errInput
	}
	count := 0
	result, err := convert(doc.Content[0], 0, &count)
	if err != nil || mapping && result.Kind != "map" {
		return nil, errInput
	}
	return result, nil
}

func convert(node *yaml.Node, depth int, count *int) (*value, error) {
	*count++
	if depth > maxDepth || *count > maxNodes || node.Anchor != "" || node.Alias != nil {
		return nil, errInput
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, errInput
		}
		v := &value{Kind: "map", Mapping: make(map[string]*value)}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			*count++
			if *count > maxNodes || key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" ||
				key.Value == "" || key.Value == "<<" || v.Mapping[key.Value] != nil {
				return nil, errInput
			}
			child, err := convert(node.Content[i+1], depth+1, count)
			if err != nil {
				return nil, err
			}
			v.Mapping[key.Value] = child
		}
		return v, nil
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, errInput
		}
		v := &value{Kind: "sequence"}
		for _, nodeChild := range node.Content {
			child, err := convert(nodeChild, depth+1, count)
			if err != nil {
				return nil, err
			}
			v.Sequence = append(v.Sequence, child)
		}
		return v, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			// yaml.v3 resolves overflowing plain floats as strings. Refuse that
			// fallback; a numeric-looking string needs quotes or an explicit tag.
			if node.Style == 0 && number.MatchString(node.Value) {
				return nil, errInput
			}
		case "!!bool":
			if node.Value != "true" && node.Value != "false" {
				return nil, errInput
			}
		case "!!null":
			if node.Value != "null" {
				return nil, errInput
			}
		case "!!int":
			if !integer.MatchString(node.Value) {
				return nil, errInput
			}
			if _, err := strconv.ParseInt(node.Value, 10, 64); err != nil {
				return nil, errInput
			}
		case "!!float":
			if !number.MatchString(node.Value) {
				return nil, errInput
			}
			if _, err := strconv.ParseFloat(node.Value, 64); err != nil {
				return nil, errInput
			}
		default:
			return nil, errInput
		}
		return &value{Kind: node.Tag, Scalar: node.Value}, nil
	default:
		return nil, errInput
	}
}
