package inputguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/template"
	"github.com/compose-spec/compose-go/v2/types"
)

// ComposeRenderer identifies this deliberately restricted model renderer, not the
// Docker CLI's config command. Changing its dependency/options changes the pin.
const ComposeRenderer = "compose-go/v2@v2.16.2:single-file-model-v1"

const maxEnvironmentBytes = 64 << 10

var (
	errCompose             = errors.New("recovery-input-compose-unconfirmed")
	projectNamePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
	environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// The pinned upstream pattern greedily includes adjacent braced expressions,
	// then recursively substitutes the suffix without our strict callbacks. For
	// this flat-expression subset, each match must end at its first closing brace.
	flatTemplatePattern = regexp.MustCompile(strings.Replace(template.DefaultPattern.String(), "(.*)", "([^}]*)", 1))
)

// RenderCompose uses compose-go's real interpolation, schema, canonicalization,
// defaults and model normalization with an explicit closed environment. It never
// loads a file, .env, daemon, plugin or remote resource. Inputs using multi-file
// features are rejected, not silently skipped. Output contains restricted values;
// only the fixed verification receipt may cross the public transport boundary.
func RenderCompose(raw []byte, environment map[string]string, projectName string) ([]byte, error) {
	if !projectNamePattern.MatchString(projectName) || validateEnvironment(environment) != nil {
		return nil, errCompose
	}
	parsed, err := parse(raw, true)
	if err != nil {
		return nil, errCompose
	}
	if err := closedCompose(parsed); err != nil {
		return nil, errCompose
	}
	if name := parsed.Mapping["name"]; name != nil && (name.Kind != "!!str" || name.Scalar != projectName) {
		return nil, errCompose
	}
	if name, present := environment["COMPOSE_PROJECT_NAME"]; present && name != projectName {
		return nil, errCompose
	}
	// Pass the strict parser's values, never parse the original YAML a second time
	// under a more permissive dialect. Config is non-nil, so loader cannot read it.
	config := nativeCompose(parsed).(map[string]any)
	env := types.Mapping{}
	for name, value := range environment {
		env[name] = value
	}
	expanded, exhausted := 0, false
	model, err := loader.LoadModelWithContext(context.Background(), types.ConfigDetails{
		WorkingDir: "/", Environment: env,
		ConfigFiles: []types.ConfigFile{{Filename: "recovery-input", Config: config}},
	}, func(options *loader.Options) {
		options.SetProjectName(projectName, true)
		options.ResolvePaths = false
		options.SkipNormalization = true
		options.SkipInclude = true
		options.SkipExtends = true
		options.Interpolate.LookupValue = func(name string) (string, bool) {
			value, present := env[name]
			expanded += len(value)
			if expanded > maxBytes {
				exhausted = true
				return "", false
			}
			return value, present
		}
		options.Interpolate.Substitute = func(text string, mapping template.Mapping) (string, error) {
			return template.SubstituteWithOptions(text, mapping, template.WithoutLogging, template.WithPattern(flatTemplatePattern),
				template.WithReplacementFunction(func(part string, mapping template.Mapping, cfg *template.Config) (string, error) {
					result, applied, err := template.DefaultReplacementAppliedFunc(part, mapping, cfg)
					if err != nil || !applied {
						return "", errCompose
					}
					return result, nil
				}))
		}
	})
	if err != nil || exhausted {
		return nil, errCompose
	}
	// Inspect pass-through entries BEFORE Normalize can erase unresolved list
	// values. A later runtime must not supply uncaptured environment values.
	for _, section := range []string{"services", "jobs"} {
		if services, ok := model[section].(map[string]any); ok {
			for _, service := range services {
				if fields, ok := service.(map[string]any); ok {
					switch environment := fields["environment"].(type) {
					case map[string]any:
						for name, value := range environment {
							if value == nil {
								resolved, present := env[name]
								if !present {
									return nil, errCompose
								}
								environment[name] = resolved
							}
						}
					case []any:
						for _, entry := range environment {
							text, ok := entry.(string)
							if !ok || !strings.Contains(text, "=") {
								return nil, errCompose
							}
						}
					}
				}
			}
		}
	}
	for _, section := range []string{"configs", "secrets"} {
		if resources, ok := config[section].(map[string]any); ok {
			for _, resource := range resources {
				if fields, ok := resource.(map[string]any); ok && fields["environment"] != nil {
					return nil, errCompose // Resource environment loading is outside this version.
				}
			}
		}
	}
	model["name"] = projectName
	model, err = loader.Normalize(model, env)
	if err != nil {
		return nil, errCompose
	}
	result, err := json.Marshal(model)
	if err != nil || len(result) > maxBytes {
		return nil, errCompose
	}
	// Apply the same depth/node/type bounds to expansion and normalization output.
	if _, err := parse(result, true); err != nil {
		return nil, errCompose
	}
	return result, nil
}

// Conservative exclusions are recursive, including extension maps: unsupported
// features cannot hide in a future library extension or a hook's file loader.
func closedCompose(v *value) error {
	// compose-go's nested default substitution does not inherit the outer strict
	// missing-variable callback. This version supports literal defaults only.
	if v.Kind == "!!str" {
		text := v.Scalar
		for {
			start := strings.Index(text, "${")
			if start < 0 {
				break
			}
			text = text[start+2:]
			end := strings.IndexByte(text, '}')
			if end < 0 || strings.ContainsRune(text[:end], '$') {
				return errCompose
			}
			text = text[end+1:]
		}
	}
	for key, child := range v.Mapping {
		switch key {
		case "include", "extends", "env_file", "label_file", "build":
			return errCompose
		}
		if err := closedCompose(child); err != nil {
			return err
		}
	}
	for _, child := range v.Sequence {
		if err := closedCompose(child); err != nil {
			return err
		}
	}
	return nil
}

func nativeCompose(v *value) any {
	switch v.Kind {
	case "map":
		result := make(map[string]any, len(v.Mapping))
		for key, child := range v.Mapping {
			result[key] = nativeCompose(child)
		}
		return result
	case "sequence":
		result := make([]any, 0, len(v.Sequence))
		for _, child := range v.Sequence {
			result = append(result, nativeCompose(child))
		}
		return result
	case "!!null":
		return nil
	case "!!bool":
		return v.Scalar == "true"
	case "!!int":
		n, _ := strconv.ParseInt(v.Scalar, 10, 64) // Already checked by parse.
		return n
	case "!!float":
		n, _ := strconv.ParseFloat(v.Scalar, 64)
		return n
	default:
		return v.Scalar
	}
}

func validateEnvironment(environment map[string]string) error {
	if environment == nil || len(environment) > 256 {
		return errCompose
	}
	size := 0
	for key, value := range environment {
		size += len(key) + len(value)
		if !environmentNamePattern.MatchString(key) || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || len(value) > 4096 {
			return errCompose
		}
	}
	if size > maxEnvironmentBytes {
		return errCompose
	}
	return nil
}

func decodeEnvironment(raw []byte) (map[string]string, error) {
	if len(raw) > maxEnvironmentBytes {
		return nil, errCompose
	}
	parsed, err := parse(raw, true)
	if err != nil || !json.Valid(raw) {
		return nil, errCompose
	}
	result := make(map[string]string, len(parsed.Mapping))
	for key, child := range parsed.Mapping {
		if child.Kind != "!!str" {
			return nil, errCompose
		}
		result[key] = child.Scalar
	}
	return result, validateEnvironment(result)
}

// VerifyComposeRequest adds fresh rendering of BOTH source snapshots and comparison
// to their frozen models to exact-delta and host application validation. The entire
// envelope, environments and renderer identity need independent approval and a
// protected same-lock capture; this function authenticates none of those roles.
func VerifyComposeRequest(reader io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes {
		return errCompose
	}
	request, err := exactObject(raw, "schema", "renderer", "project_name", "inputs", "before_environment", "after_environment")
	if err != nil {
		return errCompose
	}
	var schema, renderer, projectName string
	if json.Unmarshal(request["schema"], &schema) != nil || schema != "host-recovery-compose-request-v1" ||
		json.Unmarshal(request["renderer"], &renderer) != nil || renderer != ComposeRenderer ||
		json.Unmarshal(request["project_name"], &projectName) != nil {
		return errCompose
	}
	bundle, err := decodeRequest(bytes.NewReader(request["inputs"]))
	if err != nil || VerifyApplicationBundle(bundle) != nil {
		return errCompose
	}
	for _, side := range []struct {
		name           string
		source, frozen []byte
	}{
		{"before", bundle.ComposeSource.Before, bundle.FrozenRenderedCompose.Before},
		{"after", bundle.ComposeSource.After, bundle.FrozenRenderedCompose.After},
	} {
		env, err := decodeEnvironment(request[side.name+"_environment"])
		if err != nil {
			return errCompose
		}
		rendered, err := RenderCompose(side.source, env, projectName)
		if err != nil {
			return errCompose
		}
		expected, err := SemanticHash(side.frozen)
		actual, errHash := SemanticHash(rendered)
		if err != nil || errHash != nil || expected != actual {
			return errCompose
		}
	}
	return nil
}

// ServeCompose never emits a model, environment, schema diagnostic or source path.
func ServeCompose(reader io.Reader, writer io.Writer) bool {
	validated := VerifyComposeRequest(reader) == nil
	line := "{\"schema\":\"host-recovery-compose-result-v1\",\"matched\":false,\"application_validated\":false,\"compose_validated\":false,\"start_authorized\":false}\n"
	if validated {
		line = "{\"schema\":\"host-recovery-compose-result-v1\",\"matched\":true,\"application_validated\":true,\"compose_validated\":true,\"start_authorized\":false}\n"
	}
	n, err := io.WriteString(writer, line)
	return validated && err == nil && n == len(line)
}
