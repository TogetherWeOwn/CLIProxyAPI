// Package recoverycorrelation carries untrusted, bounded diagnostic identities.
// These values are never credentials, routing hints, or proof of replay.
package recoverycorrelation

import (
	"context"
	"net/http"
	"strings"
)

const MetadataKey = "cpa_recovery_v1"

const headerPrefix = "x-cpa-recovery-"

var fields = map[string]string{
	"x-cpa-recovery-attempt-id":        "attempt_id",
	"x-cpa-recovery-probe-id":          "probe_id",
	"x-cpa-recovery-request-id":        "request_id",
	"x-cpa-recovery-parent-request-id": "parent_request_id",
	"x-cpa-recovery-turn":              "turn",
}

type contextKey struct{}

type carrier struct {
	attemptID       string
	probeID         string
	requestID       string
	parentRequestID string
	turn            int
}

// Consume removes every diagnostic header, even malformed or unknown ones,
// before logging, auth selection, plugins, or upstream request construction.
// Invalid envelopes are ignored without changing normal HTTP/auth behavior.
func Consume(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	values := make(map[string]string, len(fields))
	valid := true
	for name, entries := range req.Header {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, headerPrefix) {
			continue
		}
		delete(req.Header, name)
		field, allowed := fields[lower]
		if !allowed || len(entries) != 1 {
			valid = false
			continue
		}
		if _, duplicate := values[field]; duplicate {
			valid = false
		}
		values[field] = entries[0]
	}
	// Shadow a parent envelope on reused contexts, including an absent or invalid
	// carrier. Never let stale request identities bleed into another request.
	ctx := context.WithValue(req.Context(), contextKey{}, carrier{})
	if !valid || !identifier(values["attempt_id"]) || !identifier(values["probe_id"]) || !identifier(values["request_id"]) {
		return req.WithContext(ctx)
	}
	c := carrier{attemptID: values["attempt_id"], probeID: values["probe_id"], requestID: values["request_id"], parentRequestID: values["parent_request_id"]}
	switch values["turn"] {
	case "1":
		if c.parentRequestID != "" {
			return req.WithContext(ctx)
		}
		c.turn = 1
	case "2":
		if !identifier(c.parentRequestID) || c.parentRequestID == c.requestID {
			return req.WithContext(ctx)
		}
		c.turn = 2
	default:
		return req.WithContext(ctx)
	}
	return req.WithContext(context.WithValue(ctx, contextKey{}, c))
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := range value {
		ch := value[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		if i > 0 && (ch == '-' || ch == '_' || ch == '.' || ch == ':') {
			continue
		}
		return false
	}
	return true
}

// Metadata returns a fresh JSON-like map for the existing executor/plugin ABI.
// Requested and resolved models remain in their existing separate fields.
func Metadata(ctx context.Context) map[string]any {
	if ctx == nil {
		return nil
	}
	c, ok := ctx.Value(contextKey{}).(carrier)
	if !ok || c.turn == 0 {
		return nil
	}
	return map[string]any{
		"attempt_id": c.attemptID, "probe_id": c.probeID, "request_id": c.requestID,
		"parent_request_id": c.parentRequestID, "turn": c.turn,
	}
}

// WithoutHeaders also protects explicit SDK execution headers, where no HTTP
// ingress middleware necessarily ran. The caller's map is never modified.
func WithoutHeaders(headers http.Header) http.Header {
	clean := headers.Clone()
	for name := range clean {
		if strings.HasPrefix(strings.ToLower(name), headerPrefix) {
			delete(clean, name)
		}
	}
	return clean
}
