package helps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// metaPromptCacheKeyDomain separates this key from every other hash in the
// proxy: a prompt cache key can never collide with another derived identity.
const metaPromptCacheKeyDomain = "cliproxy/meta-pck/v1"

// MetaPromptCacheKeyForSession derives the prompt_cache_key for one downstream
// session: hex(sha256(domain + "\0" + session))[:32]. It is stable across every
// turn of the session and distinct across sessions, so Meta's cache warms in
// one call and one session can never poison another's bucket.
func MetaPromptCacheKeyForSession(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(metaPromptCacheKeyDomain + "\x00" + sessionID))
	return hex.EncodeToString(sum[:16])
}

// ApplyMetaPromptCacheKey sets the body's prompt_cache_key for a Meta request.
// Every Meta request gets one, like the first-class Codex and xAI executors:
// the session is the same identity the proxy already uses for affinity,
// resolved into the context by EnsureSessionContext. No session means no key.
//
// A key the client sent itself is never overridden: a value already in the
// translated body wins, otherwise one from the client's own payload is
// carried over.
func ApplyMetaPromptCacheKey(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, body []byte) []byte {
	if key := strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String()); key != "" {
		return body
	}
	for _, payload := range [][]byte{req.Payload, opts.OriginalRequest} {
		if len(payload) > 0 {
			if key := strings.TrimSpace(gjson.GetBytes(payload, "prompt_cache_key").String()); key != "" {
				return SetStringIfDifferent(body, "prompt_cache_key", key)
			}
		}
	}
	if key := MetaPromptCacheKeyForSession(util.SessionIDFromContext(ctx)); key != "" {
		return SetStringIfDifferent(body, "prompt_cache_key", key)
	}
	return body
}
