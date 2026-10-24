package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// metaPromptCacheKeyDomain separates this key from every other hash in the proxy
// (notably the Muse reasoning account key): neither can collide with the other.
const metaPromptCacheKeyDomain = "cliproxy/meta-pck/v1"

// metaPromptCacheKeyForSession derives the prompt_cache_key for one downstream
// session: hex(sha256(domain + "\0" + session))[:32]. It is stable across every
// turn of the session and distinct across sessions, so Meta's cache warms in one
// call and one session can never poison another's bucket.
func metaPromptCacheKeyForSession(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(metaPromptCacheKeyDomain + "\x00" + sessionID))
	return hex.EncodeToString(sum[:16])
}

// resolveMetaPromptCacheKey returns the prompt_cache_key to send for this request.
// Every Meta request gets one, like the first-class Codex and xAI executors: the
// session is the same identity the proxy already uses for affinity, resolved into
// the context by helps.EnsureSessionContext. No session means no key.
func resolveMetaPromptCacheKey(ctx context.Context) (string, bool) {
	if key := metaPromptCacheKeyForSession(util.SessionIDFromContext(ctx)); key != "" {
		return key, true
	}
	return "", false
}

// applyMetaPromptCacheKey sets body prompt_cache_key for this request. A key the
// client sent itself is never overridden: a value already in the translated body
// wins, otherwise one from the client's own payload is carried over.
func (e *MetaExecutor) applyMetaPromptCacheKey(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, body []byte) []byte {
	if key := strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String()); key != "" {
		return body
	}
	for _, payload := range [][]byte{req.Payload, opts.OriginalRequest} {
		if len(payload) > 0 {
			if key := strings.TrimSpace(gjson.GetBytes(payload, "prompt_cache_key").String()); key != "" {
				return helps.SetStringIfDifferent(body, "prompt_cache_key", key)
			}
		}
	}
	key, ok := resolveMetaPromptCacheKey(ctx)
	if !ok {
		return body
	}
	return helps.SetStringIfDifferent(body, "prompt_cache_key", key)
}
