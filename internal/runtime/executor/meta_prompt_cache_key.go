package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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

// metaPromptCacheKeyAuthMatches reports whether auth is named by one of the
// configured canary entries. An entry matches the auth's label, email, ID or
// runtime index, case-insensitively; blank entries never match.
func metaPromptCacheKeyAuthMatches(entries []string, auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	candidates := []string{auth.Label, auth.ID, auth.Index}
	if auth.Metadata != nil {
		if email, ok := auth.Metadata["email"].(string); ok {
			candidates = append(candidates, email)
		}
	}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		for _, candidate := range candidates {
			if candidate = strings.TrimSpace(candidate); candidate != "" && strings.EqualFold(candidate, entry) {
				return true
			}
		}
	}
	return false
}

// resolveMetaPromptCacheKey returns the prompt_cache_key to send for this request.
// It applies only when the feature is enabled for the serving auth (an empty auth
// list means every Meta auth); the session is the same identity the proxy already
// uses for affinity, resolved into the context by helps.EnsureSessionContext.
func (e *MetaExecutor) resolveMetaPromptCacheKey(ctx context.Context, auth *cliproxyauth.Auth) (string, bool) {
	if e == nil || e.cfg == nil || auth == nil || !e.cfg.Meta.PromptCacheKey.Enabled {
		return "", false
	}
	filtered := false
	for _, entry := range e.cfg.Meta.PromptCacheKey.Auths {
		if strings.TrimSpace(entry) != "" {
			filtered = true
			break
		}
	}
	if filtered && !metaPromptCacheKeyAuthMatches(e.cfg.Meta.PromptCacheKey.Auths, auth) {
		return "", false
	}
	if key := metaPromptCacheKeyForSession(util.SessionIDFromContext(ctx)); key != "" {
		return key, true
	}
	return "", false
}

// applyMetaPromptCacheKey sets body prompt_cache_key for this request. A key the
// client sent itself is never overridden: a value already in the translated body
// wins, otherwise one from the client's own payload is carried over. It is a
// no-op when the feature is off for the serving auth.
func (e *MetaExecutor) applyMetaPromptCacheKey(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, body []byte, auth *cliproxyauth.Auth) []byte {
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
	key, ok := e.resolveMetaPromptCacheKey(ctx, auth)
	if !ok {
		return body
	}
	return helps.SetStringIfDifferent(body, "prompt_cache_key", key)
}
