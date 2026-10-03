package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/signature"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Muse returns reasoning as an opaque encrypted_content envelope, and Meta binds
// each envelope to the account that issued it: replaying one through any other
// account is rejected with 400 "reasoning encrypted_content was not issued to
// this caller". A client such as Claude Code resends the whole history on every
// turn, and that history mixes envelopes from every pool account that served an
// earlier turn, so forwarding it verbatim fails in production even though a
// single-account test passes.
//
// The feature therefore carries provenance end to end:
//
//   - Responses leaving this executor have each reasoning envelope wrapped as
//     meta#<account-key>#<envelope> (see signature.TagMetaReasoning), whether
//     the client reads it as an Anthropic thinking signature or as a Responses
//     encrypted_content, streaming or not.
//   - Requests entering this executor keep an envelope only when its tag names
//     the credential selected for this very request, and strip the tag first.
//     Everything else (another account's tag, an untagged legacy envelope) is
//     dropped. With the feature off, untagged envelopes are forwarded as is.
//   - If Meta still rejects a replayed envelope, the request is retried once
//     with every envelope removed, so the caller never sees that 400.

// metaReasoningNotIssuedMessage is the stable fragment of the 400 Meta returns for
// an envelope replayed through an account that did not issue it.
const metaReasoningNotIssuedMessage = "not issued to this caller"

// metaReasoningReplayStats counts what happened to the reasoning envelopes of
// one request. The executor logs it so the replay hit rate can be measured.
type metaReasoningReplayStats struct {
	kept            int
	droppedForeign  int
	droppedUntagged int
}

// metaReasoningReplay is the per-request replay policy.
type metaReasoningReplay struct {
	// enabled is true when the feature is on for this model and the selected
	// credential can be identified.
	enabled bool
	// accountKey names the credential selected for this request.
	accountKey string
	stats      *metaReasoningReplayStats
}

func (e *MetaExecutor) newMetaReasoningReplay(opts cliproxyexecutor.Options, requestModel, baseModel string, auth *cliproxyauth.Auth) metaReasoningReplay {
	replay := metaReasoningReplay{stats: &metaReasoningReplayStats{}}
	if e == nil || e.cfg == nil {
		return replay
	}
	requested := helps.PayloadRequestedModel(opts, requestModel)
	if !e.cfg.Meta.ReasoningReplay.AppliesToModel(requested, requestModel, baseModel) {
		return replay
	}
	replay.accountKey = metaReasoningAccountKey(auth)
	replay.enabled = replay.accountKey != ""
	return replay
}

// metaReasoningAccountKey derives a stable, pseudonymous key for the credential.
// It has to survive token re-minting and restarts, so it is derived from the
// credential's identity (auth.ID), never from the short-lived API key. A
// credential without an ID gets no key, which leaves replay off for it.
func metaReasoningAccountKey(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	id := strings.TrimSpace(auth.ID)
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cliproxy/meta-reasoning-account/v1\x00" + id))
	return hex.EncodeToString(sum[:8])
}

// inspector returns the policy applied to the reasoning items of a request.
func (p metaReasoningReplay) inspector() reasoningReplayInspector {
	return func(raw string) reasoningReplayDecision {
		accountKey, envelope, tagged := signature.ParseMetaReasoningTag(raw)
		if !p.enabled {
			if tagged {
				// The feature was on earlier and is off now: nothing may reach Meta
				// that did not reach it before the feature existed.
				p.stats.droppedForeign++
				return reasoningReplayDecision{reason: "Muse reasoning replay is disabled", dropItem: true}
			}
			// Without provenance, an untagged Muse envelope is forwarded as is (upstream
			// behaviour). It may belong to another pool account, so it counts as kept:
			// if Meta rejects it, the request is retried once without reasoning.
			decision := foreignReasoningReplayInspector(raw)
			if decision.reason == "" && gptReasoningReplayInspector(raw).reason != "" {
				p.stats.kept++
			}
			return decision
		}
		switch {
		case !tagged:
			p.stats.droppedUntagged++
			return reasoningReplayDecision{reason: "untagged Muse reasoning envelope has no provable account", dropItem: true}
		case p.accountKey == "" || accountKey != p.accountKey:
			p.stats.droppedForeign++
			return reasoningReplayDecision{reason: "Muse reasoning envelope was issued by another account", dropItem: true}
		default:
			p.stats.kept++
			return reasoningReplayDecision{replay: envelope}
		}
	}
}

// sanitizeRequest applies the policy to a Responses request body.
func (p metaReasoningReplay) sanitizeRequest(ctx context.Context, body []byte) []byte {
	return sanitizeOpenAIResponsesReasoningEncryptedContentWithInspector(ctx, "meta executor", body, false, p.inspector())
}

// withoutReplay is the policy for the single retry: it is enabled but names no
// account, so every envelope is dropped.
func (p metaReasoningReplay) withoutReplay() metaReasoningReplay {
	return metaReasoningReplay{enabled: true, stats: &metaReasoningReplayStats{}}
}

// shouldTag reports whether responses must carry the provenance tag.
func (p metaReasoningReplay) shouldTag() bool {
	return p.enabled && p.accountKey != ""
}

// tagResponseEvent wraps the reasoning envelopes in one upstream Responses event
// (or a bare non-streaming response object) with this account's provenance tag.
func (p metaReasoningReplay) tagResponseEvent(eventData []byte) []byte {
	if !p.shouldTag() || len(eventData) == 0 {
		return eventData
	}
	switch gjson.GetBytes(eventData, "type").String() {
	case "response.output_item.added", "response.output_item.done":
		return p.tagReasoningItem(eventData, "item")
	case "response.completed", "response.incomplete", "response.failed":
		return p.tagOutputItems(eventData, "response.output")
	case "":
		return p.tagOutputItems(eventData, "output")
	}
	return eventData
}

func (p metaReasoningReplay) tagOutputItems(data []byte, outputPath string) []byte {
	output := gjson.GetBytes(data, outputPath)
	if !output.IsArray() {
		return data
	}
	for index := range output.Array() {
		data = p.tagReasoningItem(data, outputPath+"."+strconv.Itoa(index))
	}
	return data
}

func (p metaReasoningReplay) tagReasoningItem(data []byte, itemPath string) []byte {
	item := gjson.GetBytes(data, itemPath)
	if item.Get("type").String() != "reasoning" {
		return data
	}
	encrypted := item.Get("encrypted_content")
	if encrypted.Type != gjson.String || encrypted.String() == "" {
		return data
	}
	tagged := signature.TagMetaReasoning(p.accountKey, encrypted.String())
	if tagged == encrypted.String() {
		return data
	}
	out, errSet := sjson.SetBytes(data, itemPath+".encrypted_content", tagged)
	if errSet != nil {
		// An untagged envelope is dropped on replay, so failing to tag only costs the
		// replay; it must never fail the response.
		return data
	}
	return out
}

// recordRequest logs what happened to the reasoning envelopes of one request, so the
// replay hit rate (kept / (kept + dropped_foreign)) can be measured from the logs.
func (p metaReasoningReplay) recordRequest(ctx context.Context, model, authID string) {
	if p.stats == nil {
		return
	}
	s := p.stats
	if s.kept+s.droppedForeign+s.droppedUntagged == 0 {
		return
	}
	helps.LogWithRequestID(ctx).Infof("meta reasoning replay: model=%s auth=%s kept=%d dropped_foreign=%d dropped_untagged=%d", model, authID, s.kept, s.droppedForeign, s.droppedUntagged)
}

// isMetaReasoningNotIssued reports whether an upstream error is Meta rejecting an
// envelope replayed through the wrong account.
func isMetaReasoningNotIssued(statusCode int, body []byte) bool {
	// An error event inside a 200 stream carries no HTTP status of its own, and
	// wrapMetaUpstreamError reports those as 502 unless the event names a code.
	if statusCode < 400 || statusCode >= 600 || len(body) == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(string(body)), metaReasoningNotIssuedMessage)
}
