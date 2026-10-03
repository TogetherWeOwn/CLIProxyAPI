package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/signature"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func openaiResponsesReasoningSummaryIsEmpty(summary gjson.Result) bool {
	if !summary.Exists() || summary.Type == gjson.Null {
		return true
	}
	return summary.IsArray() && len(summary.Array()) == 0
}

// openaiResponsesReasoningItemIsEmpty reports whether a reasoning item carries no
// summary and no content, so that nothing is left of it once encrypted_content is gone.
func openaiResponsesReasoningItemIsEmpty(itemRaw string) bool {
	item := gjson.Parse(itemRaw)
	if !openaiResponsesReasoningSummaryIsEmpty(item.Get("summary")) {
		return false
	}
	content := item.Get("content")
	return !content.Exists() || content.Type == gjson.Null || (content.IsArray() && len(content.Array()) == 0)
}

func promoteOpenAIResponsesReasoningTextToSummary(itemRaw string, content gjson.Result) (string, error) {
	var b strings.Builder
	b.WriteByte('[')
	n := 0
	for _, part := range content.Array() {
		if strings.TrimSpace(part.Get("type").String()) != "reasoning_text" {
			continue
		}
		text := part.Get("text").String()
		if text == "" {
			continue
		}
		partJSON, err := sjson.Set(`{"type":"summary_text"}`, "text", text)
		if err != nil {
			return itemRaw, err
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(partJSON)
		n++
	}
	b.WriteByte(']')
	if n == 0 {
		return itemRaw, nil
	}
	return sjson.SetRaw(itemRaw, "summary", b.String())
}

// reasoningReplayDecision is what a reasoningReplayInspector decides for one
// reasoning item's encrypted_content.
type reasoningReplayDecision struct {
	// replay is the encrypted_content to forward upstream. Used only when reason is empty.
	replay string
	// reason, when non-empty, drops the encrypted_content and explains why.
	reason string
	// dropItem additionally removes the whole reasoning item when dropping the
	// encrypted_content left it without any summary or content of its own.
	dropItem bool
}

// reasoningReplayInspector decides whether a string encrypted_content may be
// replayed to the upstream. Providers differ in what they can decrypt.
type reasoningReplayInspector func(raw string) reasoningReplayDecision

// gptReasoningReplayInspector accepts only structurally valid GPT/Codex reasoning signatures.
func gptReasoningReplayInspector(raw string) reasoningReplayDecision {
	if raw != strings.TrimSpace(raw) {
		return reasoningReplayDecision{reason: "encrypted_content has leading or trailing whitespace"}
	}
	if _, err := signature.InspectGPTReasoningSignature(raw); err != nil {
		return reasoningReplayDecision{reason: err.Error()}
	}
	return reasoningReplayDecision{replay: raw}
}

// foreignReasoningReplayInspector also replays unknown-format encrypted_content,
// which third-party Responses models (such as DeepSeek) expect back verbatim.
func foreignReasoningReplayInspector(raw string) reasoningReplayDecision {
	decision := gptReasoningReplayInspector(raw)
	if decision.reason != "" && raw != "" && raw == strings.TrimSpace(raw) && signature.DetectSignatureProvider(raw) == signature.SignatureProviderUnknown {
		return reasoningReplayDecision{replay: raw}
	}
	return decision
}

func sanitizeOpenAIResponsesReasoningEncryptedContent(ctx context.Context, provider string, body []byte) []byte {
	return sanitizeOpenAIResponsesReasoningEncryptedContentWithInspector(ctx, provider, body, false, gptReasoningReplayInspector)
}

func sanitizeOpenAIResponsesReasoningEncryptedContentWithCompat(ctx context.Context, provider string, body []byte, isCompat bool) []byte {
	inspect := gptReasoningReplayInspector
	if isCompat {
		inspect = foreignReasoningReplayInspector
	}
	return sanitizeOpenAIResponsesReasoningEncryptedContentWithInspector(ctx, provider, body, isCompat, inspect)
}

func sanitizeOpenAIResponsesReasoningEncryptedContentKeepForeign(ctx context.Context, provider string, body []byte) []byte {
	return sanitizeOpenAIResponsesReasoningEncryptedContentWithInspector(ctx, provider, body, false, foreignReasoningReplayInspector)
}

func sanitizeOpenAIResponsesReasoningEncryptedContentWithInspector(ctx context.Context, provider string, body []byte, isCompat bool, inspect reasoningReplayInspector) []byte {
	inputResult := util.GetGJSONBytesNoCopy(body, "input")
	if !inputResult.Exists() || !inputResult.IsArray() {
		return body
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		provider = "openai responses upstream"
	}

	// Codex backend rejects store=true and does not persist items when store=false.
	// A reasoning item that still carries an id without usable encrypted_content is
	// treated as a store lookup and returns:
	//   Item with id '...' not found. Items are not persisted when `store` is set to false.
	// Strip those orphan ids unless the request explicitly opts into store=true.
	stripOrphanReasoningIDs := !gjson.GetBytes(body, "store").Bool()

	items := inputResult.Array()

	// rebuilt accumulates the edited "input" array as JSON array bytes. It
	// stays nil while no item needs editing so the common case (nothing to
	// sanitize) does no allocation or rebuilding. Edits are applied directly
	// to each item's own raw JSON rather than re-parsing the whole body,
	// keeping the cost proportional to the item being edited.
	var rebuilt []byte
	itemsWritten := 0
	keep := func(raw string) {
		if rebuilt == nil {
			return
		}
		if itemsWritten > 0 {
			rebuilt = append(rebuilt, ',')
		}
		rebuilt = append(rebuilt, raw...)
		itemsWritten++
	}
	startRebuild := func(index int) {
		if rebuilt != nil {
			return
		}
		// First item that needs editing: start the buffer and backfill
		// it with the raw JSON of every preceding item.
		rebuilt = make([]byte, 0, len(inputResult.Raw))
		rebuilt = append(rebuilt, '[')
		for i := range index {
			keep(items[i].Raw)
		}
	}

	for index, item := range items {
		if strings.TrimSpace(item.Get("type").String()) != "reasoning" {
			keep(item.Raw)
			continue
		}

		encryptedContent := item.Get("encrypted_content")
		itemID := strings.TrimSpace(item.Get("id").String())
		if itemID == "" {
			itemID = fmt.Sprintf("input[%d]", index)
		}

		nextItem := item.Raw
		changed := false

		// Official Codex schema sets maxItems: 0 on reasoning.content. Third-party
		// channels replay cleartext thinking there; promote it into summary when
		// summary is empty, then force content to [].
		// When isCompat is true, third-party Responses models (such as DeepSeek)
		// require original reasoning_text inside reasoning.content to be replayed.
		content := item.Get("content")
		if !isCompat && content.IsArray() && len(content.Array()) > 0 {
			if openaiResponsesReasoningSummaryIsEmpty(item.Get("summary")) {
				promoted, errPromote := promoteOpenAIResponsesReasoningTextToSummary(nextItem, content)
				if errPromote != nil {
					helps.LogWithRequestID(ctx).Debugf("%s: failed to promote reasoning_text into summary at input[%d]: %v", provider, index, errPromote)
				} else {
					nextItem = promoted
				}
			}
			cleared, errClear := sjson.SetRaw(nextItem, "content", "[]")
			if errClear != nil {
				helps.LogWithRequestID(ctx).Debugf("%s: failed to clear reasoning content at input[%d]: %v", provider, index, errClear)
			} else {
				nextItem = cleared
				changed = true
				helps.LogWithRequestID(ctx).Debugf("%s: cleared reasoning content at input[%d] item_id=%q", provider, index, itemID)
			}
		}

		if !encryptedContent.Exists() {
			if !isCompat && stripOrphanReasoningIDs && item.Get("id").Exists() {
				dropped, err := sjson.Delete(nextItem, "id")
				if err != nil {
					helps.LogWithRequestID(ctx).Debugf("%s: failed to drop orphan reasoning id at input[%d]: %v", provider, index, err)
				} else {
					nextItem = dropped
					changed = true
					helps.LogWithRequestID(ctx).Debugf("%s: dropped orphan reasoning id at input[%d] item_id=%q reason=missing encrypted_content with store disabled", provider, index, itemID)
				}
			}
			if !changed {
				keep(item.Raw)
				continue
			}
			startRebuild(index)
			keep(nextItem)
			continue
		}

		var decision reasoningReplayDecision
		switch encryptedContent.Type {
		case gjson.String:
			decision = inspect(encryptedContent.String())
		case gjson.Null:
			decision.reason = "encrypted_content is null"
		default:
			decision.reason = fmt.Sprintf("encrypted_content must be a string, got %s", encryptedContent.Type.String())
		}
		reason := decision.reason
		if reason == "" {
			if decision.replay != encryptedContent.String() {
				replayed, errReplay := sjson.Set(nextItem, "encrypted_content", decision.replay)
				if errReplay != nil {
					// Forwarding the stored value would send an envelope the inspector did not
					// approve, so fall back to dropping it like any other invalid value.
					decision.reason = fmt.Sprintf("failed to rewrite encrypted_content: %v", errReplay)
					reason = decision.reason
				} else {
					nextItem = replayed
					changed = true
				}
			}
		}
		if reason == "" {
			if !changed {
				keep(item.Raw)
				continue
			}
			startRebuild(index)
			keep(nextItem)
			continue
		}

		dropped, err := sjson.Delete(nextItem, "encrypted_content")
		if err != nil {
			helps.LogWithRequestID(ctx).Debugf("%s: failed to drop invalid reasoning encrypted_content at input[%d]: %v", provider, index, err)
			if !changed {
				keep(item.Raw)
				continue
			}
			startRebuild(index)
			keep(nextItem)
			continue
		}
		nextItem = dropped
		changed = true
		if !isCompat && stripOrphanReasoningIDs && item.Get("id").Exists() {
			if nextID, errID := sjson.Delete(nextItem, "id"); errID != nil {
				helps.LogWithRequestID(ctx).Debugf("%s: failed to drop reasoning id after invalid encrypted_content at input[%d]: %v", provider, index, errID)
			} else {
				nextItem = nextID
			}
		}

		startRebuild(index)
		if decision.dropItem && openaiResponsesReasoningItemIsEmpty(nextItem) {
			helps.LogWithRequestID(ctx).Debugf("%s: dropped reasoning item at input[%d] item_id=%q reason=%s", provider, index, itemID, reason)
			continue
		}
		keep(nextItem)

		helps.LogWithRequestID(ctx).Debugf("%s: dropped invalid reasoning encrypted_content at input[%d] item_id=%q reason=%s", provider, index, itemID, reason)
	}

	if rebuilt == nil {
		return body
	}
	rebuilt = append(rebuilt, ']')

	updated, err := sjson.SetRawBytes(body, "input", rebuilt)
	if err != nil {
		helps.LogWithRequestID(ctx).Debugf("%s: failed to rebuild input array while sanitizing reasoning encrypted_content: %v", provider, err)
		return body
	}
	return updated
}
