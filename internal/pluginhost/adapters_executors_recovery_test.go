package pluginhost

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/recoverycorrelation"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestBuildExecutorRequestCarriesRecoveryMetadataWithoutHeaders(t *testing.T) {
	inbound := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	inbound.Header = http.Header{
		"X-Cpa-Recovery-Attempt-Id":        {"attempt-a"},
		"X-Cpa-Recovery-Probe-Id":          {"probe-a"},
		"X-Cpa-Recovery-Request-Id":        {"turn-2"},
		"X-Cpa-Recovery-Parent-Request-Id": {"turn-1"},
		"X-Cpa-Recovery-Turn":              {"2"},
	}
	originalHeaders := inbound.Header.Clone()
	inbound = recoverycorrelation.Consume(inbound)
	metadata := recoverycorrelation.Metadata(inbound.Context())
	for _, stream := range []bool{false, true} {
		request := buildExecutorRequest(New(), "meta-muse", nil,
			coreexecutor.Request{Model: "resolved-model", Payload: []byte(`{"messages":[]}`)},
			coreexecutor.Options{Stream: stream, Headers: originalHeaders, Metadata: map[string]any{
				recoverycorrelation.MetadataKey:        metadata,
				coreexecutor.RequestedModelMetadataKey: "requested-model",
			}})
		if len(request.Headers) != 0 || len(originalHeaders) != 5 {
			t.Fatal("diagnostic headers leaked into plugin request or caller was modified")
		}
		if request.Model != "resolved-model" || request.Metadata[coreexecutor.RequestedModelMetadataKey] != "requested-model" {
			t.Fatal("model identities changed")
		}
		raw, errMarshal := json.Marshal(request.Metadata)
		if errMarshal != nil {
			t.Fatalf("existing metadata ABI cannot serialize carrier: %v", errMarshal)
		}
		var decoded struct {
			Recovery struct {
				AttemptID       string `json:"attempt_id"`
				ProbeID         string `json:"probe_id"`
				RequestID       string `json:"request_id"`
				ParentRequestID string `json:"parent_request_id"`
				Turn            int    `json:"turn"`
			} `json:"cpa_recovery_v1"`
		}
		if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
			t.Fatalf("carrier roundtrip: %v", errUnmarshal)
		}
		got := decoded.Recovery
		if got.AttemptID != "attempt-a" || got.ProbeID != "probe-a" || got.RequestID != "turn-2" || got.ParentRequestID != "turn-1" || got.Turn != 2 {
			t.Fatalf("plugin metadata carrier = %+v", got)
		}
	}
}
