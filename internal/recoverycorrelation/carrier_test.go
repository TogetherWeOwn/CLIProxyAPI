package recoverycorrelation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func validHeaders() http.Header {
	return http.Header{
		"X-Cpa-Recovery-Attempt-Id":        {"attempt-1"},
		"X-Cpa-Recovery-Probe-Id":          {"probe-1"},
		"X-Cpa-Recovery-Request-Id":        {"request-2"},
		"X-Cpa-Recovery-Parent-Request-Id": {"request-1"},
		"X-Cpa-Recovery-Turn":              {"2"},
		"Authorization":                    {"Bearer fixture-only"},
		"X-Session-Id":                     {"unchanged"},
	}
}

func TestConsumeValidTwoTurnsAndStrip(t *testing.T) {
	for _, turn := range []string{"1", "2"} {
		t.Run(turn, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header = validHeaders()
			req.Header.Set("X-CPA-Recovery-Turn", turn)
			if turn == "1" {
				req.Header.Del("X-CPA-Recovery-Parent-Request-Id")
			}
			req = Consume(req)
			metadata := Metadata(req.Context())
			if metadata == nil || metadata["attempt_id"] != "attempt-1" || metadata["probe_id"] != "probe-1" {
				t.Fatalf("missing correlation: %v", metadata)
			}
			if metadata["turn"] != int(turn[0]-'0') {
				t.Fatalf("turn = %v", metadata["turn"])
			}
			if req.Header.Get("Authorization") != "Bearer fixture-only" || req.Header.Get("X-Session-Id") != "unchanged" {
				t.Fatal("diagnostics changed credential or session headers")
			}
			for name := range req.Header {
				if strings.HasPrefix(strings.ToLower(name), headerPrefix) {
					t.Fatal("diagnostic header survived ingress")
				}
			}
		})
	}
}

func TestConsumeIdentifierBoundsMatchProducerContract(t *testing.T) {
	for _, header := range []string{
		"X-CPA-Recovery-Attempt-Id", "X-CPA-Recovery-Probe-Id",
		"X-CPA-Recovery-Request-Id", "X-CPA-Recovery-Parent-Request-Id",
	} {
		for _, length := range []int{1, 64, 65, 128, 129} {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header = validHeaders()
			req.Header.Set(header, strings.Repeat("x", length))
			metadata := Metadata(Consume(req).Context())
			if (metadata != nil) != (length <= 128) {
				t.Fatalf("header %s length %d: metadata accepted = %v", header, length, metadata != nil)
			}
			if metadata != nil && len(metadata) != 5 {
				t.Fatalf("carrier must have exactly five fields: %v", metadata)
			}
		}
	}
}

func TestConsumeInvalidEnvelopeIgnoredButAlwaysStripped(t *testing.T) {
	tests := map[string]func(http.Header){
		"missing":             func(h http.Header) { h.Del("X-CPA-Recovery-Probe-Id") },
		"duplicate":           func(h http.Header) { h.Add("X-CPA-Recovery-Request-Id", "other") },
		"case duplicate":      func(h http.Header) { h["x-cpa-recovery-request-id"] = []string{"other"} },
		"unknown":             func(h http.Header) { h.Set("X-CPA-Recovery-Auth", "not-auth") },
		"long":                func(h http.Header) { h.Set("X-CPA-Recovery-Probe-Id", strings.Repeat("x", 129)) },
		"unicode":             func(h http.Header) { h.Set("X-CPA-Recovery-Request-Id", "request-λ") },
		"whitespace":          func(h http.Header) { h.Set("X-CPA-Recovery-Request-Id", "request with space") },
		"injection":           func(h http.Header) { h.Set("X-CPA-Recovery-Request-Id", "request\r\ninjected") },
		"comma":               func(h http.Header) { h.Set("X-CPA-Recovery-Request-Id", "one,two") },
		"leading punctuation": func(h http.Header) { h.Set("X-CPA-Recovery-Request-Id", "-request") },
		"turn zero":           func(h http.Header) { h.Set("X-CPA-Recovery-Turn", "0") },
		"turn padded":         func(h http.Header) { h.Set("X-CPA-Recovery-Turn", "02") },
		"turn whitespace":     func(h http.Header) { h.Set("X-CPA-Recovery-Turn", " 2") },
		"parent missing":      func(h http.Header) { h.Del("X-CPA-Recovery-Parent-Request-Id") },
		"parent same request": func(h http.Header) { h.Set("X-CPA-Recovery-Parent-Request-Id", "request-2") },
		"turn one parent":     func(h http.Header) { h.Set("X-CPA-Recovery-Turn", "1") },
	}
	for name, alter := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header = validHeaders()
			alter(req.Header)
			req = Consume(req)
			if Metadata(req.Context()) != nil {
				t.Fatal("malformed diagnostics reached metadata")
			}
			if len(req.Header) != 2 || req.Header.Get("Authorization") != "Bearer fixture-only" {
				t.Fatalf("expected only untouched auth/session headers: %v", req.Header)
			}
		})
	}
}

func TestConsumeDoesNotReuseOrAliasRequestMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header = validHeaders()
	req = Consume(req)
	first := Metadata(req.Context())
	first["attempt_id"] = "tampered"
	if Metadata(req.Context())["attempt_id"] != "attempt-1" {
		t.Fatal("mutable metadata alias")
	}
	next := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(req.Context())
	if Metadata(Consume(next).Context()) != nil {
		t.Fatal("stale parent metadata propagated without a new carrier")
	}
	if Metadata(nil) != nil || Metadata(context.Background()) != nil || Consume(nil) != nil {
		t.Fatal("absent context/request was not inert")
	}
}

func TestWithoutHeadersIsCaseInsensitiveAndDoesNotMutateCaller(t *testing.T) {
	headers := validHeaders()
	headers["x-cPa-rEcOvErY-unknown"] = []string{"discard"}
	original := headers.Clone()
	clean := WithoutHeaders(headers)
	if len(clean) != 2 || !reflect.DeepEqual(original, headers) {
		t.Fatal("header filtering changed caller or retained diagnostics")
	}
	clean.Set("Authorization", "different")
	if headers.Get("Authorization") != "Bearer fixture-only" {
		t.Fatal("clean map aliases caller")
	}
}

func TestConsumeConcurrentRequestsStayIsolated(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header = validHeaders()
			probe := "probe-" + strings.Repeat("x", i+1)
			req.Header.Set("X-CPA-Recovery-Probe-Id", probe)
			if got := Metadata(Consume(req).Context())["probe_id"]; got != probe {
				t.Errorf("probe cross-talk: %v", got)
			}
		}(i)
	}
	wg.Wait()
}
