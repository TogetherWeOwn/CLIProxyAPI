package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/middleware"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/recoverycorrelation"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func recoveryProbeHeaders() http.Header {
	return http.Header{
		"X-Cpa-Recovery-Attempt-Id":        {"attempt-a"},
		"X-Cpa-Recovery-Probe-Id":          {"probe-a"},
		"X-Cpa-Recovery-Request-Id":        {"request-2"},
		"X-Cpa-Recovery-Parent-Request-Id": {"request-1"},
		"X-Cpa-Recovery-Turn":              {"2"},
		"Authorization":                    {"Bearer fixture-only"},
	}
}

func TestRecoveryCorrelationIngressToExecutorOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, operation := range []string{"execute", "stream", "count", "error"} {
		t.Run(operation, func(t *testing.T) {
			model := "recovery-carrier-" + operation
			executor := &interceptorCaptureExecutor{
				stream: func(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
					chunks := make(chan coreexecutor.StreamChunk, 1)
					chunks <- coreexecutor.StreamChunk{Payload: []byte(`{"chunk":true}`)}
					close(chunks)
					return &coreexecutor.StreamResult{Chunks: chunks}, nil
				},
			}
			if operation == "error" {
				executor.execute = func(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
					return coreexecutor.Response{}, errors.New("fixture executor failure")
				}
			}
			h := newInterceptorHandler(t, model, executor, &sdkconfig.SDKConfig{})
			router := gin.New()
			router.Use(middleware.RecoveryCorrelation())
			router.POST("/v1/chat/completions", func(c *gin.Context) {
				if c.GetHeader("Authorization") != "Bearer fixture-only" {
					t.Error("diagnostic middleware changed authorization")
				}
				ctx, cancel := h.GetContextWithCancel(nil, c, context.Background())
				defer cancel()
				body := []byte(`{"model":"` + model + `"}`)
				switch operation {
				case "count":
					if _, _, errMsg := h.ExecuteCountWithAuthManager(ctx, "openai", model, body, ""); errMsg != nil {
						t.Errorf("count: %v", errMsg)
					}
				case "stream":
					data, _, errs := h.ExecuteStreamWithAuthManager(ctx, "openai", model, body, "")
					for data != nil || errs != nil {
						select {
						case _, ok := <-data:
							if !ok {
								data = nil
							}
						case errMsg, ok := <-errs:
							if !ok {
								errs = nil
							} else if errMsg != nil {
								t.Errorf("stream: %v", errMsg)
							}
						}
					}
				default:
					_, _, errMsg := h.ExecuteWithAuthManager(ctx, "openai", model, body, "")
					if (errMsg != nil) != (operation == "error") {
						t.Errorf("unexpected error outcome: %v", errMsg)
					}
				}
				c.Status(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header = recoveryProbeHeaders()
			router.ServeHTTP(httptest.NewRecorder(), req)
			_, opts := executor.captured()
			correlation, ok := opts.Metadata[recoverycorrelation.MetadataKey].(map[string]any)
			if !ok || correlation["request_id"] != "request-2" || correlation["parent_request_id"] != "request-1" || correlation["turn"] != 2 {
				t.Fatalf("executor correlation = %v", correlation)
			}
			if opts.Metadata[coreexecutor.RequestedModelMetadataKey] != model {
				t.Fatalf("requested model was not preserved: %v", opts.Metadata)
			}
			for name := range opts.Headers {
				if strings.HasPrefix(strings.ToLower(name), "x-cpa-recovery-") {
					t.Fatal("diagnostic header reached executor headers")
				}
			}
		})
	}
}

func TestRecoveryCorrelationPluginRequestBuilderAndExplicitHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header = recoveryProbeHeaders()
	req = recoverycorrelation.Consume(req)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	ctx := context.WithValue(context.Background(), "gin", c)
	h := &BaseAPIHandler{}
	for _, stream := range []bool{false, true} {
		request, opts := h.pluginExecutorRequest(ctx, "openai", "openai", "resolved-model", "requested-model", []byte(`{"model":"requested-model"}`), "", stream, modelExecutionOptions{Headers: recoveryProbeHeaders()})
		if request.Model != "resolved-model" || opts.Metadata[coreexecutor.RequestedModelMetadataKey] != "requested-model" {
			t.Fatal("correlation confused requested and resolved models")
		}
		if opts.Metadata[recoverycorrelation.MetadataKey] == nil || len(opts.Headers) != 1 {
			t.Fatal("plugin builder lost correlation or retained diagnostics in explicit headers")
		}
	}
}

func TestRecoveryCorrelationMalformedInputCannotSetAuthHints(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header = recoveryProbeHeaders()
	req.Header.Set("X-CPA-Recovery-Auth-Id", "must-not-pin")
	req = recoverycorrelation.Consume(req)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	meta := requestExecutionMetadata(context.WithValue(context.Background(), "gin", c))
	for _, key := range []string{recoverycorrelation.MetadataKey, coreexecutor.PinnedAuthMetadataKey, coreexecutor.AuthSelectionModelMetadataKey, coreexecutor.CallerScopeMetadataKey} {
		if _, exists := meta[key]; exists {
			t.Fatalf("diagnostic input influenced %s", key)
		}
	}
	if req.Header.Get("Authorization") != "Bearer fixture-only" {
		t.Fatal("normal authorization header changed")
	}
}
