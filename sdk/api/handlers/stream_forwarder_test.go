package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
)

func TestPendingStreamErrorReturnsBufferedError(t *testing.T) {
	errs := make(chan *interfaces.ErrorMessage, 1)
	want := &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: errors.New("upstream failed")}
	errs <- want
	close(errs)

	got, ok := PendingStreamError(errs)
	if !ok || got != want {
		t.Fatalf("PendingStreamError() = (%#v, %t), want (%#v, true)", got, ok, want)
	}
}

func TestValidateSSEDataJSONAllowsMultilinePayload(t *testing.T) {
	chunk := []byte("event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\n" +
		"data: \"response\":{\"status\":\"completed\"}}\n\n")
	if err := validateSSEDataJSON(chunk); err != nil {
		t.Fatalf("validateSSEDataJSON() error = %v, want nil", err)
	}
}

func TestForwardStreamNormalizesErrorBeforeWriteAndCancel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	data := make(chan []byte)
	close(data)
	errs := make(chan *interfaces.ErrorMessage, 1)
	errs <- &interfaces.ErrorMessage{StatusCode: http.StatusBadGateway, Error: errors.New("raw secret")}
	close(errs)

	var written, canceled string
	disabledKeepAlive := time.Duration(0)
	h := &BaseAPIHandler{}
	h.ForwardStream(c, recorder, func(err error) {
		if err != nil {
			canceled = err.Error()
		}
	}, data, errs, StreamForwardOptions{
		KeepAliveInterval: &disabledKeepAlive,
		NormalizeTerminalError: func(errMsg *interfaces.ErrorMessage) *interfaces.ErrorMessage {
			return &interfaces.ErrorMessage{StatusCode: errMsg.StatusCode, Error: errors.New("safe error")}
		},
		WriteTerminalError: func(errMsg *interfaces.ErrorMessage) {
			written = errMsg.Error.Error()
		},
	})

	if written != "safe error" || canceled != "safe error" {
		t.Fatalf("written=%q canceled=%q, want sanitized error", written, canceled)
	}
}

func TestForwardStreamCancellationPrecedesReadyUpstream(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, source := range []string{"closed_data", "buffered_data", "buffered_error"} {
			name := source
			if deadline {
				name += "_deadline"
			}
			t.Run(name, func(t *testing.T) {
				// Exercise simultaneous readiness without depending on select ordering.
				for range 64 {
					ctx, stop := context.WithCancel(context.Background())
					stop()
					if deadline {
						ctx, stop = context.WithDeadline(context.Background(), time.Unix(1, 0))
						stop()
					}
					recorder := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(recorder)
					c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
					data := make(chan []byte, 1)
					errs := make(chan *interfaces.ErrorMessage, 1)
					switch source {
					case "closed_data":
						close(data)
					case "buffered_data":
						data <- []byte("late payload")
					case "buffered_error":
						errs <- &interfaces.ErrorMessage{Error: errors.New("late upstream failure")}
					}
					callbacks, cancellations := 0, 0
					var outcome error
					disabledKeepAlive := time.Duration(0)
					h := &BaseAPIHandler{}
					h.ForwardStream(c, recorder, func(err error) {
						cancellations++
						outcome = err
					}, data, errs, StreamForwardOptions{
						KeepAliveInterval: &disabledKeepAlive,
						WriteChunk:        func([]byte) { callbacks++ },
						Flush:             func() error { callbacks++; return nil },
						NormalizeTerminalError: func(errMsg *interfaces.ErrorMessage) *interfaces.ErrorMessage {
							callbacks++
							return errMsg
						},
						WriteTerminalError: func(*interfaces.ErrorMessage) { callbacks++ },
						CloseError: func() *interfaces.ErrorMessage {
							callbacks++
							return &interfaces.ErrorMessage{Error: errors.New("premature EOF")}
						},
						WriteDone: func() { callbacks++ },
					})
					if !errors.Is(outcome, ctx.Err()) || callbacks != 0 || cancellations != 1 {
						t.Fatalf("cancellation lost to ready upstream: outcome=%v want=%v callbacks=%d cancellations=%d", outcome, ctx.Err(), callbacks, cancellations)
					}
				}
			})
		}
	}
}

func TestForwardStreamCancellationAfterPartialFlush(t *testing.T) {
	for range 64 {
		ctx, stop := context.WithCancel(context.Background())
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		data := make(chan []byte, 1)
		data <- []byte("partial payload")
		writes, flushes, terminalCallbacks := 0, 0, 0
		var outcome error
		disabledKeepAlive := time.Duration(0)
		h := &BaseAPIHandler{}
		h.ForwardStream(c, recorder, func(err error) { outcome = err }, data, nil, StreamForwardOptions{
			KeepAliveInterval: &disabledKeepAlive,
			WriteChunk:        func([]byte) { writes++ },
			Flush: func() error {
				flushes++
				if flushes == 1 {
					stop()
					close(data)
				}
				return nil
			},
			CloseError: func() *interfaces.ErrorMessage {
				terminalCallbacks++
				return &interfaces.ErrorMessage{Error: errors.New("premature EOF")}
			},
			WriteTerminalError: func(*interfaces.ErrorMessage) { terminalCallbacks++ },
			WriteDone:          func() { terminalCallbacks++ },
		})
		stop()
		if !errors.Is(outcome, context.Canceled) || writes != 1 || flushes != 1 || terminalCallbacks != 0 {
			t.Fatalf("cancellation lost after partial flush: outcome=%v writes=%d flushes=%d terminal=%d", outcome, writes, flushes, terminalCallbacks)
		}
	}
}

func TestForwardStreamDeliveredOutcomeSurvivesFlushCancellation(t *testing.T) {
	writeErr := errors.New("flush failed")
	chunkErr := errors.New("terminal chunk failed")
	for _, tc := range []struct {
		name     string
		flushErr error
		chunkErr error
	}{
		{name: "completed"},
		{name: "flush_failure", flushErr: writeErr},
		{name: "terminal_failure", chunkErr: chunkErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
			data := make(chan []byte, 1)
			data <- []byte("terminal payload")
			var outcome error
			cancellations := 0
			disabledKeepAlive := time.Duration(0)
			h := &BaseAPIHandler{}
			h.ForwardStream(c, recorder, func(err error) { outcome = err; cancellations++ }, data, nil, StreamForwardOptions{
				KeepAliveInterval: &disabledKeepAlive,
				Flush:             func() error { stop(); return tc.flushErr },
				ChunkDone:         func() bool { return true },
				ChunkError: func() *interfaces.ErrorMessage {
					if tc.chunkErr != nil {
						return &interfaces.ErrorMessage{Error: tc.chunkErr}
					}
					return nil
				},
			})
			want := tc.flushErr
			if want == nil {
				want = tc.chunkErr
			}
			if !errors.Is(outcome, want) || cancellations != 1 {
				t.Fatalf("delivered outcome=%v cancellations=%d, want %v once", outcome, cancellations, want)
			}
		})
	}
}

func TestPendingStreamErrorIgnoresUnavailableErrors(t *testing.T) {
	closed := make(chan *interfaces.ErrorMessage)
	close(closed)

	for name, errs := range map[string]<-chan *interfaces.ErrorMessage{
		"nil":          nil,
		"closed empty": closed,
		"open empty":   make(chan *interfaces.ErrorMessage),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := PendingStreamError(errs); ok || got != nil {
				t.Fatalf("PendingStreamError() = (%#v, %t), want (nil, false)", got, ok)
			}
		})
	}
}

func TestSplitCRLFRepro(t *testing.T) {
	state := &sseJSONValidationState{}
	chunks := []string{
		"data: {\"type\":\"response.completed\",\r",
		"\ndata: \"response\":{\"status\":\"completed\"}}\r\n\r\n",
	}
	var output []byte
	for _, chunk := range chunks {
		out, errAdd := state.AddChunk([]byte(chunk))
		if errAdd != nil {
			t.Fatal(errAdd)
		}
		output = append(output, out...)
	}
	if errFinish := state.Finish(); errFinish != nil {
		t.Fatal(errFinish)
	}

	singleState := &sseJSONValidationState{}
	unsplitChunk := "data: {\"type\":\"response.completed\",\r\ndata: \"response\":{\"status\":\"completed\"}}\r\n\r\n"
	singleOutput, errSingle := singleState.AddChunk([]byte(unsplitChunk))
	if errSingle != nil {
		t.Fatal(errSingle)
	}
	if errFinish := singleState.Finish(); errFinish != nil {
		t.Fatal(errFinish)
	}
	if string(output) != string(singleOutput) {
		t.Fatalf("output mismatch: got %q, want %q", string(output), string(singleOutput))
	}
}

func TestSSEJSONValidationStateSplitCRLFVariants(t *testing.T) {
	wantOutput := "data: {\"type\":\"response.completed\",\ndata: \"response\":{\"status\":\"completed\"}}\n\n"
	tests := []struct {
		name   string
		chunks []string
	}{
		{
			name: "intervening empty chunks",
			chunks: []string{
				"data: {\"type\":\"response.completed\",\r",
				"",
				"",
				"\ndata: \"response\":{\"status\":\"completed\"}}\r\n\r\n",
			},
		},
		{
			name: "standalone LF chunk",
			chunks: []string{
				"data: {\"type\":\"response.completed\",\r",
				"\n",
				"data: \"response\":{\"status\":\"completed\"}}\r\n\r\n",
			},
		},
		{
			name: "bare CR chunk followed by regular content",
			chunks: []string{
				"data: {\"type\":\"response.completed\",\r",
				"data: \"response\":{\"status\":\"completed\"}}\r\n\r\n",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &sseJSONValidationState{}
			var output []byte
			for _, chunk := range tc.chunks {
				out, errAdd := state.AddChunk([]byte(chunk))
				if errAdd != nil {
					t.Fatalf("AddChunk failed: %v", errAdd)
				}
				output = append(output, out...)
			}
			if errFinish := state.Finish(); errFinish != nil {
				t.Fatalf("Finish failed: %v", errFinish)
			}
			if string(output) != wantOutput {
				t.Fatalf("output mismatch: got %q, want %q", string(output), wantOutput)
			}
		})
	}
}
