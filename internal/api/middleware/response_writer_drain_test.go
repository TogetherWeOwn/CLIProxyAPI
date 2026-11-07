package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

func TestFinalizeDrainsQueuedStreamingChunks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Exercise immediate finalization before the async consumer gets CPU time.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	for _, writeString := range []bool{false, true} {
		name := "Write"
		if writeString {
			name = "WriteString"
		}
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 32; i++ {
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				stream := &drainStreamingLogWriter{}
				logger := &drainRequestLogger{
					testRequestLogger: testRequestLogger{enabled: true},
					stream:            stream,
				}
				wrapper := NewResponseWriterWrapper(c.Writer, logger, &RequestInfo{})
				wrapper.Header().Set("Content-Type", "text/event-stream")
				wrapper.WriteHeader(http.StatusOK)
				for _, payload := range []string{"data: first\n\n", "data: second\n\n"} {
					var errWrite error
					if writeString {
						_, errWrite = wrapper.WriteString(payload)
					} else {
						data := []byte(payload)
						_, errWrite = wrapper.Write(data)
						// The queued log must own its bytes after Write returns.
						for j := range data {
							data[j] = 'X'
						}
					}
					if errWrite != nil {
						t.Fatalf("write: %v", errWrite)
					}
				}
				if errFinalize := wrapper.Finalize(c); errFinalize != nil {
					t.Fatalf("Finalize: %v", errFinalize)
				}
				want := "data: first\n\ndata: second\n\n"
				if got := recorder.Body.String(); got != want {
					t.Fatalf("iteration %d: response = %q, want %q", i, got, want)
				}
				if stream.chunkCount != 2 || stream.atClose != want {
					t.Fatalf("iteration %d: chunks = %d, log at Close = %q, want two chunks %q", i, stream.chunkCount, stream.atClose, want)
				}
				if !stream.closed || wrapper.chunkChannel != nil || wrapper.streamDone != nil || wrapper.streamWriter != nil {
					t.Fatal("stream resources were not finalized")
				}
			}
		})
	}
}

type drainRequestLogger struct {
	testRequestLogger
	stream *drainStreamingLogWriter
}

func (l *drainRequestLogger) LogStreamingRequest(string, string, map[string][]string, []byte, string) (logging.StreamingLogWriter, error) {
	return l.stream, nil
}

type drainStreamingLogWriter struct {
	testStreamingLogWriter
	chunks     bytes.Buffer
	chunkCount int
	atClose    string
}

func (w *drainStreamingLogWriter) WriteChunkAsync(chunk []byte) {
	w.chunks.Write(chunk)
	w.chunkCount++
}

func (w *drainStreamingLogWriter) Close() error {
	w.atClose = w.chunks.String()
	w.closed = true
	return nil
}
