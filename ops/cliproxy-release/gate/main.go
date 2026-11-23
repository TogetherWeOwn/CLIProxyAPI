// The release gate stays running while the gateway behind it is replaced.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

type admission struct {
	mu    sync.Mutex
	state status
}

type status struct {
	Generation string `json:"generation"`
	Epoch      uint64 `json:"epoch"`
	Closed     bool   `json:"closed"`
	Active     int    `json:"active"`
}

func (a *admission) enter() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Closed {
		return false
	}
	a.state.Active++
	return true
}

func (a *admission) leave() {
	a.mu.Lock()
	a.state.Active--
	a.mu.Unlock()
}

func (a *admission) http(proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enter() {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "gateway maintenance", http.StatusServiceUnavailable)
			return
		}
		defer a.leave()
		proxy.ServeHTTP(w, r)
	})
}

func (a *admission) control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		writeStatus(w, a.state)
	})
	mux.HandleFunc("POST /{verb}/{generation}/{epoch}", func(w http.ResponseWriter, r *http.Request) {
		closed := r.PathValue("verb") == "close"
		if !closed && r.PathValue("verb") != "open" {
			http.NotFound(w, r)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if r.PathValue("generation") != a.state.Generation ||
			r.PathValue("epoch") != strconv.FormatUint(a.state.Epoch, 10) ||
			closed == a.state.Closed {
			http.Error(w, "gate state changed", http.StatusConflict)
			return
		}
		a.state.Closed = closed
		a.state.Epoch++
		writeStatus(w, a.state)
	})
	return mux
}

func writeStatus(w http.ResponseWriter, current status) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(current)
}

// A RESP connection can carry commands after becoming idle. Count the entire
// session and wait for Keeper to disconnect before declaring drain complete.
func (a *admission) forwardRESP(listener net.Listener, target string) error {
	for {
		client, errAccept := listener.Accept()
		if errAccept != nil {
			return errAccept
		}
		if !a.enter() {
			_ = client.Close()
			continue
		}
		go func() {
			defer a.leave()
			defer closeResource(client, "resp-client")
			// The backend selects its protocol from the first byte. Permit
			// only a RESP command array so HTTP cannot reach it via this lane.
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(client)
			prefix, errRead := reader.Peek(1)
			if errRead != nil || prefix[0] != '*' {
				return
			}
			_ = client.SetReadDeadline(time.Time{})
			upstream, errDial := net.DialTimeout("tcp", target, 5*time.Second)
			if errDial != nil {
				return
			}
			defer closeResource(upstream, "resp-backend")
			// When Keeper disconnects, close the upstream too, even if it
			// is blocked in a queue command and never writes a response.
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, reader)
				_ = upstream.Close()
				close(done)
			}()
			_, _ = io.Copy(client, upstream)
			_ = client.Close()
			<-done
		}()
	}
}

func run(ctx context.Context, listen []string, resp, target, socket, ingress string) error {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return errors.New("target must be a host and port")
	}
	// Require a private directory. Do not unlink a possibly live control socket.
	dir, errStat := os.Lstat(filepath.Dir(socket))
	if errStat != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 || !owned(dir) {
		return errors.New("control socket needs a private directory with mode 0700")
	}
	var generation [16]byte
	if _, errRand := rand.Read(generation[:]); errRand != nil {
		return errRand
	}
	a := &admission{state: status{Generation: hex.EncodeToString(generation[:]), Closed: true}}

	control, errControl := net.Listen("unix", socket)
	if errControl != nil {
		return errControl
	}
	defer closeResource(control, "control")
	if errMode := os.Chmod(socket, 0600); errMode != nil {
		return errMode
	}
	tcp := make([]net.Listener, 0, len(listen))
	for _, addr := range listen {
		data, errData := net.Listen("tcp", addr)
		if errData != nil {
			return errData
		}
		defer closeResource(data, "http-listener")
		tcp = append(tcp, data)
	}
	errs := make(chan error, len(tcp)+3)
	if resp != "" {
		keeper, errKeeper := net.Listen("tcp", resp)
		if errKeeper != nil {
			return errKeeper
		}
		defer closeResource(keeper, "resp-listener")
		go func() { errs <- a.forwardRESP(keeper, target) }()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	errLog := stdlog.New(io.Discard, "", 0)
	public := &http.Server{Handler: a.http(backendHTTP(target, false, transport, errLog)), ReadHeaderTimeout: 10 * time.Second, ErrorLog: errLog}
	private := &http.Server{Handler: a.control(), ReadHeaderTimeout: 2 * time.Second, ErrorLog: errLog}
	if ingress != "" {
		trusted, errTrusted := ingressListener(ingress)
		if errTrusted != nil {
			return errTrusted
		}
		defer closeResource(trusted, "trusted-ingress")
		proxy := backendHTTP(target, true, transport, errLog)
		upstream := &http.Server{Handler: a.http(proxy), ReadHeaderTimeout: 10 * time.Second, ErrorLog: errLog}
		go func() { errs <- upstream.Serve(trusted) }()
	}
	for _, data := range tcp {
		go func() { errs <- public.Serve(data) }()
	}
	go func() { errs <- private.Serve(control) }()
	select {
	case <-ctx.Done():
		return nil
	case errServe := <-errs:
		return errServe
	}
}

func closeResource(closer io.Closer, role string) {
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.WithField("resource", role).Warn("release gate close failed")
	}
}

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func ingressListener(path string) (net.Listener, error) {
	dir, errDir := os.Lstat(filepath.Dir(path))
	if errDir != nil || !dir.IsDir() || !owned(dir) || dir.Mode().Perm() != 0750 || dir.Mode()&os.ModeSetgid == 0 {
		return nil, errors.New("trusted ingress socket needs an owned setgid directory with mode 0750")
	}
	listener, errListen := net.Listen("unix", path)
	if errListen != nil {
		return nil, errListen
	}
	if errMode := os.Chmod(path, 0660); errMode != nil {
		_ = listener.Close()
		return nil, errMode
	}
	return listener, nil
}

func backendHTTP(target string, trusted bool, transport http.RoundTripper, errLog *stdlog.Logger) http.Handler {
	destination := &url.URL{Scheme: "http", Host: target}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  errLog,
		// Keep request paths, header values and upstream details out of logs.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "gateway unavailable", http.StatusBadGateway)
		},
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(destination)
			request.Out.Host = request.In.Host
			if trusted {
				request.Out.Header.Set("X-Forwarded-For", request.In.Header.Get("X-CLIProxy-Client-IP"))
			} else {
				request.SetXForwarded()
			}
			// Gin can fall back to this alternate client IP header.
			request.Out.Header.Del("X-Real-IP")
			request.Out.Header.Del("X-CLIProxy-Client-IP")
		},
	}
	if !trusted {
		return proxy
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("X-CLIProxy-Client-IP")
		if len(values) == 1 {
			ip, errIP := netip.ParseAddr(values[0])
			if errIP == nil && ip.Zone() == "" {
				proxy.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "trusted ingress requires a single client IP", http.StatusBadRequest)
	})
}

func checkListenAddress(address string) error {
	host, _, errSplit := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if errSplit != nil || ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		return errors.New("gate listeners require an explicit private or loopback IP")
	}
	return nil
}

func main() {
	var listen []string
	flag.Func("listen", "HTTP listen address (repeat for additional addresses)", func(address string) error {
		if err := checkListenAddress(address); err != nil {
			return err
		}
		listen = append(listen, address)
		return nil
	})
	resp := flag.String("resp", "", "private Keeper RESP listen address")
	target := flag.String("target", "", "private HTTP/RESP backend address")
	socket := flag.String("control", "", "local control socket")
	ingress := flag.String("trusted-ingress", "", "Unix HTTP listener for authorized ingress proxies")
	flag.Parse()
	if len(listen) == 0 || *target == "" || *socket == "" || flag.NArg() != 0 ||
		(*resp != "" && checkListenAddress(*resp) != nil) {
		log.WithField("component", "release-gate").Error("invalid listener or target arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, listen, *resp, *target, *socket, *ingress); err != nil {
		log.WithField("component", "release-gate").Error("listener startup or serving failed")
		os.Exit(1)
	}
}
