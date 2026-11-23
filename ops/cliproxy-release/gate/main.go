// The release gate stays running while the gateway behind it is replaced.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
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
			defer client.Close()
			upstream, errDial := net.DialTimeout("tcp", target, 5*time.Second)
			if errDial != nil {
				return
			}
			defer upstream.Close()
			// When Keeper disconnects, close the upstream too, even if it
			// is blocked in a queue command and never writes a response.
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, client)
				_ = upstream.Close()
				close(done)
			}()
			_, _ = io.Copy(client, upstream)
			_ = client.Close()
			<-done
		}()
	}
}

func run(listen []string, resp, target, socket string) error {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return errors.New("target must be a host and port")
	}
	// Require a private directory. Do not unlink a possibly live control socket.
	dir, errStat := os.Lstat(filepath.Dir(socket))
	if errStat != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
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
	defer control.Close()
	if errMode := os.Chmod(socket, 0600); errMode != nil {
		return errMode
	}
	tcp := make([]net.Listener, 0, len(listen))
	for _, addr := range listen {
		data, errData := net.Listen("tcp", addr)
		if errData != nil {
			return errData
		}
		defer data.Close()
		tcp = append(tcp, data)
	}
	errs := make(chan error, len(tcp)+2)
	if resp != "" {
		keeper, errKeeper := net.Listen("tcp", resp)
		if errKeeper != nil {
			return errKeeper
		}
		defer keeper.Close()
		go func() { errs <- a.forwardRESP(keeper, target) }()
	}
	// Match a normal reverse proxy's streaming and Upgrade semantics. There
	// is no total request deadline and no externally supplied backend target.
	destination := &url.URL{Scheme: "http", Host: target}
	proxy := &httputil.ReverseProxy{Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(destination)
		request.Out.Host = request.In.Host
	}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	proxy.Transport = transport
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	public := &http.Server{Handler: a.http(proxy), ReadHeaderTimeout: 10 * time.Second, ErrorLog: proxy.ErrorLog}
	private := &http.Server{Handler: a.control(), ReadHeaderTimeout: 2 * time.Second, ErrorLog: proxy.ErrorLog}
	for _, data := range tcp {
		go func() { errs <- public.Serve(data) }()
	}
	go func() { errs <- private.Serve(control) }()
	return <-errs
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
	flag.Parse()
	if len(listen) == 0 || *target == "" || *socket == "" || flag.NArg() != 0 ||
		(*resp != "" && checkListenAddress(*resp) != nil) {
		log.Print("listen, target and control are required")
		os.Exit(2)
	}
	if err := run(listen, *resp, *target, *socket); err != nil {
		log.Print("release gate failed")
		os.Exit(1)
	}
}
