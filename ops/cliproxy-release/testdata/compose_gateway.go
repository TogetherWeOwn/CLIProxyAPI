// Disposable Compose backend. Every socket, artifact and state file is synthetic.
package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	switch filepath.Base(os.Args[0]) {
	case "sha256sum":
		data, err := os.ReadFile(os.Args[len(os.Args)-1])
		if err != nil {
			return err
		}
		fmt.Printf("%x  %s\n", sha256.Sum256(data), os.Args[len(os.Args)-1])
	case "stat":
		for _, path := range os.Args[4:] {
			var info syscall.Stat_t
			if err := syscall.Stat(path, &info); err != nil {
				return err
			}
			fmt.Printf("%d:%d\n", info.Dev, info.Ino)
		}
	default:
		if len(os.Args) == 2 && os.Args[1] == "keeper" {
			for {
				time.Sleep(time.Hour)
			}
		}
		return serve()
	}
	return nil
}

func serve() error {
	data, err := os.ReadFile("/config.yaml")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	phase, version, mode := fields[0], fields[1], fields[2]
	library, err := os.ReadFile("/plugins/meta-v" + version + ".so")
	if err != nil || string(library) != phase {
		return errors.New("wrong synthetic library")
	}
	identity, err := os.ReadFile("/phase")
	if err != nil || string(identity) != phase {
		return errors.New("wrong synthetic image")
	}
	registration := fmt.Sprintf("pluginhost: plugin registered plugin_id=meta plugin_name=Meta version=%s", version)
	if fields[3] == "file" {
		name, err := os.Hostname()
		if err != nil {
			return err
		}
		if err := os.WriteFile("/probe/registration-"+name, []byte(registration+"\n"), 0o600); err != nil {
			return err
		}
	} else {
		log.Print(registration)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, phase)
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, _ *http.Request) {
		for _, path := range []string{"/oauth/state", "/kv/state"} {
			if err := os.WriteFile(path, []byte("newer"), 0o600); err != nil {
				http.Error(w, "synthetic write failed", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"data":[{"id":%q}]}`, "synthetic-"+phase)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"synthetic\"},\"finish_reason\":null}]}\n\n")
		if mode == "hang" {
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	})
	socket := "/probe/backend.sock"
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o666); err != nil {
		return err
	}
	return http.Serve(listener, mux)
}
