// Command composecmd validates restricted Compose model correspondence on stdin.
// It has no file, daemon, application, plugin, install or service-start interface.
package main

import (
	"io"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/ops/host-recovery/inputguard"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetOutput(io.Discard)
	if !inputguard.ServeCompose(os.Stdin, os.Stdout) {
		os.Exit(1)
	}
}
