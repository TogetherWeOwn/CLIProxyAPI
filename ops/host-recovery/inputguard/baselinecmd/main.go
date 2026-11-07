// Command baselinecmd validates restricted restored inputs without service access.
package main

import (
	"io"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/ops/host-recovery/inputguard"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetOutput(io.Discard)
	if !inputguard.ServeBaseline(os.Stdin, os.Stdout) {
		os.Exit(1)
	}
}
