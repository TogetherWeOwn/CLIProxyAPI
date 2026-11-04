// Command inputguard compares a single restricted stdin request. It has no path,
// environment configuration, rendering, daemon or mutation interface.
package main

import (
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/ops/host-recovery/inputguard"
)

func main() {
	input := os.Stdin
	if len(os.Args) != 1 {
		inputguard.Serve(strings.NewReader(""), os.Stdout)
		os.Exit(1)
	}
	if !inputguard.Serve(input, os.Stdout) {
		os.Exit(1)
	}
}
