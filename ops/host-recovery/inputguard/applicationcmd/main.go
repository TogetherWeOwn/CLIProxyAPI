// Command applicationguard adds host-owned config validation to exact-input checks.
// It accepts no paths, arguments, environment configuration or service operations.
package main

import (
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/ops/host-recovery/inputguard"
)

func main() {
	if len(os.Args) != 1 {
		inputguard.ServeApplication(strings.NewReader(""), os.Stdout)
		os.Exit(1)
	}
	if !inputguard.ServeApplication(os.Stdin, os.Stdout) {
		os.Exit(1)
	}
}
