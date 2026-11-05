// Command runtime-probe is an inert, statically linked disposable OCI task.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func run() error {
	// Both processes keep running on TERM, so cgroup termination is observable.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	if len(os.Args) == 2 && os.Args[1] == "child" {
		ready := os.NewFile(3, "ready")
		if _, err := ready.Write([]byte{1}); err != nil {
			return err
		}
		if err := ready.Close(); err != nil {
			return err
		}
	} else {
		reader, writer, err := os.Pipe()
		if err != nil {
			return err
		}
		child := exec.Command("/probe", "child")
		child.ExtraFiles = []*os.File{writer}
		if errStart := child.Start(); errStart != nil {
			return errStart
		}
		if errClose := writer.Close(); errClose != nil {
			return errClose
		}
		var ready [1]byte
		if n, errRead := reader.Read(ready[:]); errRead != nil || n != 1 || ready[0] != 1 {
			return fmt.Errorf("child readiness: n=%d err=%v", n, errRead)
		}
		if errClose := reader.Close(); errClose != nil {
			return errClose
		}
		if errWrite := os.WriteFile("/ready", []byte("parent-and-child-ready\n"), 0600); errWrite != nil {
			return errWrite
		}
	}
	for range signals {
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
