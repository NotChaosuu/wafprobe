package main

import (
	"fmt"
	"os"

	"github.com/NotChaosuu/wafprobe/internal/tui"
)

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runMenu opens the TUI. Needs a real terminal; piped output gets usage instead.
func runMenu() {
	if !isTTY(os.Stdin) || !isTTY(os.Stdout) {
		fmt.Fprint(os.Stderr, topUsage)
		os.Exit(2)
	}
	if err := tui.Run(Version); err != nil {
		fatal(err)
	}
}
