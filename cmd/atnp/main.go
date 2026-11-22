package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/guttenbergovitz/angry-turnip/internal/cli"
	"github.com/guttenbergovitz/angry-turnip/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message != "" {
				fmt.Fprintln(os.Stderr, exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: atnp <scan|report|ci|explain|baseline|version> [args]")
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "scan":
		return cli.Scan(cmdArgs)
	case "report":
		return cli.Report(cmdArgs)
	case "ci":
		return cli.CI(cmdArgs)
	case "explain":
		return cli.Explain(cmdArgs)
	case "baseline":
		return cli.Baseline(cmdArgs)
	case "version":
		fmt.Fprintf(out, "atnp %s\n", version.GetFull())
		return nil
	default:
		return fmt.Errorf("unknown command: %s\nusage: atnp <scan|report|ci|explain|baseline|version> [args]", cmd)
	}
}
