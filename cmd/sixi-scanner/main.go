// Command sixi is a command-line red-team scanner for LLM agents.
//
// It sends probe prompts to an endpoint you are authorised to test, judges the
// replies, and writes the evidence to JSON, SARIF or Markdown.
//
// Usage:
//
//	sixi-scanner scan     --url https://agent.example/v1/chat/completions
//	sixi-scanner list
//	sixi-scanner version
//
// Run "sixi-scanner <command> --help" for the flags of a command.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

const toolName = "sixi-scanner"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process exit, so the CLI can be tested in-process.
//
// Exit codes are the interface to CI, so they are defined once here rather than
// being encoded inside error values:
//
//	0  the scan ran and found nothing
//	1  the scan ran and found something
//	2  the command could not run — bad flags, unreachable target, bad path
//	3  the scan was interrupted before it covered what it was asked to cover
//
// A command returns its exit code and an error separately. Bundling the two
// into one value invites the failure this file originally had: a command that
// needed to signal exit 1 with nothing to report returned a non-nil wrapper
// around a nil error, which printed as a panic instead of exiting.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}

	cmd, rest := args[0], args[1:]

	switch cmd {
	case "scan":
		return finish(cmdScan(rest, stdout, stderr), stderr)

	case "list":
		return finish(cmdList(rest, stdout), stderr)

	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%s %s\n", toolName, version)
		return exitOK

	case "help", "--help", "-h":
		usage(stdout)
		return exitOK

	default:
		return finish(result{exitUsage, fmt.Errorf("unknown command %q; run \"sixi-scanner help\"", cmd)}, stderr)
	}
}

// Exit codes. Named so that a reader does not have to remember which is which.
const (
	exitOK          = 0 // ran, found nothing
	exitFindings    = 1 // ran, found something
	exitUsage       = 2 // could not run
	exitInterrupted = 3 // stopped before covering what it was asked to cover
)

// result is a command's exit code and its error, kept separate.
type result struct {
	code int
	err  error
}

// succeeded is the success result for a command that returns nothing but an
// error. It keeps the call sites from having to spell out a zero code.
func succeeded(err error) result {
	if err != nil {
		return result{code: exitUsage, err: err}
	}
	return result{code: exitOK}
}

// finish prints an error, if there is one, and returns the exit code to use.
// An error always means the command failed, whatever code it asked for — a
// scan that found something *and* could not write its report has not succeeded.
func finish(r result, stderr io.Writer) int {
	if r.err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", toolName, r.err)
		return exitUsage
	}
	return r.code
}

func usage(w io.Writer) {
	fmt.Fprint(w, `sixi — red-team scanner for LLM agents

Commands:
  scan       Send probe prompts to an endpoint and report what broke
  list       List the built-in techniques, or describe one in detail
  version    Print the version

Get started:
  sixi-scanner list
  sixi-scanner scan --url https://your-agent.example/v1/chat/completions

Only scan endpoints you are authorised to test. See SECURITY.md.
`)
}

// splitCommaList parses a comma-separated flag value, trimming spaces and
// dropping empties, so "--only a, b, ,c" behaves.
func splitCommaList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
