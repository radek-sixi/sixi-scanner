package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// finish used to return 2 for every error, which made the documented exit 3 unreachable: the
// interrupted path sets both a code and an error. An error must still override a code that claims
// the run completed.
func TestFinishKeepsAFailureCodeAndOverridesASuccessCode(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		name string
		in   result
		want int
	}{
		{"no error keeps a clean exit", result{code: exitOK}, exitOK},
		{"no error keeps a findings exit", result{code: exitFindings}, exitFindings},
		{"an error overrides a clean exit", result{code: exitOK, err: boom}, exitUsage},
		{"an error overrides a findings exit", result{code: exitFindings, err: boom}, exitUsage},
		{"an error keeps a usage exit", result{code: exitUsage, err: boom}, exitUsage},
		{"an error keeps an interrupted exit", result{code: exitPartial, err: boom}, exitPartial},
	} {
		if got := finish(c.in, io.Discard); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

// The README's contract, end to end: a scan stopped before it covered what it was asked to cover
// exits 3, so that a CI job cannot read a run that never finished as a pass — or as a bad flag.
func TestAnInterruptedScanExitsThree(t *testing.T) {
	_, stderr, code := exec("scan", "--target", "echo", "--overall-timeout", "1ns", "--quiet")
	if code != exitPartial {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitPartial, stderr)
	}
	if !strings.Contains(stderr, "stopped before completion") {
		t.Errorf("the reason is not stated: %q", stderr)
	}
}
