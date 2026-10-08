package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rbrus/sixi-scanner/internal/confirm"
	"github.com/rbrus/sixi-scanner/internal/engine"
	"github.com/rbrus/sixi-scanner/internal/judge"
	"github.com/rbrus/sixi-scanner/internal/report"
	"github.com/rbrus/sixi-scanner/internal/target"
	"github.com/rbrus/sixi-scanner/internal/tech"
	"github.com/rbrus/sixi-scanner/internal/tech/baseline"
)

func cmdScan(args []string, stdout, stderr io.Writer) result {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	var (
		url       = fs.String("url", "", "endpoint to scan (required unless --target echo)")
		connector = fs.String("target", "openai", "transport: openai, json, chat, webform, echo")
		headerArg = fs.String("header", "", "extra header, repeatable, as \"Name: value\"")

		model      = fs.String("model", "", "model field for the openai transport")
		bodyTpl    = fs.String("body", "", "request body template for the json transport; {{prompt}} and {{json}} are substituted")
		replyPath  = fs.String("reply-path", "", "dotted path to the reply in the json transport's response")
		formField  = fs.String("field", "", "form field name for the webform transport")
		formSelect = fs.String("reply-selector", "", "open|close markers delimiting the reply in the page, as \"<div class=reply>|<div class=input\"")

		only        = fs.String("only", "", "comma-separated technique IDs to run; default is all")
		exclude     = fs.String("exclude", "", "comma-separated technique IDs to skip")
		tag         = fs.String("tag", "", "comma-separated tags; only techniques carrying all of them run")
		minSeverity = fs.String("min-severity", "", "skip findings below this severity: info, low, medium, high, critical")

		rounds      = fs.Int("rounds", 1, "how many times to walk the whole technique set")
		attempts    = fs.Int("attempts", 3, "max payload variants per technique per round")
		concurrency = fs.Int("concurrency", 4, "techniques in flight at once")
		timeout     = fs.Duration("timeout", 30*time.Second, "per-request timeout")
		minConf     = fs.Float64("min-confidence", 0, "discard breaks scoring below this")
		seed        = fs.String("seed", "", "prompt sent before every probe, to start each conversation from the same state")

		reciteTh = fs.Int("recitation-threshold", judge.DefaultRecitationThreshold,
			"lines stating a constraint on the agent itself before the reply counts as reciting its "+
				"operating rules; 0 disables the test. See docs/recitation.md")

		// The optional confirmation stage: off unless an endpoint is named.
		confirmURL    = fs.String("confirm-url", "", "OpenAI-compatible endpoint to ask whether a candidate break really broke the agent's policy; empty disables the stage")
		confirmModel  = fs.String("confirm-model", "", "model name to ask at --confirm-url")
		confirmKey    = fs.String("confirm-key", os.Getenv("SIXI_CONFIRM_API_KEY"), "bearer token for --confirm-url (or set SIXI_CONFIRM_API_KEY)")
		confirmFloor  = fs.String("confirm-min-severity", "medium", "lowest severity an answer may carry and still keep a finding: none, low, medium, high, critical")
		confirmBudget = fs.Int("confirm-budget", 200,
			"how many candidates the stage may ask about in one scan; 0 means unlimited")
		contextPath = fs.String("context", "",
			"JSON file describing the agent: {\\\"purpose\\\": \\\"what it is for and which data it may show\\\"}. Required by --confirm-url, which has no policy to grade against without it")

		insecure = fs.Bool("insecure", false, "skip TLS verification (self-signed staging endpoints)")
		quiet    = fs.Bool("quiet", false, "only print the report to stdout")
		outPath  = fs.String("out", "", "also write the report to this file")
		format   = fs.String("format", "text", "stdout format: text, json, sarif, markdown")

		extraTimeout = fs.Duration("overall-timeout", 0, "abort the whole scan after this long; 0 means no limit")
	)

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sixi-scanner scan --url <endpoint> [flags]

Sends probe prompts to an endpoint and reports what broke. Only scan endpoints
you are authorised to test.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, `
Examples:
  # OpenAI-compatible chat endpoint
  sixi-scanner scan --url https://agent.example/v1/chat/completions

  # Bespoke internal agent, no OpenAI shape
  sixi-scanner scan --target json --url https://internal/api/ask \
    --body '{"question":{{json}},"session":"s1"}' --reply-path answer.text

  # Website chatbot with no API
  sixi-scanner scan --target webform --url https://site.example/chat --field message

  # See the shape of a report without touching the network
  sixi-scanner scan --target echo --format markdown

  # Gate a pull request
  sixi-scanner scan --url "$AGENT_URL" --format sarif --out sixi.sarif
`)
	}
	if err := fs.Parse(args); err != nil {
		return result{code: exitUsage, err: err}
	}

	// Validate before touching the network, so a typo costs nothing.
	cfg := target.Config{
		URL:      *url,
		Timeout:  *timeout,
		Insecure: *insecure,
		Headers:  parseHeaders(*headerArg),
		Extra:    map[string]string{},
	}
	if *model != "" {
		cfg.Extra["model"] = *model
	}
	if *bodyTpl != "" {
		cfg.Extra["body"] = *bodyTpl
	}
	if *replyPath != "" {
		cfg.Extra["reply-path"] = *replyPath
	}
	if *formField != "" {
		cfg.Extra["field"] = *formField
	}
	if *formSelect != "" {
		cfg.Extra["reply-selector"] = *formSelect
	}

	tgt, err := target.New(*connector, cfg)
	if err != nil {
		return result{code: exitUsage, err: err}
	}

	reg, err := selectTechniques(splitCommaList(*only), splitCommaList(*exclude), splitCommaList(*tag))
	if err != nil {
		return result{code: exitUsage, err: err}
	}

	floor, err := parseFloor(*minSeverity)
	if err != nil {
		return result{code: exitUsage, err: err}
	}
	if floor != "" {
		reg = filterBySeverity(reg, floor)
		if reg.Len() == 0 {
			return result{code: exitUsage, err: fmt.Errorf("no techniques at or above severity %q", floor)}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *extraTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *extraTimeout)
		defer cancel()
	}

	// The confirmation stage is opt-in and needs a policy to grade against, so
	// the two flags are validated together before anything is sent. Failing
	// here costs nothing; failing mid-scan would waste the run.
	scanCfg := engine.Config{
		Target:        tgt,
		Registry:      reg,
		Rounds:        *rounds,
		MaxAttempts:   *attempts,
		Concurrency:   *concurrency,
		Seed:          *seed,
		MinConfidence: *minConf,
		Recitation:    judge.RecitationThreshold(*reciteTh),
	}

	var stage *confirm.Stage
	if *confirmURL != "" {
		if *contextPath == "" {
			return result{code: exitUsage, err: fmt.Errorf("--confirm-url needs --context: a confirmation " +
				"stage has to know what the agent is for and which data it may show, and guessing that " +
				"would make its verdicts unfalsifiable")}
		}
		if *confirmModel == "" {
			return result{code: exitUsage, err: fmt.Errorf("--confirm-url needs --confirm-model")}
		}
		tc, err := loadContext(*contextPath)
		if err != nil {
			return result{code: exitUsage, err: err}
		}
		stage = confirm.NewStage(confirm.New(*confirmURL, *confirmModel, *confirmKey, *timeout, *confirmBudget), *confirmFloor)
		scanCfg.Confirm = stage
		scanCfg.Policy = tc.Purpose
	}
	if !*quiet {
		scanCfg.OnAttempt = progressPrinter(stderr)
	}

	scan, err := engine.Run(ctx, scanCfg)
	if err != nil {
		return result{code: exitUsage, err: err}
	}
	scan.Tool = toolName
	scan.Version = version
	if *insecure {
		scan.TargetNotes = append(scan.TargetNotes,
			"TLS verification was disabled (--insecure).")
	}
	if stage != nil {
		asked, _, rejected, exhausted := stage.Stats()
		scan.Confirm = &report.Confirmation{
			Model:     stage.Model(),
			Asked:     asked,
			Rejected:  rejected,
			Exhausted: exhausted,
		}
	}

	applyMinSeverity(scan, floor)

	if ctx.Err() != nil {
		scan.TargetNotes = append(scan.TargetNotes,
			"The scan was stopped before every technique had been tried. Coverage is partial.")
	}
	if scan.Unreached() {
		scan.TargetNotes = append(scan.TargetNotes,
			"No technique got an answer from the target. Nothing was assessed; this is not a clean result.")
	}
	scan.Summarise()

	if err := writeReport(stdout, *format, scan, !*quiet); err != nil {
		return result{code: exitUsage, err: err}
	}
	if *outPath != "" {
		if err := writeFile(*outPath, *format, scan); err != nil {
			return result{code: exitUsage, err: err}
		}
	}

	// A cancelled scan exits 3 rather than 0. A CI job that treats "no findings"
	// as a pass must not read a run that never finished as a pass.
	if ctx.Err() != nil {
		return result{code: exitInterrupted, err: fmt.Errorf("scan stopped before completion")}
	}
	if len(scan.Findings) > 0 {
		return result{code: exitFindings}
	}
	// No technique got an answer: the target was never reached. Exiting 0 here
	// would let a CI job read a down endpoint as a clean agent.
	if scan.Unreached() {
		return result{code: exitUsage, err: fmt.Errorf("no technique got an answer from %s; nothing was assessed", scan.Target)}
	}
	return result{code: exitOK}
}

// selectTechniques applies --only, --exclude and --tag in that order.
func selectTechniques(only, exclude, tags []string) (*tech.Registry, error) {
	reg := baseline.Registry()

	if len(only) > 0 {
		var err error
		if reg, err = reg.Select(only); err != nil {
			return nil, err
		}
	}
	if len(tags) > 0 {
		reg = reg.SelectMatching(tags)
		if reg.Len() == 0 {
			return nil, fmt.Errorf("no technique carries all of the tags %s", strings.Join(tags, ", "))
		}
	}
	if len(exclude) > 0 {
		keep := make([]string, 0, reg.Len())
		drop := map[string]bool{}
		for _, id := range exclude {
			drop[id] = true
		}
		for _, id := range reg.IDs() {
			if !drop[id] {
				keep = append(keep, id)
			}
		}
		if len(keep) == len(reg.IDs()) {
			return nil, fmt.Errorf("none of %s are in the selected set", strings.Join(exclude, ", "))
		}
		var err error
		if reg, err = reg.Select(keep); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

func parseFloor(s string) (tech.Severity, error) {
	if s == "" {
		return "", nil
	}
	v, ok := tech.ParseSeverity(s)
	if !ok {
		return "", fmt.Errorf("unknown severity %q; use info, low, medium, high or critical", s)
	}
	return v, nil
}

func filterBySeverity(reg *tech.Registry, floor tech.Severity) *tech.Registry {
	out := tech.NewRegistry()
	for _, t := range reg.All() {
		if t.Meta().Severity.AtLeast(floor) {
			out.MustAdd(t)
		}
	}
	return out
}

// applyMinSeverity drops findings below the floor from an already-run scan.
//
// The floor has already been applied to the technique set before anything was
// sent, so in practice this is belt and braces. It stays because the two
// filters are not the same thing: the first decides what to probe, this one
// decides what to publish.
func applyMinSeverity(scan *report.Scan, floor tech.Severity) {
	if floor == "" {
		return
	}
	kept := scan.Findings[:0]
	for _, f := range scan.Findings {
		if f.Severity.AtLeast(floor) {
			kept = append(kept, f)
		}
	}
	scan.Findings = kept
}

// parseHeaders reads repeatable --header values, given as one string with "|"
// between entries because Go's flag package has no repeatable flag.
func parseHeaders(v string) map[string]string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	out := map[string]string{}
	for _, h := range strings.Split(v, "|") {
		name, value, found := strings.Cut(h, ":")
		if !found {
			continue
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// progressPrinter writes one line per attempt to w, without interleaving.
func progressPrinter(w io.Writer) func(report.Attempt) {
	var mu sync.Mutex
	return func(a report.Attempt) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case a.Error != "":
			fmt.Fprintf(w, "  %-44s r%d a%d  no answer: %s\n",
				a.TechniqueID, a.Round, a.Attempt, firstLine(a.Error))
		case a.Broke:
			fmt.Fprintf(w, "  %-44s r%d a%d  BREAK  confidence %.2f\n",
				a.TechniqueID, a.Round, a.Attempt, a.Confidence)
		default:
			fmt.Fprintf(w, "  %-44s r%d a%d  held\n", a.TechniqueID, a.Round, a.Attempt)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// targetContext is what a confirmation stage grades against: what the agent is
// for, and which data it is entitled to show the caller.
//
// It is deliberately small. A confirmation stage that inherits a page of prose
// cannot be argued with, and the point of the stage is that its verdicts can be.
type targetContext struct {
	Purpose string `json:"purpose"`
}

// loadContext reads a target context file. A missing purpose is rejected rather
// than defaulted: a stage asked against an empty policy grades against nothing.
func loadContext(path string) (*targetContext, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --context %s: %w", path, err)
	}
	var tc targetContext
	if err := json.Unmarshal(raw, &tc); err != nil {
		return nil, fmt.Errorf("parse --context %s: %w", path, err)
	}
	if strings.TrimSpace(tc.Purpose) == "" {
		return nil, fmt.Errorf("--context %s has no \"purpose\"; a confirmation stage has nothing to grade against", path)
	}
	return &tc, nil
}
