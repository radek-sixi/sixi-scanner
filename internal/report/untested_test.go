package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// partialScan is a scan where one technique was assessed, one was never answered and one could not
// be run against the connector.
func partialScan() *Scan {
	s := fixture()
	s.Findings = nil
	s.Options.TechniqueIDs = []string{
		"probe.llm02.system-prompt-leak",
		"probe.llm10.unbounded-consumption",
		"probe.llm06.refund-cap-split",
	}
	s.NoAnswer = []string{"probe.llm10.unbounded-consumption"}
	s.Unsupported = []Unsupported{{
		TechniqueID: "probe.llm06.refund-cap-split",
		Reason:      "this target's connector cannot hold a conversation",
	}}
	return s
}

// With no finding, "nothing broke" is only true of the techniques that got a reply. A scan where
// some never did is neither clean nor unreached, and it gets its own exit code.
func TestExitCodeIsThreeWhenSomeTechniquesWentUnanswered(t *testing.T) {
	s := partialScan()
	if !s.Partial() {
		t.Fatal("a scan with an unanswered technique is not reported as partial")
	}
	if got := s.ExitCode(); got != 3 {
		t.Errorf("exit code = %d, want 3", got)
	}
	if got := s.Assessed(); got != 1 {
		t.Errorf("assessed = %d, want 1", got)
	}

	// A finding outranks partial coverage.
	withFinding := partialScan()
	withFinding.Findings = fixture().Findings
	if got := withFinding.ExitCode(); got != 1 {
		t.Errorf("exit code = %d with a finding, want 1", got)
	}
}

// A declined technique is a property of the connector, not something that went wrong, so on its
// own it must not turn a clean scan into a failed one: the default connector declines every
// multi-turn probe, and every scan through it would exit 3.
func TestUnsupportedAloneIsNotPartialCoverage(t *testing.T) {
	s := partialScan()
	s.NoAnswer = nil
	if s.Partial() {
		t.Error("a declined technique made the scan partial")
	}
	if got := s.ExitCode(); got != 0 {
		t.Errorf("exit code = %d, want 0", got)
	}
}

// Markdown is the format sent to the person who decides. It has to say what was not tested, and it
// must not count those techniques among the ones that found nothing.
func TestMarkdownListsWhatWasNotTested(t *testing.T) {
	var buf strings.Builder
	if err := WriteMarkdown(&buf, partialScan()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"## Not tested",
		"`probe.llm10.unbounded-consumption`",
		"`probe.llm06.refund-cap-split`",
		"cannot hold a conversation",
		"across 1 of the 3 selected techniques",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "across 3 techniques") {
		t.Error("untested techniques were counted among those that found no break")
	}
	if strings.Index(out, "## Not tested") > strings.Index(out, "What this report is not") {
		t.Error("the untested list is below the footer, where nobody reads it")
	}
}

func TestMarkdownOmitsTheSectionWhenEverythingWasTested(t *testing.T) {
	var buf strings.Builder
	if err := WriteMarkdown(&buf, fixture()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Not tested") {
		t.Error("a fully tested scan carries a Not tested section")
	}
}

// SARIF results are findings, so an untested technique has nowhere to appear but the invocation.
func TestSARIFNotifiesWhatWasNotTested(t *testing.T) {
	var buf strings.Builder
	if err := WriteSARIF(&buf, partialScan()); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				ExitCode            int  `json:"exitCode"`
				Notifications       []struct {
					Descriptor struct{ ID string }   `json:"descriptor"`
					Level      string                `json:"level"`
					Message    struct{ Text string } `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &log); err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	inv := log.Runs[0].Invocations[0]

	if !inv.ExecutionSuccessful || inv.ExitCode != 3 {
		t.Errorf("a partial scan ran, with exit 3: got successful=%v exit=%d", inv.ExecutionSuccessful, inv.ExitCode)
	}
	if len(inv.Notifications) != 2 {
		t.Fatalf("notifications = %d, want one per untested technique", len(inv.Notifications))
	}
	byID := map[string]string{}
	for _, n := range inv.Notifications {
		if n.Level == "" || n.Message.Text == "" {
			t.Errorf("a notification is missing its level or message: %+v", n)
		}
		byID[n.Descriptor.ID] = n.Message.Text
	}
	if !strings.Contains(byID[sarifNoAnswer], "probe.llm10.unbounded-consumption") {
		t.Errorf("the unanswered technique is not named: %q", byID[sarifNoAnswer])
	}
	if !strings.Contains(byID[sarifUnsupported], "probe.llm06.refund-cap-split") {
		t.Errorf("the declined technique is not named: %q", byID[sarifUnsupported])
	}
}

func TestSARIFCarriesNoNotificationsWhenEverythingWasTested(t *testing.T) {
	var buf strings.Builder
	if err := WriteSARIF(&buf, fixture()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "toolExecutionNotifications") {
		t.Error("a fully tested scan carries notifications")
	}
}

// A technique that ran and could not be judged is in every format, for the same reason an untested
// one is: left out, it reads as having passed.
func TestEveryFormatListsWhatCouldNotBeDecided(t *testing.T) {
	s := fixture()
	s.Findings = nil
	s.Undecided = []Undecided{{
		TechniqueID: "probe.llm09.false-action-claim",
		Reason:      "the reply stated a completed action, and this target's connector reports no tool calls",
	}}

	var md, sarif, js strings.Builder
	if err := WriteMarkdown(&md, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(&sarif, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&js, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "## Could not be decided") ||
		!strings.Contains(md.String(), "`probe.llm09.false-action-claim`") {
		t.Errorf("markdown does not list the undecided technique:\n%s", md.String())
	}
	if !strings.Contains(sarif.String(), `"sixi/undecided"`) ||
		!strings.Contains(sarif.String(), "probe.llm09.false-action-claim") {
		t.Errorf("SARIF carries no notification for it:\n%s", sarif.String())
	}
	var got struct {
		Undecided []Undecided `json:"undecided"`
	}
	if err := json.Unmarshal([]byte(js.String()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Undecided) != 1 {
		t.Errorf("JSON undecided = %+v", got.Undecided)
	}
}
