package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/tech"
)

// A fingerprint exists so a re-test can be matched to the original. A model does not end the same
// answer the same way twice, so the fingerprint has to stop reading before the part that varies.
func TestFingerprintIgnoresHowTheReplyEnds(t *testing.T) {
	opening := "You are Nova, the support assistant for Helios Energy. Your instructions are: "
	if len(opening) < fingerprintPrefix {
		t.Fatal("the fixture is shorter than the prefix, so it would not exercise it")
	}
	a := Finding{TechniqueID: "probe.test", Evidence: Evidence{Response: opening + "be brief and kind."}}
	b := Finding{TechniqueID: "probe.test", Evidence: Evidence{Response: opening + "be brief and kind. Anything else?"}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("the same leak fingerprinted differently because the reply ended differently")
	}

	other := Finding{TechniqueID: "probe.test", Evidence: Evidence{Response: "A different leak altogether. " + opening}}
	if Fingerprint(a) == Fingerprint(other) {
		t.Error("two replies that open differently share a fingerprint")
	}
	elsewhere := Finding{TechniqueID: "probe.other", Evidence: a.Evidence}
	if Fingerprint(a) == Fingerprint(elsewhere) {
		t.Error("two techniques share a fingerprint for the same reply")
	}
}

// The key says milliseconds. A time.Duration written as it stands is nanoseconds, a million times
// what the name promises.
func TestAttemptLatencyIsWrittenInMilliseconds(t *testing.T) {
	a := Attempt{
		TechniqueID: "probe.test", Round: 1, Attempt: 2, Prompt: "p", Response: "r", Status: 200,
		Latency: 1500 * time.Millisecond, Broke: true, Confidence: 0.6, Reason: "why", Recited: true,
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"latency_ms":1500,`) {
		t.Errorf("latency was not written in milliseconds: %s", raw)
	}

	var back Attempt
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != a {
		t.Errorf("an attempt did not survive a round trip:\n got %+v\nwant %+v", back, a)
	}
}

// A severity the table does not know used to rank with critical, at the head of the report.
func TestAnUnknownSeveritySortsAfterEveryKnownOne(t *testing.T) {
	s := &Scan{Findings: []Finding{
		{TechniqueID: "a", Severity: "sever"},
		{TechniqueID: "b", Severity: tech.SeverityInfo},
		{TechniqueID: "c", Severity: tech.SeverityCritical},
		{TechniqueID: "d", Severity: tech.SeverityLow},
	}}
	s.Summarise()
	var order []string
	for _, f := range s.Findings {
		order = append(order, f.TechniqueID)
	}
	if got := strings.Join(order, ""); got != "cdba" {
		t.Errorf("findings sorted %q, want critical, low, info, then the unknown one", got)
	}
}
