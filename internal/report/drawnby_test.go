package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A finding filed under a shared test names the techniques whose payloads drew it. Without that a
// reader has a rule identifier nothing can be re-run with, in every format.
func TestEveryFormatSaysWhichTechniquesDrewASharedFinding(t *testing.T) {
	s := fixture()
	if len(s.Findings) == 0 {
		t.Fatal("the fixture has no finding to mark")
	}
	s.Findings = s.Findings[:1]
	s.Findings[0].TechniqueID = "probe.llm07.rule-recitation"
	s.Findings[0].DrawnBy = []string{"probe.test.a", "probe.test.b"}

	var md, sarif, js bytes.Buffer
	if err := WriteMarkdown(&md, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(&sarif, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&js, s); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(md.String(), "| **Drawn by** | `probe.test.a`, `probe.test.b` |") {
		t.Errorf("markdown has no drawn-by row:\n%s", md.String())
	}
	if !strings.Contains(sarif.String(), "drawn by probe.test.a, probe.test.b") {
		t.Errorf("SARIF message does not name the techniques:\n%s", sarif.String())
	}

	var got struct {
		Findings []struct {
			DrawnBy []string `json:"drawn_by"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || len(got.Findings[0].DrawnBy) != 2 {
		t.Errorf("JSON drawn_by = %+v, want both techniques", got.Findings)
	}
}

// A technique's own finding already says what was sent, so the field stays out of it.
func TestATechniquesOwnFindingHasNoDrawnBy(t *testing.T) {
	var js bytes.Buffer
	if err := WriteJSON(&js, fixture()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(js.String(), "drawn_by") {
		t.Error("drawn_by appears on a finding that was filed under its own technique")
	}
}
