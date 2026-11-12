package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/radeksixi/sixi-scanner/internal/tech"
)

// sarifVersion is the only version this writer emits.
const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifToolURI = "https://github.com/radeksixi/sixi-scanner"

// sarifFingerprintKey names the fingerprint and the version of the algorithm behind it. It is v2
// because v1 covered the whole reply rather than its opening, so the two are not comparable: a
// consumer matching on v1 must not be handed values computed another way under the same name.
const sarifFingerprintKey = "sixiScan/v2"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
	// Invocations carries the exit code, whether the run assessed anything, and
	// the techniques it could not test.
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription sarifText        `json:"shortDescription"`
	FullDescription  sarifText        `json:"fullDescription,omitempty"`
	Help             sarifText        `json:"help,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       sarifRuleProps   `json:"properties"`
	DefaultConfig    sarifLevelConfig `json:"defaultConfiguration"`
}

type sarifRuleProps struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type sarifLevelConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifText         `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int        `json:"startLine"`
	Snippet   *sarifText `json:"snippet,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
	ExitCode            int  `json:"exitCode"`
	// Notifications carries what the run could not test. SARIF results are findings, so a technique
	// that was never answered has nowhere else to appear, and a consumer reading only the results
	// would take its absence for a pass.
	Notifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Descriptor sarifDescriptorRef `json:"descriptor"`
	Level      string             `json:"level"`
	Message    sarifText          `json:"message"`
}

type sarifDescriptorRef struct {
	ID string `json:"id"`
}

// Notification descriptor IDs. They are stable strings a consumer can filter on.
const (
	sarifNoAnswer    = "sixi/no-answer"
	sarifUnsupported = "sixi/unsupported"
	sarifUndecided   = "sixi/undecided"
)

// untestedNotifications lists every selected technique the scan did not assess.
func untestedNotifications(s *Scan) []sarifNotification {
	var out []sarifNotification
	for _, id := range s.NoAnswer {
		out = append(out, sarifNotification{
			Descriptor: sarifDescriptorRef{ID: sarifNoAnswer},
			Level:      "warning",
			Message:    sarifText{Text: "Not tested: " + id + " got no answer from the target."},
		})
	}
	for _, u := range s.Unsupported {
		out = append(out, sarifNotification{
			Descriptor: sarifDescriptorRef{ID: sarifUnsupported},
			Level:      "note",
			Message:    sarifText{Text: "Not tested: " + u.TechniqueID + " cannot run against this target: " + u.Reason + "."},
		})
	}
	for _, u := range s.Undecided {
		out = append(out, sarifNotification{
			Descriptor: sarifDescriptorRef{ID: sarifUndecided},
			Level:      "warning",
			Message:    sarifText{Text: "Not decided: " + u.TechniqueID + ": " + u.Reason + "."},
		})
	}
	return out
}

// severityToSARIFLevel maps a finding severity to a SARIF level. SARIF has
// three levels, so medium and low both become "warning" and the exact severity
// travels in the rule's properties instead of being lost.
func severityToSARIFLevel(s tech.Severity) string {
	switch s {
	case tech.SeverityCritical, tech.SeverityHigh:
		return "error"
	case tech.SeverityMedium, tech.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF writes the scan as SARIF 2.1.0 for code scanning tools.
//
// SARIF describes findings against *locations in files*. A scan against a live
// endpoint has no file, so each finding is placed against a synthetic
// artifact named after the target and the evidence is carried in the region
// snippet and the message. Consumers that require a real location will show
// the synthetic one; that is the honest mapping available, and the JSON report
// is the one to read when the evidence itself is what matters.
func WriteSARIF(w io.Writer, s *Scan) error {
	s.Summarise()

	uri := "sixi-scanner://" + sanitizeURIComponent(s.Target)

	rules := make([]sarifRule, 0, len(s.Findings))
	seen := map[string]bool{}
	for _, f := range s.Findings {
		if seen[f.TechniqueID] {
			continue
		}
		seen[f.TechniqueID] = true
		rule := sarifRule{
			ID:               f.TechniqueID,
			Name:             f.Title,
			ShortDescription: sarifText{Text: f.Title},
			FullDescription:  sarifText{Text: f.Description},
			Help:             sarifText{Text: remediationMarkdown(f)},
			HelpURI:          sarifToolURI + "#" + f.TechniqueID,
			Properties: sarifRuleProps{
				Tags:     sarifTags(f),
				Severity: string(f.Severity),
			},
			DefaultConfig: sarifLevelConfig{Level: severityToSARIFLevel(f.Severity)},
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	results := make([]sarifResult, 0, len(s.Findings))
	for _, f := range s.Findings {
		snippet := &sarifText{Text: excerpt(f.Evidence.Response, 400)}
		message := f.Evidence.Reason
		if len(f.DrawnBy) > 0 {
			// The rule is the shared test, so the message is the only place a SARIF consumer
			// can learn which payloads to re-run.
			message += " (drawn by " + strings.Join(f.DrawnBy, ", ") + ")"
		}
		results = append(results, sarifResult{
			RuleID:  f.TechniqueID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifText{Text: message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: uri},
					Region:           &sarifRegion{StartLine: 1, Snippet: snippet},
				},
			}},
			Fingerprints: map[string]string{sarifFingerprintKey: f.Fingerprint},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           s.Tool,
				InformationURI: sarifToolURI,
				Version:        s.Version,
				Rules:          rules,
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				// executionSuccessful says whether the tool ran, not whether it found
				// anything: SARIF 2.1.0 §3.20.14 notes that a non-zero exit code can mean
				// "results were found", and a consumer that sees false here treats the
				// upload as a failed analysis. A scan with findings ran. So did one with
				// partial coverage, which says so in the notifications. Only a scan that
				// assessed nothing failed to run.
				ExecutionSuccessful: !s.Unreached(),
				ExitCode:            s.ExitCode(),
				Notifications:       untestedNotifications(s),
			}},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("write SARIF: %w", err)
	}
	return nil
}

func sarifTags(f Finding) []string {
	tags := []string{"security", "llm", "agentic-ai"}
	if f.Category != "" {
		tags = append(tags, f.Category)
	}
	return tags
}

func remediationMarkdown(f Finding) string {
	var b strings.Builder
	b.WriteString(f.Remediation)
	if len(f.Rounds) > 1 {
		fmt.Fprintf(&b, "\n\nReproduced in %d scan rounds.", len(f.Rounds))
	}
	return b.String()
}

// sanitizeURIComponent makes a target description usable as a URI fragment.
func sanitizeURIComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '.', r == '_', r == '/':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// excerpt trims s to at most n runes, marking that it was cut.
func excerpt(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n[truncated]"
}
