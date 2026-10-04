package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rbrus/sixi-scanner/internal/tech"
)

// sarifVersion is the only version this writer emits.
const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifToolURI = "https://github.com/rbrus/sixi-scanner"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
	// Invocations carries the exit code so a SARIF consumer can tell a clean
	// run from a run that produced findings, which SARIF has no other way to
	// express.
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
		results = append(results, sarifResult{
			RuleID:  f.TechniqueID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifText{Text: f.Evidence.Reason},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: uri},
					Region:           &sarifRegion{StartLine: 1, Snippet: snippet},
				},
			}},
			Fingerprints: map[string]string{"sixiScan/v1": f.Fingerprint},
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
				ExecutionSuccessful: len(s.Findings) == 0,
				ExitCode:            s.ExitCode(),
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
