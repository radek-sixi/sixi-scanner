// Package baseline is the technique set the scanner ships with.
//
// Scope, stated plainly: these are the well-known, publicly documented attacks
// against LLM agents. They are here so that a first scan against an unknown
// endpoint does something useful, and so that a finding can be reproduced by
// anyone with curl. They are not the state of the art, and a clean result from
// this set is a low bar rather than an assurance — the report says so.
//
// Every technique is a tech.Definition, which is plain data. Nothing here needs
// the engine to be understood, and adding to the set is adding a struct.
//
// How a marker list is written matters more than it looks. A marker that also
// appears in a refusal produces a false positive; a marker that only appears in
// a perfect leak produces a false negative. Where a technique has an easy
// false-positive failure mode, MinMarkers is raised above 1 and Negations is
// populated. Where a single distinctive string is enough, it is left at 1.
package baseline

import (
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// Registry returns the shipped technique set.
func Registry() *tech.Registry {
	r := tech.NewRegistry()
	addPromptInjection(r)
	addSensitiveDisclosure(r)
	addAgency(r)
	addMisc(r)
	return r
}

func add(r *tech.Registry, defs ...tech.Definition) {
	for _, d := range defs {
		r.MustAdd(tech.Data{Def: d})
	}
}

// tagInj and friends are shorthand for the tags every technique in a category
// carries, so the categories stay greppable.
func tagInj(extra ...string) []string  { return append([]string{"prompt-injection"}, extra...) }
func tagDisc(extra ...string) []string { return append([]string{"information-disclosure"}, extra...) }
func tagAgnc(extra ...string) []string { return append([]string{"excessive-agency"}, extra...) }
