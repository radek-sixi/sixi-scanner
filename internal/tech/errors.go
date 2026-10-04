package tech

import (
	"fmt"
	"strings"
)

// ValidationError means a Definition cannot be used as written.
type ValidationError struct {
	Technique string
	Reason    string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("technique %s: %s", e.Technique, e.Reason)
}

// UnknownTechniqueError means an identifier passed to --only or --exclude is
// not registered. It lists the known identifiers, because the overwhelmingly
// likely cause is a typo and the fix is visible in the list.
type UnknownTechniqueError struct {
	ID    string
	Known []string
}

func (e *UnknownTechniqueError) Error() string {
	if len(e.Known) == 0 {
		return fmt.Sprintf("unknown technique %q", e.ID)
	}
	return fmt.Sprintf("unknown technique %q; registered techniques are: %s",
		e.ID, strings.Join(e.Known, ", "))
}
