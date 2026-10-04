package target

import (
	"sort"
	"strings"
)

func sortStrings(s []string) { sort.Strings(s) }

// UnknownConnectorError means --target named a transport that is not compiled
// in. It lists the ones that are, which is the whole answer in most cases.
type UnknownConnectorError struct {
	Name  string
	Known []string
}

func (e *UnknownConnectorError) Error() string {
	return "unknown connector " + quote(e.Name) +
		"; available: " + strings.Join(e.Known, ", ")
}

func quote(s string) string { return "\"" + s + "\"" }
