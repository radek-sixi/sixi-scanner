package report

import "sort"

// stableSort is sort.SliceStable, named so report.go reads clearly and the
// choice is greppable.
func stableSort(s []Finding, less func(i, j int) bool) {
	sort.SliceStable(s, less)
}
