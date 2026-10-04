# Contributing

Patches are welcome, including from people who disagree with the design.

## Before you start

Open an issue for anything larger than a bug fix. The three decisions below are
load-bearing, and changing one of them silently will get a patch rejected.

**Techniques are data, not code.** A technique is a `tech.Definition` struct.
If yours needs a new package, that is a signal worth discussing first — it
usually means the marker approach was wrong.

**The judge is intentionally simple.** It matches strings and discounts markers
appearing inside a denial. Making it smarter is the single most likely way to
make it worse, because the failure mode is a refusal reported as a leak. Read
[docs/judge.md](docs/judge.md) first. A change that improves recall and loses
precision is a regression, and the tests will usually say so.

**A clean report must stay clearly a clean report.** If you add anything to the
output, it may not imply coverage, assurance, or certification beyond what was
actually tested. There is a test for this and it is not negotiable.

## Adding a technique

1. Add it to the relevant file in `internal/tech/baseline/`.
2. Fill in every field, including `Remediation`. A finding whose remediation is a
   platitude is noise, and the baseline tests reject an empty one.
3. Choose `Markers` carefully. Ask whether your marker also appears in a good
   refusal. If it does, raise `MinMarkers` or add to `Negations`.
4. Run `go test ./internal/tech/baseline/`. Two of those tests run every
   technique against a battery of refusals in three languages. If yours trips
   one of them, that is a real finding about your technique, not a test to relax.

## Inspecting the catalogue as data

```console
go run ./cmd/techdump                      # JSON, sorted by ID, deterministic
go run ./cmd/techdump --format go          # Go literals, ready to read or paste
go run ./cmd/techdump --only llm02.system-prompt-leak
go run ./cmd/techdump --tag credentials
go run ./cmd/techdump --compare before.json
```

`--compare` is the one to use when reviewing a set of technique changes. It
reports what was added, removed and behaviourally changed, and it treats a
removed technique as a regression worth investigating rather than a diff line to
accept. Rewording a description is not a behavioural change and is not reported,
so the output stays worth reading.

The export is sorted by ID on purpose. Registry order is insertion order, which
changes whenever anyone adds a technique anywhere, so an unsorted dump would show
a whole-file diff for a one-technique change.

## Adding a connector

Implement `Send` and `Describe` in `internal/target/`, register it in `init`,
and add it to the table in the README. Nothing else changes — the engine does not
know which transport it has.

If it needs a dependency, do not add one without discussing it first. The
standard-library-only property is what makes the supply-chain story a one-liner,
and it is worth more than most features.

## Running the checks

```console
make check     # fmt, vet, tests, and the build
make race      # tests under -race
make lint      # gofmt -l over the tree, non-empty is a failure
```

CI runs the same set on Go 1.24 and the current release.

Please include a test that fails before your change and passes after it. For a
judge change, that means a reply shape that demonstrates the bug — the existing
tests were all written that way.

## Commit messages

Plain sentences. Say what changed and why; a reviewer needs to know which
failure you saw.
