# Architecture

Four packages, one interface between each, no framework, no dependencies. The
whole tool is about 3,800 lines of Go and can be read in an afternoon, which is
a deliberate design goal: a security tool nobody can audit is a security tool
nobody will act on.

```
cmd/sixi-scanner          flags, exit codes, report rendering
cmd/techdump              exports the technique set as data, and diffs it
   │
   ├── tech      a technique as data: Definition, Registry, Technique
   │     └── tech/baseline   the 21 shipped techniques
   │
   ├── target    where prompts go: Target, and four transports
   │
   ├── engine    the scan: walks techniques, sends payloads, collects breaks
   │
   ├── judge     a reply plus a technique becomes a verdict
   │
   └── report    the result, in JSON / SARIF 2.1.0 / Markdown
```

Dependencies run one way only. `engine` imports `judge`, `report`, `target` and
`tech`; nothing imports `engine`. `judge` imports only `tech`, and only for one
conversion function. That is what lets the judge be tested against
hand-written definitions with no engine in the picture.

## The seam that matters

```go
type Target interface {
    Send(ctx context.Context, prompt string) (Reply, error)
    Describe() string
}
```

The engine never learns which transport it has. Adding one means implementing
two methods and registering it; nothing above changes.

```go
type Technique interface {
    Meta() Definition
    Payload(attempt int, failed []string) string
}
```

A technique is data behind an interface. `tech.Data` adapts a `Definition` to
it, which is how all 21 shipped techniques work — but a technique that needs
request-dependent payloads can implement the interface directly and get the same
orchestration for free.

```go
func Disclosure(def Def, response string) Score
```

One function decides what is a finding. It is pure, it takes the reply and a
definition, and it returns a score carrying the evidence and a sentence of
reasoning. Being pure is what allows `docs/judge.md`'s test suite to exist.

## Why no framework

A dependency is a supply-chain liability in a security tool, and it is a
liability that a reader has to take on trust. The standard library covers
everything here: `net/http` for four transports, `encoding/json` for the report
shapes, `text/tabwriter` for the catalogue listing.

The cost is that some things are hand-rolled that a framework would give you —
notably the HTML text extraction in `internal/target/text.go`, which is a
deliberately crude tag stripper rather than a parser. That is the right trade
here: it is extracting text out of an untrusted reply for substring matching, and
a parser would be both a larger attack surface and unnecessary.

## Concurrency

The engine walks techniques in parallel, bounded by `--concurrency`. Findings
are appended under a mutex, and merges across rounds are done by **index** into
the findings slice rather than through a pointer held in a map — a map of
`*Finding` would point at a copy made before the append, so later rounds would
update the map and never the report. That bug existed and is now pinned by
`TestRoundsMergeIntoOneFinding`.

The default concurrency is 4, which is conservative on purpose. Some agents
share mutable state between sessions, and probing them concurrently measures
something other than what a single user would experience.

## Where a finding comes from

1. A technique's `Payload` produces a prompt. With a seed set, the seed is
   prepended — every conversation starts from the same state.
2. The transport sends it and returns the reply.
3. `judge.Disclosure` counts markers, discounts those inside a denial, and
   returns a score with a reason.
4. If it broke and cleared `--min-confidence`, the engine files a finding with
   the prompt, the reply, the markers and the reason.
5. A later round that reproduces the same technique appends to its `Rounds`
   rather than filing a duplicate.

## Adding things

**A technique** — a `Definition` in `internal/tech/baseline/`. The baseline tests
will check its description, its remediation, and that it does not fire on a
battery of refusals.

**A transport** — two methods and a `Register` call in `internal/target/`.

**A report format** — a `Write…(io.Writer, *Scan) error` function in
`internal/report/`, plus a case in the CLI's `--format` switch and the README
table.

**A technique** — either a new `Definition` in `internal/tech/baseline/`, or a
change to the export in `cmd/techdump` when the catalogue needs to be read by
something other than this binary.

**A judge rule** — the highest-leverage and highest-risk change. Read
`docs/judge.md` first and bring a reply shape that demonstrates the bug; every
existing test there was written that way.

## What is deliberately absent

No persistence. No database, no scan history, no resume. A scan is a run, and
its report is the record; anything that needs history should keep the JSON.

No service mode. There is no daemon and no port. If you want a CI gate, the
exit code is the interface.

No model calls. The judge is string matching. Adding a model to it would make
every finding cost money, be non-deterministic, and be impossible to re-derive
from the report — which would defeat the point of carrying the transcript.
