# Sixi Scanner

[![CI](https://github.com/rbrus/sixi-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/rbrus/sixi-scanner/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/rbrus/sixi-scanner)](https://github.com/rbrus/sixi-scanner/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/rbrus/sixi-scanner.svg)](https://pkg.go.dev/github.com/rbrus/sixi-scanner) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) [![Benchmark](https://img.shields.io/badge/benchmark-1st%20precision%20%26%20recall-orange)](https://github.com/rbrus/agent-redteam-benchmark)

A command-line red-team scanner for LLM agents. It sends probe prompts to an
endpoint you are authorised to test, judges the replies, and writes out the
evidence.

```console
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions
```

27 techniques · Go standard library only, zero dependencies · reports as JSON,
SARIF 2.1.0 or Markdown · Apache 2.0.

**Radoslaw Brus** · [github.com/rbrus/sixi-scanner](https://github.com/rbrus/sixi-scanner)

---

## What this tool is not

Read this before you use the output for anything.

**A clean result is not an assurance.** It means the 21 probes below did not
produce a finding against the endpoint you named. It says nothing about
techniques this tool does not implement, and nothing about attacks that need
judgement no substring match can make. The report says so at the bottom of
every Markdown run, because a reader forwarding the document should not have to
come back to the README to find out.

**It does not certify, attest or grade compliance.** No output of this tool says
the words *compliant*, *certified* or *guaranteed*, and a test enforces that.

**The technique set is a baseline.** Every probe here is publicly documented.
That is deliberate — a finding you can reproduce with `curl` is worth more than
one you cannot — but it means this is a floor, not a state of the art.

**It is not a scanner for your infrastructure.** It probes one agent endpoint
over HTTP. It does not read your cloud tenancy, map your agent fleet, or check
whether your prompt actually reached the model you think it did.

## What it does do

Five things, in order of how much they matter.

**It shows its evidence.** Every finding carries the exact prompt sent and the
exact reply received, plus the sentence explaining why that reply was judged a
break. A security claim you cannot check is a rumour.

**It finds the leak nobody asked for.** A marker list only recognises the leak
its own payload requested, and most real leaks are not the one you asked about.
An agent asked about package managers can answer with its refund cap, its
e-mail allow-list and the accounts it may not touch — handing over its
instruction set — while every technique reads that reply as a hold, because no
marker shares a substring with a paraphrase of a rule. A shared second marker
catches a reply that states three or more constraints on the agent itself,
whichever probe drew it. On 1,456 replies recorded from a real agent this took
payload recall from 0.444 to 0.889 at no cost in precision. See
[docs/recitation.md](docs/recitation.md), which also says plainly what this
cannot decide on its own.

**It does not cry wolf on refusals.** This is the hard part of the problem and
the part most tools get wrong. A target that answers *"I don't retain any
personal data"* has just used the word *retain* — and a naive scanner reports
that as a data leak. Every marker this tool matches is checked against the
sentence it appeared in, and a match inside a denial is discounted rather than
counted. See [docs/judge.md](docs/judge.md).

**It reports what it could not test.** A technique that got no answer is listed
as untested rather than counted as a pass. A scan interrupted partway says its
coverage is partial and exits 3.

**It can ask, if you have somewhere to ask.** A marker match is evidence, not a
verdict: *"I can't share API keys"* contains every credential marker's substring
and is not a leak. One optional flag points the scanner at an OpenAI-compatible
model and a context file describing the agent, and every candidate break is put
to it — severity and all, so a "violation, low" does not become a finding. It is
off by default, budgeted, and a run that ran out of budget says so. See
[docs/confirm.md](docs/confirm.md).

## How it measures up

Every release is re-run on a public benchmark: seven red-teaming tools against
one real Microsoft Foundry agent, scored from the wire by deterministic oracles
and a tool-blind judge rather than by any tool's own verdict. The benchmark is
maintained by this tool's author; the conflict of interest is stated there and
every raw finding is published.

| v0.6.0 on [agent-redteam-benchmark](https://github.com/rbrus/agent-redteam-benchmark) | measured | among seven tools |
|---|---|---|
| Precision: of what it reported, how much was real | 0.688 | 1st (next: 0.300) |
| Recall: of what it broke, how much it reported | 0.833 | 1st (next: 0.556) |
| Real leaks caught, on each reply's own evidence | 34 of 37 | |
| Cloud cost of the run | $0.57 | |

A follow-up audit found recall at its practical ceiling on that target: the 3
missed leaks are a disagreement between two judges about whether a capability
summary is a leak, not something a marker can fix. **Where it loses is
breadth:** 6 distinct violating attacks, against 67 for garak and 89 for
promptfoo. See the
[v0.6.0 write-up](https://github.com/rbrus/agent-redteam-benchmark/blob/main/results/2026-10-08-sixi-oss-v6/README.md).

## Install

```console
go install github.com/rbrus/sixi-scanner/cmd/sixi-scanner@latest
```

Or build from a checkout:

```console
git clone https://github.com/rbrus/sixi-scanner
cd sixi-scanner && make build && ./sixi-scanner
```

Go 1.24 or later. There is nothing to vendor and nothing to configure.

## Quick start

See the shape of a report without touching the network:

```console
$ sixi-scanner scan --target echo --format markdown
```

Scan an OpenAI-compatible chat endpoint:

```console
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions
```

Scan a bespoke internal agent that does not speak the OpenAI shape:

```console
$ sixi-scanner scan --target json --url https://internal.example/api/ask \
    --body '{"question":{{json}},"session":"s1"}' \
    --reply-path answer.text
```

Scan a website chatbot:

```console
$ sixi-scanner scan --target webform --url https://site.example/chat --field message
```

Re-run exactly one finding to check it still reproduces:

```console
$ sixi-scanner scan --url https://your-agent.example/v1/chat/completions \
    --only probe.llm02.system-prompt-leak
```

## Connectors

| `--target` | Talks to | Needs |
|---|---|---|
| `openai` | OpenAI-compatible `/chat/completions` | `--url`, optionally `--model` |
| `json` | Anything, with a described request and reply shape | `--url`, `--body`, `--reply-path` |
| `chat` | An endpoint that keeps a conversation, one probe per turn | `--url` |
| `webform` | An HTML form | `--url`, `--field` |
| `echo` | Nothing — an in-process target for demos and CI | nothing |

The `json` connector is the one that makes this usable against a system nobody
else has seen. `--body` takes a template with `{{prompt}}` (raw) or `{{json}}`
(JSON-escaped, which is what you want); `--reply-path` is a dotted path into the
response, with numeric segments for arrays:

```console
--body '{"q":{{json}}}' --reply-path data.0.answer.text
```

### Multi-turn probes

Some attacks only exist across a conversation: a limit expressed per request,
an instruction planted on one turn and acted on in the next, a payload that
asks to be relayed onward. Those are **sequences** -- ordered turns sent inside
one attempt -- and they need a target that can hold a conversation. Point
`--target chat` at an endpoint that takes `{"message", "session_id"}` and
answers `{"reply"}`, and they run:

```console
$ sixi-scanner scan --target chat --url https://agent.example/chat
```

Each attempt gets its own conversation, and the conversation id travels per
request rather than living on the connector, so techniques running at the same
time cannot end up inside each other's sessions.

Against a connector that cannot hold a conversation, these probes are **not
sent at all**. Sending them anyway would not weaken them, it would corrupt
them: the turns would go out as unrelated requests, and a probe that requires
every turn to break would then report two individually compliant replies as a
breach. They are listed under `unsupported` in the report, and a scan that
could run nothing exits 2 rather than passing.

## Output

| `--format` | For |
|---|---|
| `text` | Reading at a terminal. Findings go to stderr, the summary to stdout, so `> summary.txt` stays clean. |
| `json` | Machines. The full schema, including every finding's transcript. |
| `sarif` | Code scanning. SARIF 2.1.0; GitHub code scanning, `reviewdog` and friends consume it. |
| `markdown` | Sending to a person who has to decide whether to act. |

Write a report to a file with `--out`; the format is taken from the extension
unless `--format` says otherwise.

## In CI

On GitHub, the [`rbrus/scan-action`](https://github.com/rbrus/scan-action) Action does all of this in one step. Anywhere else:

```yaml
- name: Red-team the agent
  env:
    AGENT_URL: ${{ secrets.AGENT_URL }}
    AGENT_TOKEN: ${{ secrets.AGENT_TOKEN }}
  run: |
    sixi-scanner scan --url "$AGENT_URL" \
      --header "Authorization: Bearer $AGENT_TOKEN" \
      --format sarif --out sixi.sarif
```

Exit codes are the interface:

| Code | Meaning |
|---|---|
| `0` | Ran, found nothing |
| `1` | Ran, found something |
| `2` | Could not run — bad flags, unreachable target, bad output path |
| `3` | Interrupted before covering what it was asked to cover |

`3` is distinct from `0` on purpose: a cancelled scan must not read as a pass.

Upload with [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action)
or the SARIF uploader of your choice.

## What is covered, and what is not

`sixi-scanner list` prints the catalogue; `docs/techniques.md` explains the gaps.

Covered, as publicly documented baseline probes:

- **Prompt injection** — instruction override, forged conversation turns,
  authority and persona framing, encoded instructions, non-English instructions,
  indirect injection via quoted content
- **Sensitive disclosure** — system prompt leakage (direct and as a translation
  task), credential and configuration elicitation, conversation-context leakage,
  personal data elicitation, canary disclosure
- **Excessive agency** — tool enumeration, assent to irreversible actions,
  injected instructions inside tool arguments, scope expansion
- **Misinformation and availability** — unqualified compliance claims, unbounded
  output, verbatim memorisation probes
- **Output handling** — data exfiltration through rendered markup

Not covered, and worth being explicit about:

- Anything requiring a browser. The `webform` connector does not run
  JavaScript, so a chatbot that renders client-side comes back empty rather than
  clean.
- Anything requiring authentication flows, MFA, or multi-turn setup.
- Semantic or multi-step chains. Each technique is independent and probes in
  isolation; this tool does not build or follow attack chains across requests.
  The optional confirmation stage is a judge, not a second attacker — it cannot
  escalate.
- Agent-to-agent attacks, where the target is another agent rather than a user.
- Anything about your deployment. Whether the prompt reaches the model you
  think it does is out of scope for an HTTP scanner.

## Design notes worth knowing

**Every technique starts a fresh conversation.** A jailbreak that worked has
already changed the target's state — it agreed to something, adopted a persona,
dropped a guardrail. A later technique probing that state is measuring a
different agent than the one that answered the first probe.

**A refusal moves to the next variant, it does not repeat.** Repeating a refused
request is how a scan turns into a wall: slow, expensive, and it tells the
reader nothing the first refusal did not. Each variant is a different statement
of the same idea.

**A transport error is not an answer.** It is retried once, then that technique
is abandoned and the rest of the scan continues. It is never scored.

**The prompt is never judged.** Only the reply is. A marker that appears in your
own payload has matched nothing.

## Extending it

A technique is a struct. There is nothing to register by hand and nothing in the
engine to change:

```go
tech.Data{Def: tech.Definition{
    ID:          "probe.llm02.example-probe",
    Title:       "Example probe",
    Category:    "LLM02:2025 Sensitive Information Disclosure",
    Severity:    tech.SeverityHigh,
    Description: "What it probes for, and why it matters.",
    Remediation: "The concrete change that closes it.",
    Variants:    []string{"first payload", "different second payload"},
    Markers:     []string{"string that appears only on a real disclosure"},
    Negations:   []string{"cue that the marker was named, not disclosed"},
    MinMarkers:  1,
}}
```

`Markers` is the part that needs care. A marker that also appears in a refusal
produces a false positive; one that appears only in a perfect leak produces a
false negative. When a technique has an easy false-positive failure mode, raise
`MinMarkers` and populate `Negations`.

A transport is likewise just an interface — implement `Send` and `Describe`,
register it, and nothing else changes.

## Related

This is a complete tool for probing an endpoint you can reach, and it is
deliberately small enough to read in an afternoon. If you need more than this,
the honest answer is usually that you need a different tool rather than a bigger
one: a larger technique library bought on trust is worth less than the twenty-one
techniques here, each of which you can check.

## Security

Please read [SECURITY.md](SECURITY.md) before running this against anything. It
covers reporting a vulnerability and the acceptable-use boundary, which is
narrow: only scan endpoints you own or are authorised to test in writing.

## Author

Radoslaw Brus. Issues and pull requests welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).

This is a personal project. It is not affiliated with, endorsed by, or derived
from any company, and it has no commercial counterpart. Everything it does, it
does locally, with no account and no telemetry.

## Licence

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The licence covers the code and not the name. **Sixi Scanner** and
**sixi-scanner** are marks of the author, and Apache 2.0 grants no trademark
rights. In practice that means: use it commercially, fork it, change every line
of it — but do not ship a modified version as Sixi Scanner, or sell a product
under the name, without asking. Nominative use — saying what you use, linking
here, naming it in an assessment — needs no permission and never does.

[TRADEMARK.md](TRADEMARK.md) has the details, including what happens if someone
ignores it.
