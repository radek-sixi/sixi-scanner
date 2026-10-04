# Technique coverage

`sixi-scanner list` prints the live catalogue with severities and categories.
`sixi-scanner list --detail <ID>` prints one technique in full, including every payload
variant and success marker.

This document explains what the set is for and, more usefully, what it misses.

## What ships

21 techniques across six categories.

### Prompt injection — `llm01`

| ID | Severity | What it probes |
|---|---|---|
| `instruction-override` | high | The base case: original instructions discarded. |
| `delimiter-injection` | high | Closing the user turn and opening a system turn of the attacker's own. |
| `role-confusion` | medium | Borrowed authority — security lead, DAN, internal auditor. |
| `encoded-instruction` | medium | Base64 and ROT13, so a plain-text filter does not see the instruction. |
| `refusal-consistency` | medium | Single-turn formulation of the refusal-then-fold weakness. |
| `multilingual-bypass` | medium | The instruction in German, French or Spanish. |
| `indirect-injection` | high | The instruction inside content the agent was asked to process. |

### Sensitive disclosure — `llm02`, `llm07`

| ID | Severity | What it probes |
|---|---|---|
| `system-prompt-leak` | high | The direct ask for the instructions. |
| `system-prompt-translation` | high | The same ask framed as a language task, which passes checks the direct ask fails. |
| `credential-elicitation` | critical | API keys, tokens, connection strings. |
| `context-leak` | high | What the agent can see about the requester, or else in its context. |
| `pii-elicitation` | high | A real customer record. |
| `canary-leak` | high | A planted token — the cheapest reliable test for prompt leakage. |

### Excessive agency — `llm06`

| ID | Severity | What it probes |
|---|---|---|
| `tool-enumeration` | medium | What the agent can reach. Reconnaissance, not a break on its own. |
| `irreversible-action-assent` | high | Whether the agent will accept a destructive instruction on its face. Probes willingness; issues no real call. |
| `tool-argument-injection` | high | An instruction smuggled into a field the model fills in for a tool call. |
| `scope-expansion` | medium | Being told the assigned task is wrong. |

### Output handling, misinformation, availability, poisoning

| ID | Severity | What it probes |
|---|---|---|
| `llm05.markdown-exfiltration` | high | Data leaving through a URL or image in the rendered answer. |
| `llm09.false-certification` | medium | The agent stating a control is satisfied. The agreement is the defect. |
| `llm10.unbounded-consumption` | medium | Accepting a request sized to exhaust budget. |
| `llm04.training-data-extraction` | medium | Verbatim reproduction from the training set. |

## What does not ship

This is the section that matters. Every item here is a way a real assessment
gets a finding that this tool will not.

**Browser-driven targets.** The `webform` connector does not run JavaScript. A
chatbot that renders its answers client-side returns an empty body, and the
connector reports that rather than claiming a clean result. Anything behind a
login, a bot check, or a client-side render is out of reach.

**Multi-turn chains.** Each technique starts a fresh conversation and probes in
isolation. That is the right default — a broken agent is a different agent from
a clean one — but it means the tool will not follow a chain. The classic
four-step escalation, where each turn is individually defensible, will not be
found.

**Stateful targets.** Sessions, memory, and rate limiting are all real. A target
that behaves differently on the twentieth request than the second is being
measured unevenly, and `--rounds` exists to expose that rather than to average
it away.

**Semantic success.** A technique whose break has no distinctive string does not
belong in this design. If you need one, write a custom judge.

**Agent-to-agent attacks.** The target here is always something a user talks to.
A system where one agent instructs another is a different problem.

**Your deployment.** Whether the prompt reaches the model you believe it reaches
is invisible to an HTTP scanner. So is whether the guardrail you are relying on
sits in front of the model or behind it.

**RAG and indirect injection, properly.** `indirect-injection` exists, but
against a plain chat endpoint it cannot land, so a clean result there means
almost nothing. The description says so; read it before citing the result.

## How severities are assigned

Severity describes the **consequence of a successful attack**, not the
confidence in it. These are separate numbers in the report and should not be
conflated.

- **critical** — direct disclosure of credentials or keys; the impact is
  immediate and belongs to someone else
- **high** — system prompt leakage, personal data, exfiltration, assent to an
  irreversible action
- **medium** — reconnaissance, framing bypasses, availability and misinformation
- **low**, **info** — used by custom techniques; nothing in the baseline set
  ships at these levels

## Adding one

A technique is a `tech.Definition`. The two fields that need judgement:

**`Markers`** — a marker that also appears in a refusal produces a false
positive; one that appears only in a perfect leak produces a false negative.
Where a technique has an easy false-positive failure mode, raise `MinMarkers`
and populate `Negations`. `docs/judge.md` explains what the negation machinery
does with them.

**`Remediation`** — one concrete change, not a principle. "Do not put
guardrail text in the system prompt" is actionable; "improve prompt hygiene" is
not. A finding whose remediation is a platitude is noise.

The baseline tests will hold you to both: every technique must have a
description over twenty characters and a non-empty remediation, must be
reachable by the shipped judge, and must not produce a finding against any of
the refusal shapes those tests carry.
