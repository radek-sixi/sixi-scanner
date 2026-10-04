# Support

Sixi Scanner is a personal project by Radoslaw Brus. It is free, complete and
Apache 2.0, and it does not need a support contract to work.

## If something is broken

Open an issue. Bugs with a reproduction get fixed; that is the whole arrangement.

Include the technique ID, the command you ran, and the output. If you found a
false positive, the reply that caused it is the most useful thing you can
attach.

## What is worth opening an issue for

**A false positive.** Include the technique ID and the reply. False positives
are the failure mode that matters most in this tool, and a concrete case turns
into a test that stops it recurring.

**A technique that should ship.** A probe whose markers do not collide with
refusals is genuinely useful. `docs/techniques.md` says how to write one, and
the baseline tests will check it.

**A connector you need.** Especially for a bespoke internal API shape — that is
what the `json` connector is for, and if it does not fit yours, it should.

Please do not open an issue asking how to detect your agent's specific
behaviour. If a break has no distinctive string, it does not belong in a marker
list, and `docs/judge.md` explains why. That is a design conversation and the
honest answer is usually a custom judge rather than another technique.

## Commercial use and the name

The code is Apache 2.0 and you may use it commercially, fork it, and change
every line of it.

The name is not. "Sixi Scanner" is a trademark of Radoslaw Brus and Apache 2.0
grants no rights to it. You do not need permission to use the tool, link to it,
name it in an assessment, or build your own version under your own name. You do
need permission to ship a modified version as Sixi Scanner or to put the name on
a commercial offer. See [TRADEMARK.md](TRADEMARK.md).

## What will not be answered

- "How do I make this pass?" — the techniques are the public baseline, and a
  clean report is the goal. If a probe trips on your agent, that is usually the
  agent.
- "Can you add feature X for my product?" — contributions are welcome in the
  shape `CONTRIBUTING.md` describes. Hosted or tailored work is not something
  this repository takes on.
- Anything about using this against a system you do not own. See the acceptable
  use section in [SECURITY.md](SECURITY.md); it is not a formality.

## Maintenance reality

One person maintains this, in their own time. That has consequences worth being
straight about:

- Issues are triaged, not serviced. Expect triage within a few weeks, not a
  response within days.
- There is no roadmap. If something is not fixed, it is usually because nobody
  needed it enough, not because it is planned.
- Nothing here depends on a company, a funding round, or a service staying
  online. The repository is the artefact.

If you depend on this in a pipeline, pin a version.
