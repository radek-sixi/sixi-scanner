# Security

## Supported versions

The latest released tag. This project is young; there is no long-term support
branch.

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on
<https://github.com/rbrus/sixi-scanner/security/advisories/new>.

Please include the technique ID or code path, what an attacker gains, and a
reproduction if you have one.

Do not open a public issue for a vulnerability that has not been fixed.

You should get an acknowledgement within three working days. There is no bounty
programme and no contractual SLA, and it would be dishonest to imply otherwise.

## Acceptable use

**Only scan endpoints you own or have explicit written authorisation to test.**

This tool sends adversarial prompts to a URL. That is its entire purpose, and
the same property makes it dangerous to point at something you do not control.

Out of scope without exception:

- Any endpoint you do not own or have written authorisation to test
- Third-party APIs, hosted models, or SaaS products, including free tiers
- Rate limits, load tests, or availability testing — this is not a DoS tool and
  `llm10.unbounded-consumption` probes willingness, not endurance
- Anything that would access data belonging to a person who has not consented
- Circumventing an access control on a system you are permitted to use but not
  permitted to break

If you are unsure whether you have authorisation, you do not.

If you are assessing your own systems, the useful and unambiguous answers are
that the endpoint is yours, or that the scope is written down and the owner
agrees.

## Handling of scan output

A report contains whatever the target chose to disclose, which may include
secrets and personal data. It is evidence.

- Reports are not written anywhere by this tool. They go to stdout or to the
  path you gave with `--out`. There is no telemetry, no analytics, and no
  network call to anywhere other than the target URL.
- Credentials in a target URL are stripped before the URL reaches a report
  header or a log line. Credentials in a *reply* are findings, and are written
  out as such — which is the point, and also the reason to store reports as
  carefully as the secrets they contain.
- Treat a report as sensitive. If you upload SARIF to a code-scanning service,
  your evidence is going to that service.

## This tool's own trust properties

- No dependencies outside the Go standard library, and no `go.sum`. The supply
  chain is `git clone` plus the Go toolchain.
- No network calls other than to the target URL and its redirects.
- No telemetry, no analytics, no crash reporting, no update check.
- The binary makes no attempt to verify its own integrity, and does not phone
  home. There is nothing to disable, because there is nothing there.
- Reproducible: the same binary and the same technique set produce the same
  verdict from the same reply.

## What the judge can and cannot be relied on for

Stated once here because it is the property most likely to be assumed wrongly.

A finding means: a technique's markers appeared in a reply in a form the judge
did not recognise as a denial. It is a reproducible observation, not a proof of
compromise, and the report carries the transcript so a reader can judge it.

The absence of findings means: these 21 probes did not produce a finding. Not
more than that. See [docs/techniques.md](docs/techniques.md) for what is not
covered and [docs/judge.md](docs/judge.md) for the judge's known limitations.
