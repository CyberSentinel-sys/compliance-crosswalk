# compliance-crosswalk

Map the security controls an organization already has **in place** across
several public security and OT frameworks at once, and report — per framework —
how much of that framework's structure is covered and which requirements remain
as gaps.

The thesis this demonstrates: one assessment can answer to every framework a
critical-infrastructure operator is measured against — **IEC 62443-3-3**,
**NIST SP 800-82**, **NIST CSF 2.0**, and the **CISA Cross-Sector
Cybersecurity Performance Goals (CPGs)** — instead of re-doing the paperwork
once per standard.

Standard library only. Python 3.8+. No dependencies.

## The problem

Critical-infrastructure operators are rarely measured against a single
standard. A water utility or hospital may be held to IEC 62443 by an
integrator, to NIST 800-82 / CSF by an insurer or a US-facing partner, and to
the CISA CPGs by sector guidance — all describing overlapping controls in
different vocabularies.

Mapping the same set of findings to each framework by hand is slow, repetitive,
and error-prone. The same "we have network segmentation" fact has to be located
and re-justified under `SR 5.1`, `SC-7`, `PR.IR-01`, and `2.F` separately. A
small taxonomy problem becomes hours of spreadsheet work per assessment.

## How it works

1. You describe a **canonical control set** — vendor-neutral control names like
   `asset-inventory`, `network-segmentation`, `remote-access-mfa`,
   `backup-recovery`, `logging-monitoring`, `vuln-management`.
2. A **crosswalk** maps each canonical control to the relevant requirement IDs
   in each framework.
3. You feed in which of those controls are **in place**. The tool computes, per
   framework, `covered / total` (a percentage) and lists the unmet requirement
   IDs as **gaps**.

```
controls in place  ──►  crosswalk  ──►  per-framework coverage + gap list
```

> **The bundled data is an illustrative public-reference starter — bring your
> own.** The framework files (`data/frameworks/`) hold a representative public
> *subset* of each framework: requirement IDs plus short, generically-worded
> titles written for this project (not the copyrighted standard text). The
> crosswalk (`data/crosswalk.json`) is a hand-written demonstration mapping. It
> is **not authoritative** and **not** anyone's proprietary product mapping.
> Replace both with your own vetted data for real use.

## Usage

```
python crosswalk.py <controls.json> [--framework KEY|all] [--format text|markdown|json]
```

- `--framework` — one of `iec-62443`, `nist-800-82`, `nist-csf`, `cisa-cpg`, or
  `all` (default `all`).
- `--format` — `text` (default), `markdown`, or `json`.

The input file is either a JSON list of control ids, or an object with a
`controls_in_place` list. Unknown control ids are warned about and ignored, not
fatal. Exit code is `0` on success, `2` on an input error.

Run the included sample (a deliberately partial control set, so you see gaps):

```
python crosswalk.py examples/controls-sample.json --framework all
```

Output (abridged):

```
IEC 62443-3-3 [iec-62443]
  coverage: 13/21 (61.9%)
  gaps (8):
    - SR 1.7  Strength of password-based authentication
    - SR 2.1  Authorization enforcement
    ...

NIST CSF 2.0 [nist-csf]
  coverage: 9/19 (47.4%)
  gaps (10):
    - GV.RR-01  Cybersecurity roles & responsibilities established
    - ID.RA-01  Vulnerabilities identified & recorded
    ...
```

A single framework, as Markdown:

```
python crosswalk.py examples/controls-sample.json --framework nist-csf --format markdown
```

Machine-readable, for piping into other tooling:

```
python crosswalk.py examples/controls-sample.json --format json
```

## What it does — and does NOT do

**It does:** organize and visualize how a set of controls maps onto the
structure of several public frameworks, so you can see coverage and gaps across
all of them from one input.

**It does NOT:**

- issue a compliance **certification**, perform an **audit**, or give **legal
  advice** — it organizes coverage against a framework's structure, nothing
  more;
- ship an authoritative crosswalk — the bundled mapping is **illustrative**,
  not authoritative, and not a product mapping;
- reproduce standard text — framework files carry IDs and short paraphrased
  titles only, so you should consult the official publications for the
  normative requirements.

Treat its output as a starting map for a human assessor, not a verdict.

## Layout

```
crosswalk.py                     engine + CLI (stdlib only)
data/frameworks/*.json           illustrative public subset per framework
data/crosswalk.json              illustrative canonical-control -> requirement map
examples/controls-sample.json    sample "controls in place" input
tests/test_crosswalk.py          unittest suite (python -m unittest)
```

## Tests

```
python -m unittest discover -s tests
```

## About Wardhelm

Wardhelm builds operator-safe security tooling for critical-infrastructure
environments. This repository is an open, self-contained engineering showcase —
the crosswalk data is public-reference and illustrative, and contains no client
data or proprietary mapping. https://wardhelm.com

## License

MIT — see [LICENSE](LICENSE).
