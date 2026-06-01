# AgentGuard-CI

[![CI](https://github.com/zjnbwxq/agentguard-ci/actions/workflows/ci.yml/badge.svg)](https://github.com/zjnbwxq/agentguard-ci/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A proof-of-concept Consent-Integrity mediator for black-box LLM agents.

It renders the security-relevant approval from the *real* action observed at the
action boundary, never from the agent's self-reported narration; binds the
approval to the exact action (defeating post-approval swaps); and surfaces only
consequential actions to the human (risk-tiering). Actions it cannot decode are
flagged as uninspectable/high-risk rather than silently approved, so the target
is zero silent approval bypasses.

This is the artifact for the preprint *What You Approve Is What Executes:
Consent Integrity for Black-Box LLM Agents*.

## Files

- `ci.py` — de-obfuscating action analyzer that defaults to flagging anything it
  cannot positively clear as benign, recursive inspection of referenced local
  script bodies, a session analyzer for write-time content verdicts / locally
  built artifacts / real remote taint, and the bind-to-execution mediator.
- `corpus.py` — standard LITL items plus independently constructed cases that
  target the analyzer (interpreted-script payloads, capability-bearing scripts,
  opaque binaries, fetch-then-execute), benign inspectable workflows,
  faithful-prompt cases, and TOCTOU pairs.
- `evaluate.py` — runs all metrics against the corpus.
- `results.txt` — captured output of `python evaluate.py`.
- `tests/` — pytest suite.

## Run

```
python evaluate.py        # reproduce the evaluation numbers
pip install pytest
pytest -q                 # run the test suite
```

The core (`ci.py`, `corpus.py`, `evaluate.py`) has no dependencies beyond the
Python 3 standard library. `pytest` is only needed to run the tests.

## Results

Headline is the **independent** benchmark, GTFOBins, a third-party catalogue of
trusted-tool abuses not authored for this project (`python benchmarks/gtfobins_eval.py`):

- 1330 abuse commands across 478 binaries: **90.0% flagged** (405 by a danger fact,
  792 as uninspectable), **10.0% silent pass** — not zero, and every silent pass is
  through a binary the trust list treats as safe.
- Residual silent passes: 85 writes under `/tmp` (a deliberate scratch threshold),
  19 in-tree relative writes (risk caught later by provenance, not at the write),
  8 benign primitives (`mkdir`/`touch`), 21 genuine long-tail (pager/editor escapes).
- Implementing the missing `writes_outside_ws` boundary fact moved this from 15.0%
  to 10.0%. The number is a **position against the current corpus at a version**, not
  a solved property; security is a treadmill and this reports its rung honestly.

Fatigue axis, second **independent** corpus, tldr-pages normal idiomatic usage
(`python benchmarks/tldr_eval.py`):

- 28,798 example commands from 6,503 tools: **95.9% prompted, 87.0% uninspectable**
  (83.4% purely because the tool is not on the trust list); only **4.1% pass without a prompt**.
- The clean fatigue proxy is the uninspectable rate (some prompted commands are genuinely
  consequential). The same trust list that holds silent passes to 10% on GTFOBins forces 87%
  uninspectable on normal usage: shrink it and you get fatigue, grow it and you get silent
  passes. That trade-off, not a solved defense, is the finding.

Controlled co-designed set (`python evaluate.py`): 22 malicious 0 silent / 10 benign
0 false positives / TOCTOU 3/3 / ~0.05 ms. These are clean *because* the corpus is
co-designed with the analyzer; trust the GTFOBins figure, not this zero. See the
paper's Threats to Validity.

## Scope

This is a proof-of-concept of the mechanism, evaluated against a controlled
adversarial stand-in implementing the LITL threat model. Enforcing total
mediation via OS sandboxes, cross-platform, and evaluating against live
commercial agents are out of scope for this artifact.

## License

Apache-2.0.
