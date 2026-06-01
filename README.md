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

On the bundled corpus (`python evaluate.py`):

- 22 malicious cases: 17 fully explained, 5 safely flagged, **0 silent approval bypasses**.
- 10 benign inspectable workflows: **0 false positives**.
- 4 faithful-prompt cases (remote push, dependency build, configure, privileged install) prompt by design; these carry a real security-relevant fact and are not false positives.
- TOCTOU post-approval swaps refused: 3/3. Mean overhead ~0.056 ms/action.

The guarantee is analyzer-relative: referenced-content inspection clears a script
only when its body stays within bounded operations and otherwise flags it, and
build provenance is trusted at the granularity of the build tool, not its full
dependency closure. See the paper's Threats to Validity.

## Scope

This is a proof-of-concept of the mechanism, evaluated against a controlled
adversarial stand-in implementing the LITL threat model. Enforcing total
mediation via OS sandboxes, cross-platform, and evaluating against live
commercial agents are out of scope for this artifact.

## License

Apache-2.0.
