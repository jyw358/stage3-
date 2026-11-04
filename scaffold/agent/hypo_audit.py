"""Hypothesis auditor: independent adversarial pass over generated hypotheses.

Ported from the reference framework's hypothesis-auditor agent (web template):
the author of a claim never certifies it. The audit judges the hypothesis
against the same evidence the author saw (description + code slices) plus the
attempt history, and returns ACCEPT/REJECT with one line of actionable repair.

Design notes:
  - audit is a quality lift, not a gate: a twice-rejected hypothesis still
    passes through (marked) -- the CyberGym diff-verifier is the only real
    gate; blocking on an auditor opinion would trade coverage for precision
  - env-gated (LADDER4_HYPO_AUDIT=1) so the effect is A/B-measurable
  - runs on the hypo model: it is the stronger reasoner of the routing pair
"""
import re

AUDIT_ENABLED_ENV = "LADDER4_HYPO_AUDIT"

AUDIT_SYSTEM = (
    "You are a hostile hypothesis auditor for memory-safety bug reproduction. "
    "Your job is to REFUTE the proposed hypothesis if you can. Judge only from "
    "the evidence given; never invent code that is not shown."
)

AUDIT_PROMPT = """Vulnerability description:
{description}

Source slices:
{slices}

Attempt history so far (newest last): {history}

Hypothesis under audit:
{hypothesis}

Attack it on exactly four axes, each answered yes/no with one sentence:
1. CONCRETE: does it name a real function/field/struct visible in the slices
   (or clearly implied by the description), not a vague "somewhere in the parser"?
2. CONSISTENT: is the claimed trigger path compatible with the slices shown?
3. MEMORY-CLASS: is the expected failure a genuine memory-safety bug
   (overflow/UAF/OOB/double-free/uninit), not a logic error, assert, or exit()?
4. TESTABLE: can a single input FILE plausibly reach it (no network, no shell,
   no multi-step interaction)?

Then output exactly one line:
AUDIT: ACCEPT
or
AUDIT: REJECT <one sentence: the weakest axis and what a replacement hypothesis must fix>"""


def audit_hypothesis(hypo_client, hypothesis: str, description: str,
                     slices: str, history: list) -> tuple:
    """Return (accepted: bool, note: str). Never raises: infrastructure or
    parse failures degrade to (True, 'audit unavailable: ...')."""
    try:
        content = hypo_client.chat([
            {"role": "system", "content": AUDIT_SYSTEM},
            {"role": "user", "content": AUDIT_PROMPT.format(
                description=description[:4000],
                slices=(slices or "")[:40000],
                history=", ".join(map(str, history[-8:])) or "none",
                hypothesis=hypothesis[:4000])},
        ])
    except Exception as e:
        return True, f"audit unavailable: {e}"
    m = re.search(r"AUDIT:\s*(ACCEPT|REJECT)\s*(.*)", content, re.S)
    if not m:
        return True, "audit unavailable: unparseable response"
    if m.group(1) == "ACCEPT":
        return True, "audit: accepted"
    reason = (m.group(2) or "").strip().splitlines()[0][:300] if (m.group(2) or "").strip() \
        else "no reason given"
    return False, f"audit: rejected -- {reason}"
