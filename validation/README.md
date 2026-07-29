# Random-sample validation

Curated repos (see [../VALIDATION.md](../VALIDATION.md)) prove OrthoSec *can* find real
issues and stay false-positive-free on code we hand-picked. That's necessary but not
sufficient — the honest question a security leader asks is: **how does it behave on repos we
didn't choose?** This harness answers that reproducibly.

## What it does

`random_sample.py`:

1. Searches GitHub for public AI repos matching a query (default: repos using `openai`).
2. Takes a **seeded-random** sample of *N* — so the sample isn't cherry-picked, and the run
   is reproducible (same query + seed → same repos; the exact repo **and resolved commit**
   are recorded in the output for audit).
3. Shallow-clones and scans each with OrthoSec.
4. Reports **measured finding rates**: findings per KLOC, per detector, per severity, and the
   share of repos with a HIGH/CRITICAL finding — as Markdown + JSON.

## Run it

```bash
# a token lifts the search rate limit (unauthenticated works for small N)
export GITHUB_TOKEN=ghp_...
python validation/random_sample.py --n 30 --seed 0

# also dump a random set of findings for manual TP/FP labeling
python validation/random_sample.py --n 30 --seed 0 --triage-sample 40
```

Output lands in `validation/results/seed<seed>-n<N>.{json,md}` (+ `-triage.md`).

## Finding-rate is not precision — and we don't pretend otherwise

A finding count on unlabeled repos is a **rate**, not accuracy. Precision needs ground
truth. The honest path, built in:

1. `--triage-sample K` dumps *K* random findings (rule, `file:line`, evidence) to a triage
   file.
2. A human labels each `TP` or `FP`.
3. Precision on a **random** sample = `TP / (TP + FP)` — a defensible number, because the
   findings were sampled at random, not chosen to look good.

Recall on random repos is harder still (it needs known-vulnerable ground truth); the labeled
CVE/vuln-fixture corpora in [../benchmark](../benchmark) carry the recall claim.

## Honest limitations

- **Sample, not census.** Results describe the sampled repos at their recorded commits.
- **Search bias.** GitHub search ranks/filters; the query shapes the population. Vary
  `--query` and `--seed` and report several runs, not one.
- **Triage is judgment.** TP/FP on borderline findings is a call; label conservatively and
  keep the labeled file alongside the result for others to check.
- **Network + rate limits.** Unauthenticated search is 10 requests/min; use a token for
  larger samples.

The point isn't a single trophy number — it's a **reproducible, non-curated** measurement
anyone can re-run and audit.
