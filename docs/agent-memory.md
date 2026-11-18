# Agent memory: the evidence graph (and what we took from Bevor)

## Why agents need it

Model agents forget: context gets compacted, sessions restart, models are swapped. An agent that forgets re-reads history (expensive), or worse, re-decides something already decided (inconsistent). The fix is a memory layer that is **deterministic, complete and cheap to query**, so the agent can always fall back on what is known and spend its budget on what is not.

## What we looked at

Bevor (bevor.io), a smart-contract audit platform, keeps a code graph per code version and a versioned ledger of findings. Its public SDK (`@bevorai/sdk` 0.2.1) exposes:

- **A content-addressed graph**: nodes with merkle hashes, typed edges (`calls`, `calls_external`, `reads`, `writes`, `inherits`...), call chains and cursors.
- **Versioned analyses**: lineage, fork, merge and head. Findings in unchanged code carry over to the next version, and **transitions** record each finding as `remediated` or `carried`.
- **Bounded slices**: nodes and call chains can be pulled individually instead of whole files.

It only graphs Solidity, Rust and Python, so it cannot index afw (Go) or network evidence, and network evidence should not leave the box anyway. On 18 Nov 2026 its docs site was serving an expired certificate.

## What earlier hands-on testing found

An earlier session ran Bevor on a real codebase (122 entrypoints) and measured its graph against the compiler's own output:

- Graph-built context packs made the verification step **about 30% cheaper, but not more accurate**.
- The graph caught every storage write and 95% of internal calls, but **only 74% of external calls**. Paths through them were truncated: one function really reached 133 functions; the graph showed 21.
- **Carry-forward was wrong where the graph had gaps**: after six functions changed, 10 affected entrypoints were marked unchanged.
- The plan's allowance (100 entrypoints) was **used up in one call with no warning**, so 11 were silently skipped.
- As a scanner it was weak: 28 of 47 findings were "admin can call the admin function", and severities were off.

**Lesson: the ledger and graph *idea* is excellent; inferring the graph is where it breaks.** A memory that is silently incomplete is worse than none, because the agent trusts it.

## What afw does with it

| Bevor idea | afw version | Fixes the measured weakness |
|---|---|---|
| Code graph | **Evidence graph** over every AFP message: subjects, assets, attack classes, incidents, verdicts, escalations, explanations, observations, rules | Every edge comes from an explicit AFP field (`subject`, `refs`, `about`, `incident`, `class`), never from parsing or inference, so it is **complete by construction** |
| Versioned ledger | The append-only **journal is the record of truth**; the graph is a pure function of it, rebuilt on start | Live graph and rebuilt graph are identical (tested), so memory can never drift from the record |
| Bounded slices | **Context packs**: `afw graph <ip|incident|class> -pack` gives tallies first, then a newest-first timeline trimmed to a line budget | Bounded and deterministic: a 2.1 MB campaign journal packs into 4.5 KB (about 470 times smaller), the same bytes every time |
| Coverage per node | **Saturation per asset** (`afw coverage`) | Attention goes to what is new, not to what is loud |
| Allowance | **Analyst rationing** per hour and day | Always reported (`over-budget`), never silently skipped |
| Carry-forward and transitions (v0.3) | When the rule set changes, replay the journal; incidents become `remediated` (new rules would have caught it) or `carried` | **Conservative by default**: anything the replay cannot prove unchanged is reopened. Rule sets get lineage like analyses (fork, head) and content hashes for exact change detection |

## How an analyst agent will use it (v0.3)

1. An incident is admitted by the rationing layer.
2. The agent gets the incident's **pack** plus the packs of its subjects and assets. That is a few KB, not the journal.
3. It asks follow-up questions by id (`afw graph ver_...`) instead of re-reading logs. After compaction it starts again from the packs, with nothing lost.
4. Its conclusions come back as AFP explanations and rules, which go into the journal and therefore into the graph. The next agent, or the same one after a restart, sees them.
