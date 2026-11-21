# Tests that cannot be cheated

A security product is only as good as the tests that say it works. These rules keep those tests honest, whether the thing being tested is afw's code, a model advising it, or a coding agent changing it.

Several come from mistakes made and caught in an earlier project on this machine (benchmarking local language models). Those lessons are marked **[learned]**.

## The rules

1. **The foundation works with no internet, and is tested that way.** `lab/rails.sh` runs every test inside a throwaway namespace with no network at all, and refuses to start if it finds a route out. A test cannot pass by fetching something, and nothing in the core can quietly depend on a remote service. Built.

2. **The answer must be out of reach.** **[learned]** A model once scored 23 out of 24 in 38 minutes because the folder it could read contained the finished solution; another test's injected bug was simply the last entry in the history. For afw this means:
   - The public attack datasets planned for v0.4 are known to every model. Before any model or tuning agent sees them, addresses are remapped and times shifted, so remembered labels are useless.
   - Known-answer checks for the adviser are **generated fresh on the machine, never stored in this public repository**, and look exactly like real briefings.
   - The adviser has no tools, so it cannot look anything up; its briefing is all it gets.

3. **The grader is out of reach of what it grades.** The adviser cannot read the expected answers (separate process, one narrow socket). Labels never sit in a folder the tested thing can read.

4. **A test that did not run has failed.** A skipped, renamed or deleted safety test turns the suite green while proving nothing. `rails.txt` lists the safety tests; `railscheck` fails the build unless every one ran and passed and nothing at all was skipped. Built. Before this, the kernel tests would have skipped silently on a machine without nftables and still shown green.

5. **A suite must be able to fail.** **[learned]** A benchmark where the untuned model already passed 66 of 67 could only ever show regressions. For v0.4: a firewall that blocks nothing and one that blocks everything must both score badly, or the benchmark measures nothing.

6. **Know the noise before trusting a difference.** **[learned]** Two runs of an equally good model differed by chance, enough to fail one. afw's replays are exactly deterministic (tested), so a changed result is a real change. Anything involving a model is repeated, and the same setup is compared with itself first.

7. **Related cases stay on the same side of a split.** **[learned]** Flows from one attack scenario or one day go entirely into tuning or entirely into the final check. The final check is used once, for finalists.

8. **Record what was consulted and who answered.** **[learned]** One run silently fell back to a weaker model, and its work had to be redone. Every adviser answer records which model and version produced it and which briefings it was given; a change of model raises an alert.

9. **Internet research is a bonus, never the base, and never part of a benchmark.** The whole internet is an attack surface: any page can be wrong, planted or written to steer whoever reads it. So:
   - Benchmarks and replays run with no feeds and no network. They measure the foundation alone.
   - In live use, anything fetched from the internet is treated like the adviser's advice: unproven. It can raise attention or slow an already-flagged source. It cannot block, cannot unblock, and is never read as instructions.
   - The reputation feeds already follow this: optional, sanitised, cached, and afw runs without them.

10. **Watch the momentum, not a seal.** The tests change with every version, so there is no fixed "correct" state to seal. What stays true is the direction: safety tests are added and grow, they do not shrink or vanish. `momentum` recomputes, from git history alone, how every safety test moved in each version: new, grew, reworded, **shrank** or **removed**, with the number of checks before and after. Nothing is stored, so there is no record to overwrite. A supervisor, human or agent, reads one table and one chart and looks only at the lines that went the wrong way. Built; CI posts it on every push and warns when a safety test shrank or vanished.

## What this does not solve

Momentum shows **that** a safety test lost checks, and a reworded test is listed too, but it cannot judge whether a reworded check is weaker. That judgement belongs to the supervisor. It only works if the supervisor is not the same agent that made the change: an independent reviewer, human or machine, with its own access.

## Running the gate

```sh
lab/rails.sh        # offline tests + real-kernel tests + manifest check, no sudo
go run ./internal/tools/momentum   # how the safety tests moved, version by version
```
