# Machine-speed attackers: why this is urgent, and what afw does about it

## What changed (autumn 2026)

Autonomous attack tooling is no longer a forecast. Sources, read on 20 Nov 2026:

- **Microsoft, 21 Oct 2026**: a China state-aligned group it tracks as Storm-0940 used **ARTEX**, an open-source multi-agent AI penetration-testing framework, to automate attacks on hundreds of organisations. In several cases the time **from first targeting to privileged access was under 3 hours**. One password-spray run peaked at 2,900 failed sign-ins a minute. Microsoft's own words: the activity is noisy and does raise alerts, but "the speed of the activity allows very little time for Defenders to respond" ([Microsoft Security blog](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)).
- **FBI FLASH advisory, 13 Nov 2026**, as reported by BleepingComputer: several groups have used ARTEX since at least August 2026; it lets people "with minimal technical expertise" run multi-target operations at once; it is good at finding overlooked systems (partner portals, legacy services); and over 1,600 ARTEX consoles were found exposed on the internet ([BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-warns-artex-ai-hacking-tool-is-powering-global-cyberattacks/)). We have not read the FBI PDF itself.
- The same reporting describes agents "pursuing different attack paths when initial attempts failed".

Two honest limits on the headlines. Microsoft says **most of the targeting failed**. And the best-known breach was **abuse of a trusted cloud application's credentials** in Microsoft 365, which no network firewall can see.

## What that means for defence

| The attacker now... | So the defence must... | afw |
|---|---|---|
| Goes from first probe to control in under 3 hours, around the clock | Decide and act in seconds without waiting for a person, and be safe to leave alone | Built: kernel enforcement, fast tier, the rails in [self-harm.md](self-harm.md). A decoy touch is blocked in about 0.1 s in the kernel lab |
| Probes everything, including systems nobody remembers | Turn that breadth into a tripwire | Built: **decoy ports**. One completed connection is proven evidence |
| Chains stages automatically (scan, then guess passwords, then move on) | Link the stages into one story and treat the chain as worse than its parts | Built: **`chain.*` class**, longer block, critical escalation to a human |
| Tries another path when one is blocked | Block the source, not the path, and remember it | Built: verdicts act on the source for every port; repeat offences lengthen the block (10 m up to 24 h) |
| Runs many targets and paths at once from many addresses | Group by campaign, not by address, and survive volume | Built: range-level subjects, incidents, action budgets, break-glass |
| Is noisy but faster than any analyst | Not depend on anyone reading alerts in time | Built: the action comes first; the explanation and escalation follow |
| Costs the attacker almost nothing to run | Make each attempt cost time | Built: decoys hold the connection open (tarpit); throttles slow new connections |
| Is driven by a language model reading what it finds | Never let attacker-written text steer our own model | Rule in force for v0.3: traffic content is quoted data, never instructions; decoy captures are stored escaped |

## What afw does not cover

- **Cloud identity abuse** (stolen application credentials, consent grants, sign-ins to a SaaS tenant). That needs the cloud provider's own logs and controls.
- **Exploits inside a single allowed request**, and **data theft over an allowed connection**. afw sees the flow, not the content. These are the top roadmap items.
- **Password spraying against a cloud login page** you do not host.

## Roadmap, reordered by this threat

1. **Authentication log sensors** (sshd, reverse proxies, VPNs): failed-login evidence is far sharper than connection patterns, and password spraying is where these tools start.
2. **Linking incidents across devices**: "the address that got into the NAS" and "the NAS uploading 2 GB" as one story.
3. **Egress volume baselines** per device: the FBI advises watching for large transfers.
4. **Richer decoys** (believable service banners, decoy credentials) and **quarantine** of inside devices, with link-layer proof.
5. **Model analyst** (v0.3), rationed and fed from the evidence graph.

## Using decoys

List ports that nothing on the machine serves:

```yaml
canary:
  ports: [2323, 5900, 6379, 9200]
```

A port that is in use is skipped with a warning, never taken over. `afw status` shows which decoys are listening, how many touches they have seen and how many connections are being held.
