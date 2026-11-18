# Design

Status: draft v0.1. Everything here is open for discussion.

## Goals

1. Define an **open standard** for agentic network defence: how agents observe traffic, decide, act, escalate and explain.
2. Ship a **reference implementation** that runs on a single box (Raspberry Pi, mini PC, VM sidecar).
3. Keep every decision **explainable** and every action **reversible**.

Non-goals for the open core: fleet management, compliance reporting, hosted inference, shared threat intelligence. Those belong to the enterprise edition (see below).

## Architecture

```
          traffic
             │
   ┌─────────▼─────────┐   verdict (allow/drop/throttle/reroute)
   │  Data plane       │◄──────────────────────────────┐
   │  (enforcer)       │                               │
   └─────────┬─────────┘                               │
             │ observations                            │
   ┌─────────▼─────────┐  escalate  ┌──────────────┐  escalate  ┌──────────────┐
   │  Fast tier        ├───────────►│ Medium tier  ├───────────►│  Slow tier   │
   │  µs – ms          │            │ ms – s       │            │  s – min     │
   │  heuristics,      │            │ session &    │            │  LLM reasoning│
   │  small models     │            │ behaviour    │            │  & policy    │
   └─────────▲─────────┘            └──────┬───────┘            └──────┬───────┘
             │          compiled rules     │                           │
             └─────────────────────────────┴───────────────────────────┘
```

- **Data plane (enforcer).** Sits inline. Applies verdicts. Must never wait on a model. Reference backends: nftables, eBPF/XDP, reverse proxy (Envoy/Caddy plugin).
- **Fast tier.** Scores every flow inside the latency budget. Allow, drop or throttle. Anything uncertain is allowed or throttled per policy and escalated.
- **Medium tier.** Looks at sessions and behaviour over time. Adjusts rate limits, quarantines hosts, reroutes suspects to decoys.
- **Slow tier.** Full reasoning over incidents. Produces explanations, proposes policy changes and compiles conclusions into fast-tier rules.

### The learning loop

Slow-tier conclusions become **compiled rules** that the fast tier can apply in microseconds. Over time, more decisions are made cheaply at the edge and fewer need a model. Every compiled rule carries provenance (which incident, which reasoning) and a TTL.

### Host and gateway: one engine, two placements

Host mode and gateway mode are not competing products. They see different things:

- A **gateway** sees every device's internet traffic, including devices that can never run an agent (TVs, cameras, smart plugs). It cannot see traffic between two devices on the same switch, and it cannot tell which program made a connection.
- A **host** sees its own traffic in full, including attacks from inside the LAN, but nothing about its neighbours.

So v0.1 ships **one engine** with a `role` setting that only changes defaults (which addresses count as internal). The nftables ruleset hooks prerouting and output, which covers both placements. Run one, the other, or both.

When both run, they are **independent but linked** through **crosstalk**: each node publishes the verdicts it reached from its own evidence to its peers as signed AFP verdicts. A receiving node treats them as *evidence* weighted by trust, never as commands, and passes them through its own safety rails. A host that is brute-forced tells the gateway, which then protects every device; a gateway that sees a LAN device scanning tells the hosts. Loops are impossible by construction (`hops`: received verdicts are never relayed), spoofability travels with the evidence, and peer-derived actions are capped in strength and duration. If a peer dies, every node carries on alone. Details and edge cases: [docs/threat-model.md](docs/threat-model.md).

### Spoofable versus proven evidence

A SYN or a UDP packet can carry any source address. Evidence built only from them is marked `spoofable` and can at most **throttle new connections** from that source, never drop it, so an attacker cannot make the firewall cut you off from your DNS resolver by faking its address. Only evidence that needed a completed handshake (or a trusted peer's proven verdict) can drop.

## Protocol (AFP, Agentic Firewall Protocol)

Transport-agnostic messages, JSON for the reference implementation, protobuf later. Every message has `afp` (version), `id`, `ts` and `source` (tier + agent id, optional `node`).

The normative v0.1 definitions are the JSON Schemas in [spec/afp/0.1](spec/afp/0.1), with an example of each message. The Go types are tested against them so they cannot drift. Additions over the first draft: verdicts carry `signals` (each with `weight` and `spoofable`), `refs` to the observations behind them, `mode` (`enforce` or `shadow`) and `hops` (for crosstalk); escalations carry `refs`, `question`, `priority`, `deadline` and `target`; an `allow` verdict lifts earlier actions on its subject.

### Observation

What the enforcer or a tier saw.

```json
{
  "afp": "0.1", "type": "observation", "id": "obs_01", "ts": "2026-11-18T09:20:00Z",
  "source": { "tier": "dataplane", "agent": "gw-1" },
  "flow": { "src": "203.0.113.7:51544", "dst": "10.0.0.5:443", "proto": "tcp", "bytes": 4210, "packets": 12 },
  "context": { "sni": "api.example.com", "geo": "NL", "asn": 64500 }
}
```

### Verdict

A decision on a flow, host or session.

```json
{
  "afp": "0.1", "type": "verdict", "id": "ver_01", "ts": "2026-11-18T09:20:00Z",
  "source": { "tier": "fast", "agent": "heuristics-v1" },
  "subject": { "kind": "host", "value": "203.0.113.7" },
  "action": "throttle", "params": { "rate": "10/s" },
  "confidence": 0.62, "ttl": "10m",
  "reason": "burst of failed TLS handshakes",
  "escalate": true
}
```

Actions: `allow`, `drop`, `throttle`, `reroute` (to a decoy), `quarantine`, `observe`. Every action except `allow` must carry a `ttl`. Nothing is permanent without a policy decision.

### Escalation

A request for a higher tier to look. References the observations and verdicts that triggered it, plus the question being asked.

### Rule

A compiled, fast-tier-executable rule produced by a higher tier.

```json
{
  "afp": "0.1", "type": "rule", "id": "rule_01",
  "source": { "tier": "slow", "agent": "analyst" },
  "match": { "asn": 64500, "dst_port": 443, "handshake_fail_rate": { "gt": 0.5 } },
  "action": "drop", "ttl": "24h",
  "provenance": { "incident": "inc_07", "explanation": "exp_07" }
}
```

### Explanation

Human-readable reasoning attached to a verdict, rule or incident. This is the audit trail.

## Tier contract

Each tier must declare:

- **Latency budget** it guarantees (for example fast tier p99 < 1 ms).
- **Capabilities**, meaning which actions it may take. Policy can restrict this (for example only the slow tier may `quarantine`).
- **Failure mode** if it is overloaded or down: `fail-open` (allow and log) or `fail-closed` (drop). Defaults to fail-open for home use, configurable per subject.

Higher tiers can override lower-tier verdicts. Lower tiers never block on higher tiers.

## Safety rails

- All non-allow actions expire (TTL) unless confirmed by policy.
- Action budgets per tier: caps on how many hosts can be blocked per minute, so a confused model cannot take the network down.
- Protected subjects (gateway, DNS, admin hosts) can never be blocked by an agent.
- Optional human approval for high-impact actions.
- Full replay: observations and verdicts are logged so incidents can be replayed against new models and rules.

## Open core vs enterprise

| Area | Open (Apache-2.0) | Enterprise |
| --- | --- | --- |
| Protocol (AFP) and tier contract | ✓ | ✓ |
| Single-node gateway and enforcers | ✓ | ✓ |
| Reference fast-tier heuristics | ✓ | ✓ |
| Local-model slow tier | ✓ | ✓ |
| Rule compiler and replay | ✓ | ✓ |
| Fleet console, multi-site, SSO, RBAC | | ✓ |
| Audit, compliance and explainability reports | | ✓ |
| SIEM / SOAR integrations (Splunk, Sentinel, etc.) | | ✓ |
| Shared threat network (rules learned across customers) | | ✓ |
| Hosted slow-tier inference with SLAs | | ✓ |
| Managed decoys and honeypots | | ✓ |
| High-throughput inline path (XDP/DPDK, 10G+) | | ✓ |

## Roadmap

1. **v0.1** (built) AFP schemas, single-node host or gateway on nftables, fast-tier heuristics (rate, scans, handshake failures, short sessions, reputation), safety rails, crosstalk between nodes, JSON log, offline replay, kernel lab tests.
2. **v0.2** Medium tier with session tracking, throttling and decoy rerouting.
3. **v0.3** Slow tier with a local LLM, explanations and the rule compiler.
4. **v0.4** Replay harness and benchmark against public attack datasets (CIC-IDS, UNSW-NB15).
5. **v1.0** Stable AFP spec.
