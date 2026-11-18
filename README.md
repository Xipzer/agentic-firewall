# agentic-firewall

**Bouncers for your network.** An always-on, AI-driven firewall that reasons about traffic the way a very fast security analyst would, 24/7.

Static rules are brittle: either you block everyone and whitelist (terrible UX), or you let things through and react after the fire starts. Agentic Firewall sits in between. It watches flows, lets good traffic through, and remediates the rest in real time, explaining every decision.

## The idea

Security is moving to a nightclub model. Every network gets a door staff of agents that:

- **Watch** traffic continuously and decide who gets in.
- **Remediate** instantly: drop, rate-limit, quarantine or reroute to decoys.
- **Reason** about why something was allowed or blocked, and learn from it.

There is no open protocol or framework for this yet. This repo aims to be it.

## Tiered agents

Speed and sophistication are staggered, because no single model is both instant and deep.

| Tier | Latency | Job |
| --- | --- | --- |
| **Fast** | microseconds to ms | Inline packet and flow scoring. Heuristics and small models. Allow, drop, throttle. |
| **Medium** | ms to seconds | Session and behaviour analysis. Adjusts rate limits, plugs holes, reroutes suspects to honeypots. |
| **Slow** | seconds to minutes | Full LLM reasoning over incidents. Writes new rules for the fast tier, explains decisions, acts as the 24/7 security director. |

Heuristics scale from simple (rate, reputation, geo) to non-trivial (behavioural fingerprints, multi-step attack chains). Slow-tier conclusions get compiled down into fast-tier rules, so the system gets cheaper and faster as it learns.

## Deployment targets

- **Home:** a Raspberry Pi or mini PC as the gateway, with full programmable control of your network.
- **Edge / cloud:** a sidecar or reverse proxy in front of web services and APIs.
- **Enterprise:** a policy and agent layer on top of existing firewalls, IDS and SIEM tooling.

## Status

**v0.1 works**: one Go binary for a Raspberry Pi, mini PC or server.

- **AFP v0.1**: JSON Schemas and examples in [spec/afp/0.1](spec/afp/0.1).
- **Fast tier**: scores sources for scans (fast, slow, distributed), handshake failures, brute force, connection floods and reputation, then allows, throttles or drops through nftables. Every action expires.
- **Host or gateway, or both**: the same engine runs in either place, and nodes share verdicts over signed **crosstalk** as advice, not commands.
- **Safety rails**: protected subjects (auto-detected), spoof-aware actions, action budgets, TTLs, shadow mode, probation and `afw panic`.
- **Cheap by design**: the kernel and heuristics handle floods with no model calls. Escalations fold into one incident per campaign, model attention is rationed, and it goes first to what a coverage ledger says is new.
- **Memory for agents**: an evidence graph rebuilt deterministically from the journal; `afw graph <ip> -pack` gives a bounded context pack (a 2 MB campaign packs into 4.5 KB).
- **Explainable**: every verdict is logged with a plain-English explanation and the observations behind it, and can be replayed offline.

```sh
go build -o afw ./cmd/afw          # GOOS=linux GOARCH=arm64 for a Pi
sudo ./afw run -c configs/afw.example.yaml
sudo ./afw status
```

Start with [docs/home-testing.md](docs/home-testing.md). The design is in [DESIGN.md](DESIGN.md), what it defends against (and its own failure modes) in [docs/threat-model.md](docs/threat-model.md), and why each threat feed was chosen in [docs/alpha-sources.md](docs/alpha-sources.md). Contributions, ideas and threat models welcome.

## License

[Apache-2.0](LICENSE)
