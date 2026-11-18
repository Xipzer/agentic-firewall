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

Early design. Read [DESIGN.md](DESIGN.md) for the architecture, the AFP protocol draft and the roadmap. Contributions, ideas and threat models welcome.

## License

[Apache-2.0](LICENSE)
