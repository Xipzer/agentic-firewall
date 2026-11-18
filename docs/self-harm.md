# Can the defence be turned against us?

An active defence is a machine that takes actions on input an attacker partly controls. If the attacker can steer those actions, the defence becomes their weapon: an autoimmune response. This document is the rule set that stops that, now and for every tier we add later.

The goal is a hard guarantee, not a best effort: **the worst an attacker can make afw do must cost us less than what afw stops.**

## The model

Every action has three parts an attacker might control:

1. **Evidence**: what we saw. Packets can carry forged source addresses; feeds can be wrong or poisoned; peers can be compromised; later, traffic content will reach an LLM.
2. **Subject**: who we act on. An attacker wants that to be something we need: our resolver, our bank, a CDN, our own phone, a LAN device.
3. **Effect**: what the action does. The damage depends on the blast radius (which traffic stops), duration and reversibility.

A rail must cap at least one of these so that, for every input an attacker can craft, the effect on us stays below the damage they intended. Ideally it caps all three.

## Ten rules

| # | Rule | What it stops | Status |
|---|---|---|---|
| 1 | **Harm direction.** A verdict built from what a subject *sent us* only limits what that subject can *start*. It never touches connections we start, or replies to them | Getting a shared address (CDN, cloud, CGNAT) blocked to cut us off from services we use | Built: verdict drops match `ct direction original` only. Lab-tested |
| 2 | **Proof proportional to force.** Evidence that can be forged (SYNs, UDP) can at most throttle new connections, never drop | Spoofing your DNS resolver's address to get it blocked | Built |
| 3 | **Earned trust.** A source with real sessions on 2+ days is judged on proven evidence only; spoofed packets in its name can at most get it watched | Framing your own phone or a regular client | Built (`Incumbent`), persisted across restarts |
| 4 | **Proven evidence only escalates punishment.** Repeat-offender TTL growth needs non-spoofable evidence | Ratcheting a spoofed victim's block up to 24 hours | Built |
| 5 | **Separate budgets.** Actions on forgeable evidence draw on half the budget and half the active slots; they cannot spend what proven attacks need | Flooding fake scanners to exhaust the budget before the real attack | Built |
| 6 | **No blind spots on demand.** Login and admin ports get their own sampling budget; conntrack backs up the sampler | Noise floods that blind the sensor during a brute force | Built |
| 7 | **Hard limits nobody can talk past.** Protected subjects, minimum prefix width, TTL caps, the internal-device cap and the global budget apply to every tier, peers and future LLMs included. The guard can only downgrade | Any single confused component taking the network down | Built |
| 8 | **Distrust inputs about inputs.** Feeds are sanitised, churn-limited and https-only; peers are signed, rate-limited, never relayed, and their spoofability travels with them | Poisoned feeds, compromised peers, loops | Built |
| 9 | **Never amplify.** The defence never sends traffic towards a subject (no resets, no ICMP, no abuse reports, no decoy replies) on forgeable evidence | Reflection: making us attack a third party | Holds today because afw only drops silently. Binding rule for v0.2 decoys and v0.3 reports |
| 10 | **Recoverable by construction.** Everything expires, restarts fail open, probation disarms, panic always works, and unblocks hold in grace | Any remaining mistake becoming permanent | Built |

## How rule 1 changes the maths

Before rule 1, dropping an address dropped *all* its packets, including replies to our own connections. An attacker renting a Cloudflare Workers or AWS Lambda address could brute-force us, get that shared address dropped, and cut us off from every site behind it. The attack's real yield was the outage, not the login.

Now the same drop only stops that address from opening connections to us. The attacker gets nothing they did not already lose. The only remaining collateral is other users of the same address who connect *to* us (for example a shared mobile carrier address and your home server). That is rule 3's job, and the verdict is escalated with a "may be a shared address" note.

## Attacks considered, and the answer to each

| Attack | Outcome now |
|---|---|
| Spoof SYN floods "from" 1.1.1.1 | 1.1.1.1 is auto-protected. Even if it were not, forged evidence can only throttle new inbound connections, and our DNS queries are outbound |
| Brute-force from a cloud or CDN egress address | Dropped for inbound only; our traffic to that provider is untouched |
| Spoof scans "from" your phone so your home server rejects it | Your phone has earned trust: observed only |
| Real abuse from an address shared with your phone (CGNAT) | Dropped for 10 minutes, escalated as a possible shared address; you can `afw unblock` |
| Exhaust the budget with spoofed sources, then attack | Spoofed actions use their own half; proven drops still have budget; exhaustion is a critical escalation |
| Repeatedly spoof a victim to get it blocked for a day | TTL never grows on forgeable evidence: 10 minutes, every time |
| Flood noise to hide a brute force from the sampler | Sensitive ports have their own sampling budget |
| Poison a feed with the LAN or a giant range | Stripped by the sanitiser; a sudden large change is refused |
| Compromise a peer | Its verdicts are weighted evidence, pass every local rail, last at most an hour and are never relayed |
| Groom trust, then attack | Trust takes sessions on two days and only protects against forged evidence; proven abuse still drops |
| Spoof a LAN device's address to get it "quarantined" | Internal devices are capped at observe in v0.1. Quarantine (v0.2) must require link-layer identity (MAC, switch port) and proven evidence, never IP alone |

## Break-glass is bounded too

Break-glass lets afw act harder in an emergency (see [attack-universe.md](attack-universe.md)). It is built so the emergency itself cannot be turned against us:

- It is triggered by **harm to the service**, which an attacker can only produce by actually attacking, never by a single signal that is cheap to fake.
- It **prioritises the known good** rather than blocking more of the unknown: trusted, protected and LAN sources are never limited.
- It raises *how hard* afw acts (thresholds, budget) but never *what it may act on*. Rules 1, 2, 3, 7 and 10 still hold.
- If an attacker holds break-glass on, the cost to us is that unknown newcomers share a capped lane, which is the right trade during a flood, and a human is told at once.

## Rules for the tiers still to come

These bind v0.2 and v0.3 before they are written:

- **The LLM never sees traffic as instructions.** SNI, hostnames, user agents and usernames are attacker-written text. They reach the model as quoted data, and the model's output is only ever a *proposal* that goes through the same guard.
- **Simulate before applying.** A proposed rule is replayed against the last days of journal first. If it would have blocked established, long-lived sessions (our real usage), it is rejected or sent to a human.
- **No rule wider than its evidence.** A compiled rule's match cannot be broader than the subjects in its provenance, without human approval.
- **The learning loop cannot be trained to allow.** Allow-listing and "benign" labels come only from humans and curated feeds, never from observed traffic. Otherwise an attacker could teach the system that their pattern is normal.
- **Quarantine and decoys need link-layer proof and rule 9.** Rerouting must never send traffic towards a forgeable source.
- **A self-harm breaker.** If our own outbound success rate or DNS health drops after new actions, the newest actions roll back first and the incident is escalated.
