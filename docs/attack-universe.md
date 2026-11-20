# The attack universe and what afw covers

Two questions decide whether a defence is complete:

1. **The universe of attacks.** Is every kind of attack at least *named* when it happens, even if afw cannot stop it?
2. **The universe of one attack.** For a given incident, can afw see all of its stages (reconnaissance, access, foothold, movement, extraction, impact), not just the noisy one?

Coverage means three different things, and this table keeps them apart:

- **See**: the evidence reaches afw at all.
- **Name**: afw classifies it (the `class` field on verdicts and escalations, e.g. `recon.scan.vertical`).
- **Act**: afw can reduce the harm automatically.

Something can be seen and named without being stoppable here (a 10 Gbit/s flood saturates the uplink before any home box sees it). The rule is that **nothing should be invisible and unnamed**. Gaps are listed so they are closed on purpose, not discovered in an incident.

## Where an attack can be seen

| Layer | What it shows | Where afw gets it |
|---|---|---|
| L3/L4 flow | who talks to whom, ports, rates, handshake outcome, duration | v0.1: NFLOG sampling and conntrack |
| Kernel state | connection table fill, shed counters | v0.1: `/proc`, nft counters |
| Reputation | known-bad infrastructure | v0.1: feeds |
| Peers | what other nodes saw | v0.1: crosstalk |
| Payload headers | TLS ClientHello (SNI, JA4), DNS names, HTTP request lines | v0.2 |
| Host | which process opened a socket, file and login events | v0.2 host agent |
| Link | MAC, ARP, DHCP, switch port | v0.2 (needed before quarantine) |
| Volume | bytes per destination over time | v0.2 (needs conntrack accounting) |

## The taxonomy, with v0.1 coverage

Class names are dotted: the family first, then detail, then modifiers such as `.distributed`. An inside device doing any of these is reported as `lateral.*`, because on a home network that is a symptom of compromise.

| Family | Class | See | Name | Act (v0.1) |
|---|---|---|---|---|
| **Reconnaissance** | `recon.scan.vertical` (many ports, one host) | yes | yes | throttle; drop with proven evidence |
| | `recon.scan.horizontal` (one port, many hosts) | yes | yes | throttle |
| | `recon.scan.slow` (spread over minutes) | yes | yes | throttle |
| | `recon.scan.*.distributed` (many sources in one range) | yes | yes | throttle the range |
| | service and OS fingerprinting | partly (looks like a scan) | as scan | as scan |
| | `recon.decoy` (completed connection to a decoy port) | yes | yes | drop in about 0.1 s, on one touch; connection tarpitted |
| **Automated intrusion chain** | `chain.<stage>-<stage>` (e.g. `chain.recon-access-decoy`): one source moving through stages within 3 hours | yes | yes | drop when two stages are proven; longer block; escalated as high or critical |
| **Initial access** | `access.bruteforce` (password guessing, credential stuffing) | yes | yes | drop |
| | exploit of an exposed service (a single crafted request) | flow only | no | **gap**: needs payload or host view (v0.2/v0.3) |
| | phishing, malicious download | egress flow only | no | **gap** unless the destination is listed |
| **Denial of service** | `dos.syn-flood` (handshakes that never complete) | yes | yes | throttle; break-glass lane |
| | `dos.connection-flood` (completed connections at high rate) | yes | yes | drop sources; break-glass lane |
| | `dos.flood` (network-wide harm: posture) | yes | yes | break-glass: serve trusted first, cap newcomers, reclaim table slots |
| | connection-table exhaustion | yes (fill %) | yes (posture reason) | shed before conntrack; reclaim half-open slots |
| | UDP and amplification floods | counted | as flood | **upstream only**: spoofable and volumetric, a home box cannot absorb them |
| | slow application attacks (slowloris) | partly | no | **gap**: v0.2 session tier |
| **Command and control** | `infra.known-bad` (listed C2 or hijacked ranges) | yes | yes | drop, both directions |
| | beaconing to unlisted C2 | flow only | no | **gap**: v0.2 periodicity detection |
| | DNS tunnelling | no | no | **gap**: v0.2 DNS view |
| **Lateral movement** | `lateral.scan.*` (inside device scanning) | yes | yes | observe and escalate (quarantine needs link-layer proof, v0.2) |
| | `lateral.bruteforce` (inside device guessing passwords) | yes, on the targeted host | yes | observe and escalate |
| | ARP or DHCP spoofing | no | no | **gap**: link layer, v0.2 |
| **Exfiltration** | large or unusual uploads to a new destination | flow only | no | **gap**: v0.2 volume baselines per device and destination |
| | slow drip over an encrypted channel | no | no | **gap**: needs host view |
| **Impact** | ransomware spreading over SMB | as lateral scan | yes | observe and escalate |
| | crypto-mining (egress to pools) | if listed | if listed | drop if listed |
| **Attacks on the defence** | spoofing to frame others, budget exhaustion, sensor blinding, feed poisoning, peer compromise, slow baseline poisoning | yes | yes (escalations name the rail) | see [self-harm.md](self-harm.md) |
| **Reported by a peer** | `peer.reported` | yes | yes | weighted evidence |

## The universe of one attack

Real intrusions are chains: a scan finds a service, a brute force gets in, the foothold calls home, then moves sideways and takes data. A defence that only reacts to the loudest stage misses the rest.

v0.1 already links the stages that share a subject: every verdict carries `refs` to its observations, escalations reference their verdicts, and the same source moving from `recon.scan.vertical` to `access.bruteforce` raises its offence count and lengthens its block. Escalations of the same class are already folded into one **incident** per campaign (one brute-force campaign from a thousand addresses is one incident, not a thousand alerts), and `afw coverage` lists open incidents. What v0.1 cannot yet do is join stages across *different* subjects, for example "the address that brute-forced the NAS at 03:00" and "the NAS uploading 2 GB to a new destination at 03:05". That correlation is the medium tier's first job (v0.2): an **incident** object that groups verdicts by time, target and chain stage, so an escalation reads as one story with a beginning, not five unrelated alerts.

## Break-glass: staying up while under attack

Most defences fail in one of two ways under a real flood: they block too little and the service drowns, or they block too much and the defence finishes the attacker's job. Break-glass is designed around a different goal: **keep serving genuine users first.**

- **Trigger on harm, not on one signal.** Pressure far above the learned baseline *together with* failing handshakes, an exhausted action budget or a connection table over 70% full. Or the operator's `afw breakglass on`. A rush of genuine traffic only raises the posture to *elevated*.
- **Serve the known good first.** Protected hosts, LAN devices and sources with earned trust (real sessions on 2+ days) bypass the lane completely. Every other new connection is limited per source and shares one capped lane. This is checked before conntrack, so shed attempts never take a slot in the connection table.
- **Free the table.** If the table is still over 70% full, half-open and closing connections from untrusted sources are cleared, so new genuine connections fit. Established sessions are never cut.
- **Act harder, not wider.** Thresholds tighten and the action budget quadruples. Protected subjects, harm direction, TTLs and the spoofable/proven split do **not** change, so break-glass cannot be used to make afw harm us.
- **Hold, renew, step down.** It lasts at least 10 minutes, renews while the lane is still shedding, steps down through *elevated*, and escalates to a human at once with the reasons.
- **The baseline cannot be groomed.** It learns only in calm periods, slowly, and is capped below the absolute ceiling, so a slow ramp cannot teach afw that a flood is normal.

In the kernel lab, a flood of over 240,000 connection attempts from rotating sources (enough to fill a 262,144-slot connection table) was shed while a trusted user connected 10 times out of 10, a protected host connected, and our own outbound traffic was untouched.
