# Threat model and edge cases (v0.1)

This lists what v0.1 defends against, how the defender itself can be attacked or can fail, and what each case does in the code. "Tested" names the test that proves it. Known gaps are at the end.

The guiding rule: **a firewall that can be tricked into blocking the wrong thing is itself an attack surface.** Every rail below exists because the obvious design has a second-order failure.

## 1. First order: attacks on the network

| Attack | Signal | Response | Tested |
|---|---|---|---|
| Fast port scan | `port_fanout`, `conn_rate`, `handshake_fail` (all spoofable) | Throttle new connections, escalate | `TestSYNPortScanIsThrottledNotDropped`, lab `TestLabEndToEnd` |
| Slow scan (1 port every few seconds) | `slow_scan` over a 10 minute window | Throttle | `TestSlowScanCaughtOverLongWindow` |
| Distributed scan from one range | Same signals on the /24 (IPv4) or /48 (IPv6) aggregate, only when 3+ members are active | Throttle the prefix, escalate (could be CGNAT or cloud) | `TestDistributedScanCaughtAtAggregate` |
| IPv6 scanner rotating addresses | Subjects are keyed by /64, not /128 | Same as a single host | `TestIPv6RotationWithinSlash64` |
| Login brute force (SSH, RDP, SMB...) | `short_sessions` (completed handshakes, so not spoofable); sensitive ports count double | Drop | `TestSSHBruteForceIsDropped`, lab |
| Known-bad infrastructure | Reputation feeds in the kernel | Drop or throttle per feed | `TestManager*`, lab `TestLabLargeReputationLoad` |
| Compromised IoT device beaconing to C2 | Egress match on drop feeds (`repout`) | Drop outbound | ruleset test |
| Compromised LAN device scanning | Internal subject: fan-out with 8x thresholds, handshake failures | Observe and escalate as "possible compromise" (quarantine is a higher-tier call) | guard `internal host` case |
| Persistent attacker | Offence count per subject | TTL 10m, 40m, 2h40m, 10h40m, capped at 24h | `TestRepeatOffenderTTLGrowsAndCaps` |

## 2. Second order: turning the firewall against its owner

| Attack | Why it works on a naive design | v0.1 defence | Tested |
|---|---|---|---|
| **Spoofed SYN flood "from" your DNS resolver or a CDN** | SYNs need no handshake, so any source can be faked. A naive blocker cuts you off from 1.1.1.1 | (a) SYN-only and UDP evidence is marked spoofable and can only **throttle**, never drop. (b) Throttle applies to `ct state new` only, so replies to your own connections are never slowed. (c) Resolvers, gateways and self are auto-protected | `TestSYNPortScan...`, guard `spoofable only`, lab |
| Blocking a protected host through a wider prefix | A /16 verdict that contains the router | Guard checks prefix *overlap*, not just equality | guard `prefix covering protected` |
| IPv4-mapped IPv6 (`::ffff:1.1.1.1`) to dodge the protected list | String comparison misses it | Every address is unmapped before any check | guard `mapped v4 protected` |
| Operator locked out of a remote Pi | A bad heuristic blocks the admin's own address | The SSH client that started afw is auto-protected; enforce mode starts on **probation** and disarms itself unless `afw confirm` | lab `TestLabProbationDisarms` |
| Exhausting the action budget so the real attack gets through | Thousands of decoy sources | Budget refusal is itself a **critical escalation**; aggregates catch ranges; blocks already in place stay | `TestBudget` |
| Burning the budget with renewals | Re-issuing the same block costs a token | Renewals and upgrades of an active subject are free | `TestBudget` |
| Poisoned or broken reputation feed | A feed that suddenly lists `0.0.0.0/1` or RFC1918 | Entries wider than policy, reserved, private or protected are stripped; a refresh that changes over half the list (configurable) is refused; empty refreshes are refused; https only; last good copy kept | `TestSanitize...`, `TestManagerGuardsAgainstPoisonedRefresh` |
| **FireHOL level1 cuts off the LAN** | It ships RFC1918 and CGNAT as "bogons" | Same sanitiser; FireHOL left out of defaults (see `docs/alpha-sources.md`) | `TestSanitizeStripsLANAndProtected` |
| Attack-report feeds contain CDN and cloud IPs | blocklist.de lists 40 Cloudflare and 621 Google addresses | Those feeds are **inbound-only** and **throttle** class; config validation rejects throttle on outbound | config validation |
| Research scanners (Shodan, Censys) flood the escalation queue | They are on many lists but harmless | `benign` feed class: still scored, never escalated | `TestObserveAndBenignLookup` |
| Filling the SD card through log volume | Every event logged | Only evidence attached to verdicts is logged by default; size rotation; a per-second line cap with a dropped counter | journal |
| Memory exhaustion via many sources | Unbounded maps | LRU-bounded subjects, bounded flows, bounded distinct-port sets that report saturation | `TestBoundedMemory` |
| Conntrack table exhaustion under flood | Every SYN creates state | Verdict and reputation drops run at `priority -300`, before conntrack, so dropped floods create no state | ruleset test |
| NFLOG sampler overwhelmed | A burst exceeds the log rate | Conntrack independently reports failed attempts the sampler missed, and a sensor overflow is counted, not blocking | lab `TestLabEndToEnd` (scanner caught with sampling) |

## 3. Third order: the defender's own failure modes

| Failure | Consequence on a naive design | v0.1 behaviour |
|---|---|---|
| afw crashes or is killed | Blocks stay forever, or vanish | Every entry has a kernel timeout, so it lapses on its own. On restart, live entries are read back with their remaining time | lab `TestLabEnforcerPrimitives` |
| A sensor dies | Firewall goes blind silently | Sensors restart with backoff and report counters in `afw status`; nothing new is blocked while blind (fail-open) |
| nft transaction fails | Partial state | Every change is one atomic `nft -f` transaction; on failure the mirror resyncs from the kernel and retries once; otherwise the batch is logged and skipped (fail-open) | lab (apply after kernel expiry) |
| Interval set overlap errors | The kernel rejects `1.2.3.4` when `1.2.3.0/24` exists | The planner skips covered entries and replaces narrower ones with wider ones in the same transaction | `TestPlanResolvesOverlaps`, lab |
| DHCP moves the gateway or resolver | The new resolver is unprotected | Protected subjects are re-discovered every 5 minutes and the kernel set is updated |
| Pi boots before its uplink | Feeds fail, no reputation until the next 12h refresh | The last good copy loads from disk first; failed fetches retry after 2 minutes, backing off |
| Pi boots with no clock (no RTC, 1970) | Signed peer messages fail freshness checks, or replay protection is bypassed | While the local clock is clearly unset, freshness is skipped and the ID cache still blocks replays | `TestUnsetClockSkipsFreshness` |
| Teardown of a duplicated flow | FIN, TIME_WAIT and destroy events count one session three times | The first end event counts; later ones for the same flow are ignored for five minutes |
| Operator unblocks, next tick re-blocks | Same evidence, same verdict | Unblock puts the subject in **grace** (default 1h) | `TestUnblockGraceHolds`, lab |
| Shadow mode that still blocks | Rules left in the kernel | Shadow installs a ruleset with no drop rules at all | lab `TestLabShadowNeverBlocks` |
| Need to stop everything now | Hunting for the right rule | `afw panic` asks the daemon and also deletes the table directly; works even if afw is hung | lab |

## 4. Crosstalk between nodes

Nodes run independently and only *advise* each other.

| Risk | Defence | Tested |
|---|---|---|
| Forged peer messages | HMAC-SHA256 over node name and body, known peers only, key at least 32 bytes | `TestReceiveRules` |
| Replay | ID cache plus a timestamp window | `TestReplayAndRateLimit` |
| Feedback loops and cascades (A blocks, B copies, A copies B...) | Only verdicts a node reached from its **own** evidence are published (`hops: 0`). Received verdicts are stamped `hops: 1` and never relayed. A verdict that only exists because of peer evidence is not published | `TestPublishNeverRelays`, `TestPeerEvidence...` |
| A compromised or confused peer blocks the network | A peer verdict is weighted evidence (`trust × confidence`), still passes every rail (protected, budget, internal cap), and peer-derived TTLs are capped at 1h | `TestPeerEvidenceFlowsThroughRails` |
| Spoofed evidence laundered through a peer | Spoofability travels with the message: a peer *throttle* is spoofable evidence here, so it can never become a drop | `TestPeerEvidenceSpoofabilityPropagates` |
| Peer flood | Per-peer rate limit; bounded queues; senders never block | `TestReplayAndRateLimit` |
| A peer's unblock lifting our own decision | A peer `allow` only lifts actions that peer evidence produced | `TestPeerAllowLiftsOnlyPeerDerived` |

## 5. Known gaps in v0.1

- **TLS-level handshake anomalies** (ClientHello then abort, JA4 fingerprints) need payload parsing. v0.1 sees them only as short sessions.
- **UDP floods and amplification** are counted (rate, fan-out) but never dropped, by design, since all UDP evidence is spoofable. Upstream or ISP mitigation is the real fix.
- **Anti-spoofing with full bogons** on the WAN ingress needs interface awareness (which side is the internet). Planned for v0.2.
- **Encrypted DNS and SNI context** is not used yet.
- **Quarantine and decoy rerouting** are medium-tier actions (v0.2); v0.1 escalates instead.
- **Thresholds are not yet tuned on real home traffic.** Run in shadow first; the replay tool exists to tune them on your own captures.
- Running afw on a box that also runs Docker or ufw works (separate table, earlier hook priority), but other tables' rules still apply after ours.
