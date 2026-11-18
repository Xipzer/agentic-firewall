// Package fast is the fast tier: per-flow heuristics that score sources in
// milliseconds and propose verdicts. It never blocks the data path; the
// kernel enforces, this package only decides.
package fast

import (
	"container/list"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

// Reputation looks up an address in observe-class feeds.
type Reputation interface {
	Lookup(a netip.Addr) (feed string, weight float64, ok bool)
	// Benign reports known research scanners (Shodan, Censys and similar).
	// They are still scored and acted on, but never escalated.
	Benign(a netip.Addr) bool
}

type Params struct {
	H              config.Heuristics
	P              config.Policy
	Local          []netip.Prefix // this machine's addresses
	Internal       []netip.Prefix // LAN ranges
	SensitivePorts []uint16
	ServicePorts   []uint16
	MaxSubjects    int
	MaxFlows       int
	Rep            Reputation
}

// Decision is the fast tier's proposal for one subject. The guard turns it
// into an AFP verdict after applying the safety rails.
type Decision struct {
	Subject       netip.Prefix
	Action        afp.Action
	Score         float64
	NonSpoofScore float64
	TTL           time.Duration
	Signals       []afp.Signal
	Internal      bool
	Aggregate     bool
	Escalate      bool
	SpoofLimited  bool
	PeerDerived   bool
	Offences      int
	// Incumbent subjects have a proven history of legitimate sessions with us.
	Incumbent bool
	Reason    string
	Evidence      []Event
	Direction     Direction
}

type flowRec struct {
	subj, agg   netip.Prefix
	start       time.Time
	established bool
	failed      bool
	sensitive   bool
}

type pendingItem struct {
	key   flowKey
	start time.Time
}

type peerEvidence struct {
	weight    float64
	spoofable bool
	until     time.Time
	reason    string
}

type subject struct {
	key       netip.Prefix
	agg       bool
	internal  bool
	dir       Direction
	elem      *list.Element
	lastSeen  time.Time
	newConns  counter // all new flows, short window
	estConns  counter // completed handshakes, short window
	attempts  counter // tcp attempts, long-ish window
	fails     counter
	short     counter // short established sessions, weighted
	repHits   counter
	ports     distinct[uint16]
	hosts     distinct[netip.Addr]
	sources   distinct[netip.Addr] // aggregates only: distinct members
	repFeed   string
	repWeight float64
	benign    bool
	peers     map[string]peerEvidence
	evidence  []Event
}

type activeAction struct {
	action afp.Action
	until  time.Time
	peer   bool
	spoof  bool
}

type Engine struct {
	p        Params
	subjects map[netip.Prefix]*subject
	lru      *list.List
	flows    map[flowKey]*flowRec
	pending  []pendingItem
	dirty    map[netip.Prefix]struct{}
	active   map[netip.Prefix]activeAction
	offences map[netip.Prefix]int
	grace    map[netip.Prefix]time.Time
	ended    map[flowKey]time.Time
	trust    map[netip.Prefix]*TrustRecord
	sens     map[uint16]bool
	svc      map[uint16]bool
	Stats    Stats
}

type Stats struct {
	Events, Evicted, FlowsDropped, Decisions uint64
}

const failWindow = 60 * time.Second

func New(p Params) *Engine {
	if p.MaxFlows == 0 {
		p.MaxFlows = p.MaxSubjects * 8
	}
	e := &Engine{p: p, subjects: map[netip.Prefix]*subject{}, lru: list.New(), flows: map[flowKey]*flowRec{},
		dirty: map[netip.Prefix]struct{}{}, active: map[netip.Prefix]activeAction{}, offences: map[netip.Prefix]int{},
		grace: map[netip.Prefix]time.Time{}, ended: map[flowKey]time.Time{}, trust: map[netip.Prefix]*TrustRecord{}, sens: map[uint16]bool{}, svc: map[uint16]bool{}}
	for _, port := range p.SensitivePorts {
		e.sens[port] = true
	}
	for _, port := range p.ServicePorts {
		e.svc[port] = true
	}
	return e
}

func (e *Engine) classify(a netip.Addr) (local, internal bool) {
	return netx.Contains(e.p.Local, a), netx.Contains(e.p.Internal, a)
}

// Direction classifies a flow by its initiator and responder.
func (e *Engine) Direction(src, dst netip.Addr) Direction {
	sl, si := e.classify(src)
	dl, di := e.classify(dst)
	switch {
	case sl && dl:
		return DirLocal
	case !sl && !si && (dl || di):
		return DirInbound
	case (sl || si) && !dl && !di:
		return DirOutbound
	case (sl || si) && (dl || di):
		return DirInternal
	}
	return DirTransit
}

func (e *Engine) get(key netip.Prefix, agg, internal bool, now time.Time) *subject {
	if s, ok := e.subjects[key]; ok {
		e.lru.MoveToFront(s.elem)
		s.lastSeen = now
		return s
	}
	h := e.p.H
	s := &subject{key: key, agg: agg, internal: internal, lastSeen: now,
		newConns: newCounter(h.Window.D()), estConns: newCounter(h.Window.D()),
		attempts: newCounter(failWindow), fails: newCounter(failWindow), short: newCounter(failWindow),
		repHits: newCounter(h.Window.D()),
		ports:   newDistinct[uint16](1024), hosts: newDistinct[netip.Addr](1024), sources: newDistinct[netip.Addr](256)}
	s.elem = e.lru.PushFront(key)
	e.subjects[key] = s
	for len(e.subjects) > e.p.MaxSubjects {
		old := e.lru.Back()
		k := old.Value.(netip.Prefix)
		e.lru.Remove(old)
		delete(e.subjects, k)
		delete(e.dirty, k)
		e.Stats.Evicted++
	}
	return s
}

// Ingest folds one sensor event into the per-subject state.
func (e *Engine) Ingest(ev Event) {
	e.Stats.Events++
	src, dst := ev.Src.Addr().Unmap(), ev.Dst.Addr().Unmap()
	if !src.IsValid() || !dst.IsValid() {
		return
	}
	dir := e.Direction(src, dst)
	if dir == DirLocal || (dir == DirOutbound && netx.Contains(e.p.Local, src)) {
		return // this machine's own traffic is never a subject
	}
	internal := dir == DirOutbound || dir == DirInternal
	key := ev.key()
	switch ev.Kind {
	case KindNew:
		e.onNew(ev, key, src, dst, dir, internal)
	case KindEstablished:
		e.onEstablished(ev, key, src, dir, internal)
	case KindEnd:
		e.onEnd(ev, key, src, dst, dir, internal)
	}
}

func (e *Engine) subjectsFor(src netip.Addr, dir Direction, internal bool, now time.Time) (*subject, *subject) {
	s := e.get(netx.HostKey(src), false, internal, now)
	s.dir = dir
	var a *subject
	if !internal {
		a = e.get(netx.AggKey(src), true, false, now)
		a.dir = dir
		a.sources.add(src, now, e.p.H.LongWindow.D())
	}
	return s, a
}

func (e *Engine) onNew(ev Event, key flowKey, src, dst netip.Addr, dir Direction, internal bool) {
	now := ev.Time
	s, a := e.subjectsFor(src, dir, internal, now)
	port := ev.Dst.Port()
	weight := uint32(10)
	if e.svc[port] && dir == DirInbound {
		weight = 1 // published services see legitimate bursts; count them at a tenth
	}
	for _, x := range []*subject{s, a} {
		if x == nil {
			continue
		}
		x.newConns.add(now, weight)
		if port != 0 {
			x.ports.add(port, now, e.p.H.LongWindow.D())
		}
		x.hosts.add(dst, now, e.p.H.Window.D())
		if ev.Proto == ProtoTCP {
			x.attempts.add(now, 1)
		}
		e.dirty[x.key] = struct{}{}
	}
	if e.p.Rep != nil {
		peer := src
		if internal {
			peer = dst // an internal host talking to a listed address
		}
		if feed, w, ok := e.p.Rep.Lookup(peer); ok {
			s.repHits.add(now, 1)
			s.repFeed, s.repWeight = feed, w
		}
		if !internal && e.p.Rep.Benign(src) {
			s.benign = true
		}
	}
	s.remember(ev)
	if ev.Proto == ProtoTCP {
		if _, ok := e.flows[key]; !ok {
			if len(e.flows) >= e.p.MaxFlows {
				e.Stats.FlowsDropped++
				return
			}
			rec := &flowRec{subj: s.key, start: now, sensitive: e.sens[port]}
			if a != nil {
				rec.agg = a.key
			}
			e.flows[key] = rec
			e.pending = append(e.pending, pendingItem{key, now})
		}
	}
}

func (e *Engine) onEstablished(ev Event, key flowKey, src netip.Addr, dir Direction, internal bool) {
	rec, ok := e.flows[key]
	if !ok {
		// The NEW packet was not sampled. Track it from here so session length still counts.
		if len(e.flows) >= e.p.MaxFlows {
			e.Stats.FlowsDropped++
			return
		}
		s, a := e.subjectsFor(src, dir, internal, ev.Time)
		rec = &flowRec{subj: s.key, start: ev.Time, sensitive: e.sens[ev.Dst.Port()]}
		if a != nil {
			rec.agg = a.key
		}
		e.flows[key] = rec
	}
	if rec.established {
		return
	}
	rec.established = true
	for _, k := range []netip.Prefix{rec.subj, rec.agg} {
		if x, ok := e.subjects[k]; ok {
			x.estConns.add(ev.Time, 1)
			e.dirty[k] = struct{}{}
		}
	}
}

func (e *Engine) onEnd(ev Event, key flowKey, src, dst netip.Addr, dir Direction, internal bool) {
	rec, ok := e.flows[key]
	if !ok {
		if ev.Proto != ProtoTCP || ev.Assured || e.recentlyEnded(key, ev.Time) {
			return
		}
		// A failed attempt the NFLOG sampler missed (rate limit or burst).
		// Conntrack still saw it, so count the attempt, the port and the failure.
		s, a := e.subjectsFor(src, dir, internal, ev.Time)
		for _, x := range []*subject{s, a} {
			if x == nil {
				continue
			}
			x.newConns.add(ev.Time, 10)
			x.attempts.add(ev.Time, 1)
			x.fails.add(ev.Time, 1)
			x.ports.add(ev.Dst.Port(), ev.Time, e.p.H.LongWindow.D())
			x.hosts.add(dst, ev.Time, e.p.H.Window.D())
			e.dirty[x.key] = struct{}{}
		}
		s.remember(ev)
		return
	}
	e.markEnded(key, ev.Time)
	delete(e.flows, key)
	for _, k := range []netip.Prefix{rec.subj, rec.agg} {
		x, ok := e.subjects[k]
		if !ok {
			continue
		}
		switch {
		case !rec.established && !rec.failed:
			x.fails.add(ev.Time, 1)
		case rec.established && ev.Time.Sub(rec.start) < e.p.H.ShortSession.D():
			n := uint32(1)
			if rec.sensitive {
				n = 2
			}
			x.short.add(ev.Time, n)
		case rec.established && k == rec.subj && !x.internal && ev.Time.Sub(rec.start) >= TrustSession:
			e.recordTrust(k, ev.Time)
		}
		x.remember(ev)
		e.dirty[k] = struct{}{}
	}
}

// The first FIN/RST update ends a flow; the destroy event for the same flow
// can follow minutes later and must not be counted again.
func (e *Engine) markEnded(k flowKey, t time.Time) {
	if len(e.ended) >= e.p.MaxFlows {
		clear(e.ended)
	}
	e.ended[k] = t
}

func (e *Engine) recentlyEnded(k flowKey, now time.Time) bool {
	t, ok := e.ended[k]
	return ok && now.Sub(t) < 5*time.Minute
}

// TrustSession is how long a completed session must last to count as
// legitimate use. Login guessing and scanning never last this long.
const TrustSession = 30 * time.Second

const maxTrust = 8192

// TrustRecord is a source's history of legitimate sessions. It needs real
// sessions on at least two different days, so it cannot be built in one
// sitting just before an attack.
type TrustRecord struct {
	Sessions int       `json:"sessions"`
	Days     int       `json:"days"`
	LastDay  int64     `json:"last_day"`
	LastSeen time.Time `json:"last_seen"`
}

func (e *Engine) recordTrust(k netip.Prefix, t time.Time) {
	r, ok := e.trust[k]
	if !ok {
		if len(e.trust) >= maxTrust {
			e.evictTrust()
		}
		r = &TrustRecord{}
		e.trust[k] = r
	}
	r.Sessions++
	if day := t.Unix() / 86400; day != r.LastDay {
		r.Days++
		r.LastDay = day
	}
	r.LastSeen = t
}

func (e *Engine) evictTrust() {
	var oldest netip.Prefix
	var ot time.Time
	for k, r := range e.trust {
		if ot.IsZero() || r.LastSeen.Before(ot) {
			oldest, ot = k, r.LastSeen
		}
	}
	delete(e.trust, oldest)
}

// Incumbent reports whether a subject has earned trust: 3+ long sessions on
// 2+ days, the last one within 30 days.
func (e *Engine) Incumbent(k netip.Prefix, now time.Time) bool {
	r, ok := e.trust[k]
	return ok && r.Sessions >= 3 && r.Days >= 2 && now.Sub(r.LastSeen) < 30*24*time.Hour
}

// TrustSnapshot and LoadTrust persist earned trust across restarts.
func (e *Engine) TrustSnapshot() map[string]TrustRecord {
	out := make(map[string]TrustRecord, len(e.trust))
	for k, r := range e.trust {
		out[k.String()] = *r
	}
	return out
}

func (e *Engine) LoadTrust(m map[string]TrustRecord) {
	for k, r := range m {
		p, err := netip.ParsePrefix(k)
		if err != nil || r.Sessions < 0 || r.Days < 0 || len(e.trust) >= maxTrust {
			continue
		}
		rec := r
		e.trust[p.Masked()] = &rec
	}
}

// AddPeer records evidence about a subject reported by another node.
func (e *Engine) AddPeer(subj netip.Prefix, node string, weight float64, spoofable bool, ttl time.Duration, reason string, now time.Time) {
	internal := netx.Contains(e.p.Internal, subj.Addr())
	s := e.get(subj, !netx.IsHost(subj), internal, now)
	if s.peers == nil {
		s.peers = map[string]peerEvidence{}
	}
	s.peers[node] = peerEvidence{weight: weight, spoofable: spoofable, until: now.Add(ttl), reason: reason}
	e.dirty[subj] = struct{}{}
}

// Release forgets the active action on a subject. With grace > 0 the subject
// is also left alone for that long, so an operator's unblock sticks instead of
// being re-blocked on the next tick from the same evidence. With peerOnly it
// only lifts actions that peer evidence produced.
func (e *Engine) Release(subj netip.Prefix, peerOnly bool, grace time.Duration, now time.Time) bool {
	act, ok := e.active[subj]
	if peerOnly && (!ok || !act.peer) {
		return false
	}
	delete(e.active, subj)
	if s, ok := e.subjects[subj]; ok {
		s.peers = nil
	}
	if grace > 0 {
		e.grace[subj] = now.Add(grace)
	}
	return ok
}

func (s *subject) remember(ev Event) {
	if len(s.evidence) >= 8 {
		copy(s.evidence, s.evidence[1:])
		s.evidence = s.evidence[:7]
	}
	s.evidence = append(s.evidence, ev)
}

// Tick sweeps unfinished handshakes and evaluates every subject that changed.
func (e *Engine) Tick(now time.Time) []Decision {
	e.sweep(now)
	keys := make([]netip.Prefix, 0, len(e.dirty))
	for k := range e.dirty {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	clear(e.dirty)
	var out []Decision
	for _, k := range keys {
		s, ok := e.subjects[k]
		if !ok {
			continue
		}
		if d, ok := e.evaluate(s, now); ok {
			out = append(out, d)
		}
	}
	for k, a := range e.active {
		if now.After(a.until) {
			delete(e.active, k)
		}
	}
	e.Stats.Decisions += uint64(len(out))
	return out
}

func (e *Engine) sweep(now time.Time) {
	wait := e.p.H.HandshakeWait.D()
	i := 0
	for ; i < len(e.pending); i++ {
		it := e.pending[i]
		if now.Sub(it.start) < wait {
			break
		}
		rec, ok := e.flows[it.key]
		if !ok || rec.established || rec.failed || !rec.start.Equal(it.start) {
			continue
		}
		rec.failed = true
		for _, k := range []netip.Prefix{rec.subj, rec.agg} {
			if x, ok := e.subjects[k]; ok {
				x.fails.add(now, 1)
				e.dirty[k] = struct{}{}
			}
		}
	}
	e.pending = e.pending[i:]
	if len(e.ended) > 4096 {
		for k, t := range e.ended {
			if now.Sub(t) > 5*time.Minute {
				delete(e.ended, k)
			}
		}
	}
	// Forget flows that never ended (lost DESTROY events) after the long window.
	if len(e.flows) > e.p.MaxFlows/2 {
		cut := now.Add(-e.p.H.LongWindow.D())
		for k, r := range e.flows {
			if r.start.Before(cut) {
				delete(e.flows, k)
			}
		}
	}
}

// ramp maps a measurement onto a signal weight: zero below warn, 0.35 at
// warn rising to 0.95 at high and beyond.
func ramp(x, warn, high float64) float64 {
	if x < warn || warn <= 0 {
		return 0
	}
	if high <= warn {
		return 0.95
	}
	return 0.35 + 0.6*math.Min(1, (x-warn)/(high-warn))
}

func combine(sigs []afp.Signal, nonSpoofOnly bool) float64 {
	p := 1.0
	for _, s := range sigs {
		if nonSpoofOnly && s.Spoofable {
			continue
		}
		p *= 1 - math.Min(math.Max(s.Weight, 0), 0.999)
	}
	return 1 - p
}

func (e *Engine) signals(s *subject, now time.Time) []afp.Signal {
	h := e.p.H
	f := 1.0
	if s.agg {
		f = h.AggregateFactor
		if s.sources.count(now.Add(-h.LongWindow.D())) < 3 {
			return nil // one busy host is already handled at host level
		}
	}
	win := h.Window.D()
	var sigs []afp.Signal
	add := func(name string, w float64, spoof bool, detail string, args ...any) {
		if w > 0 {
			sigs = append(sigs, afp.Signal{Name: name, Weight: round(w), Spoofable: spoof, Detail: fmt.Sprintf(detail, args...)})
		}
	}
	rate := float64(s.newConns.sum(now)) / 10 / win.Seconds()
	add("conn_rate", ramp(rate, h.RateWarn*f, h.RateHigh*f), true, "%.1f new flows/s over %s", rate, win)
	est := float64(s.estConns.sum(now)) / win.Seconds()
	add("established_rate", ramp(est, h.RateWarn*f, h.RateHigh*f), false, "%.1f completed handshakes/s over %s", est, win)

	ports := s.ports.count(now.Add(-win))
	add("port_fanout", ramp(float64(ports), float64(h.PortsWarn)*f, float64(h.PortsHigh)*f), true, "%d distinct ports in %s", ports, win)
	longPorts := s.ports.count(now.Add(-h.LongWindow.D()))
	add("slow_scan", ramp(float64(longPorts), float64(h.PortsLongHigh)*f/4, float64(h.PortsLongHigh)*f), true,
		"%d distinct ports in %s", longPorts, h.LongWindow.D())
	hosts := s.hosts.count(now.Add(-win))
	hf := f
	if s.internal {
		hf *= 8 // one web page can touch dozens of hosts; worms show up through failed handshakes instead
	}
	add("host_fanout", ramp(float64(hosts), float64(h.HostsWarn)*hf, float64(h.HostsHigh)*hf), !s.internal, "%d distinct targets in %s", hosts, win)

	attempts, fails := s.attempts.sum(now), s.fails.sum(now)
	if fails >= uint32(h.FailMin) && attempts > 0 {
		ratio := math.Min(1, float64(fails)/float64(attempts))
		if ratio >= 0.5 {
			w := ramp(float64(fails), float64(h.FailMin)*f, float64(h.FailMin)*10*f) * ratio
			add("handshake_fail", w, true, "%d of %d TCP handshakes never completed in %s", fails, attempts, failWindow)
		}
	}
	short := s.short.sum(now)
	add("short_sessions", ramp(float64(short), float64(h.ShortWarn)*f, float64(h.ShortHigh)*f), false,
		"%d short completed sessions in %s (sensitive ports count double)", short, failWindow)
	if s.repHits.sum(now) > 0 && s.repWeight > 0 {
		add("reputation", s.repWeight, false, "listed in %s", s.repFeed)
	}
	for node, pe := range s.peers {
		if now.After(pe.until) {
			delete(s.peers, node)
			continue
		}
		add("peer:"+node, pe.weight, pe.spoofable, "%s", pe.reason)
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].Weight > sigs[j].Weight })
	return sigs
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }

func (e *Engine) actionFor(score, nonSpoof float64) (afp.Action, bool) {
	p := e.p.P
	switch {
	case score >= p.Drop && nonSpoof >= p.Drop:
		return afp.ActionDrop, false
	case score >= p.Drop:
		return afp.ActionThrottle, true // spoofable evidence can slow a source, never cut it off
	case score >= p.Throttle:
		return afp.ActionThrottle, false
	case score >= p.Observe:
		return afp.ActionObserve, false
	}
	return "", false
}

func (e *Engine) evaluate(s *subject, now time.Time) (Decision, bool) {
	if until, ok := e.grace[s.key]; ok {
		if now.Before(until) {
			return Decision{}, false
		}
		delete(e.grace, s.key)
	}
	sigs := e.signals(s, now)
	if len(sigs) == 0 {
		return Decision{}, false
	}
	score, nonSpoof := combine(sigs, false), combine(sigs, true)
	act, spoofLimited := e.actionFor(score, nonSpoof)
	incumbent := !s.agg && !s.internal && e.Incumbent(s.key, now)
	if incumbent {
		// A source with a proven history of real sessions is judged on proven
		// evidence only. Spoofed packets carrying its address can at most get
		// it watched, so an attacker cannot use its identity against us.
		act, spoofLimited = e.actionFor(nonSpoof, nonSpoof)
		if act == "" && score >= e.p.P.Observe {
			act = afp.ActionObserve
		}
	}
	if act == "" {
		return Decision{}, false
	}
	local := slices.DeleteFunc(slices.Clone(sigs), func(x afp.Signal) bool { return strings.HasPrefix(x.Name, "peer:") })
	localAct, _ := e.actionFor(combine(local, false), combine(local, true))
	peerDerived := localAct.Severity() < act.Severity()

	cur, has := e.active[s.key]
	if has && now.Before(cur.until) {
		// Re-issue only on escalation, or to renew a block that is about to lapse while still deserved.
		same := act.Severity() == cur.action.Severity()
		renew := same && cur.until.Sub(now) < e.p.P.BaseTTL.D()/4
		// A throttle that now has drop-level but spoofable evidence is re-issued once so it gets escalated.
		newlySpoofLimited := same && spoofLimited && !cur.spoof
		if act.Severity() < cur.action.Severity() || (same && !renew && !newlySpoofLimited) {
			return Decision{}, false
		}
	}
	offences := e.offences[s.key]
	alreadyEnforced := has && now.Before(cur.until) && cur.action.Severity() >= afp.ActionThrottle.Severity()
	// Only proven evidence lengthens punishment. Otherwise an attacker spoofing
	// a victim's address could ratchet the victim's throttle up to 24 hours.
	proven := !spoofLimited && nonSpoof >= e.p.P.Throttle
	if proven && act.Severity() >= afp.ActionThrottle.Severity() && (!alreadyEnforced || cur.until.Sub(now) < e.p.P.BaseTTL.D()/4) {
		offences++
		e.offences[s.key] = offences
		if len(e.offences) > e.p.MaxSubjects {
			clear(e.offences) // bounded memory; repeat-offender history is best effort
		}
	}
	ttl := e.ttl(offences)
	if alreadyEnforced && cur.until.After(now.Add(ttl)) {
		ttl = cur.until.Sub(now)
	}
	e.active[s.key] = activeAction{action: act, until: now.Add(ttl), peer: peerDerived, spoof: spoofLimited}
	d := Decision{Subject: s.key, Action: act, Score: round(score), NonSpoofScore: round(nonSpoof), TTL: ttl,
		Signals: sigs, Internal: s.internal, Aggregate: s.agg, SpoofLimited: spoofLimited, PeerDerived: peerDerived,
		Offences: offences, Evidence: slices.Clone(s.evidence), Direction: s.dir, Incumbent: incumbent}
	d.Escalate = !s.benign && (spoofLimited || s.internal || s.agg || incumbent || (act != afp.ActionObserve && score < 0.9))
	d.Reason = reason(d)
	return d, true
}

func (e *Engine) ttl(offences int) time.Duration {
	p := e.p.P
	if offences < 1 {
		offences = 1
	}
	t := float64(p.BaseTTL.D()) * math.Pow(p.TTLMultiplier, float64(offences-1))
	return time.Duration(math.Min(t, float64(p.MaxTTL.D())))
}

func reason(d Decision) string {
	var parts []string
	for i, s := range d.Signals {
		if i == 3 {
			break
		}
		parts = append(parts, s.Detail)
	}
	r := strings.Join(parts, "; ")
	if d.SpoofLimited {
		r += " (evidence is spoofable, so throttled rather than dropped)"
	}
	if d.Incumbent {
		r += " (source has a history of legitimate sessions: judged on proven evidence only; may be a shared address)"
	}
	return r
}

// Active reports the number of subjects with a live action.
func (e *Engine) Active() int { return len(e.active) }
