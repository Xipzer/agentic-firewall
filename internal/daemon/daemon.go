// Package daemon wires sensors, the fast tier, the guard, the enforcer, the
// journal, reputation feeds and crosstalk into one process.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/canary"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/coverage"
	"github.com/Xipzer/agentic-firewall/internal/crosstalk"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/graph"
	"github.com/Xipzer/agentic-firewall/internal/guard"
	"github.com/Xipzer/agentic-firewall/internal/incident"
	"github.com/Xipzer/agentic-firewall/internal/journal"
	"github.com/Xipzer/agentic-firewall/internal/netx"
	"github.com/Xipzer/agentic-firewall/internal/posture"
	"github.com/Xipzer/agentic-firewall/internal/reputation"
	"github.com/Xipzer/agentic-firewall/internal/sensor"
)

const Agent = "heuristics-v1"

type Daemon struct {
	Cfg       config.Config
	Log       *slog.Logger
	Enforcer  enforce.Enforcer
	Journal   *journal.Journal
	Feeds     *reputation.Manager
	Bus       *crosstalk.Bus
	Engine    *fast.Engine
	Guard     *guard.Guard
	Events    chan fast.Event
	Posture   *posture.Controller
	Ledger    *coverage.Ledger
	Graph     *graph.Graph
	Tarpit    *canary.Tarpit
	Incidents *incident.Grouper
	// Now is the clock; replaceable in tests.
	Now func() time.Time

	src       afp.Source
	cmds      chan func()
	applyCh   chan enforce.Entry
	mu        sync.Mutex
	probation time.Time
	confirmed bool
	panicked  bool
	started   time.Time
	discover  func() config.Discovered
	done      chan struct{}
	internal  []netip.Prefix
	local     []netip.Prefix
	adv       *adviser
	ticks     int
	running   atomic.Bool
	// Kernel probes; replaceable in tests.
	TableFill func() float64
	Reclaim   func(keep func(netip.Addr) bool, limit int) (int, error)
	lastShed  uint64
	reclaimAt time.Time
	reclaimMu sync.Mutex
}

// New builds a daemon. Enforcer, journal and bus may be swapped before Run.
func New(cfg config.Config, log *slog.Logger) *Daemon {
	d := &Daemon{Cfg: cfg, Log: log, Now: time.Now, Events: make(chan fast.Event, 16384),
		cmds: make(chan func(), 64), applyCh: make(chan enforce.Entry, 4096), discover: config.Discover,
		src: afp.Source{Tier: afp.TierFast, Agent: Agent, Node: cfg.Node}, done: make(chan struct{}),
		TableFill: sensor.ConntrackFill, Reclaim: sensor.Reclaim}
	return d
}

func (d *Daemon) protectedNow() []netip.Prefix {
	ps := append([]netip.Prefix(nil), d.Cfg.ProtectedPrefixes()...)
	if d.Cfg.AutoProtectEnabled() {
		ps = append(ps, d.discover().All()...)
	}
	return netx.Collapse(ps)
}

// Init prepares everything that does not need the kernel.
func (d *Daemon) Init() error {
	disc := d.discover()
	prot := d.protectedNow()
	local := disc.Self
	internal := d.Cfg.InternalPrefixes()
	if d.Cfg.Role == "gateway" {
		internal = append(internal, disc.OnLink...)
	}
	maxAct := map[string]afp.Action{"observe": afp.ActionObserve, "throttle": afp.ActionThrottle, "drop": afp.ActionDrop}[d.Cfg.InternalMax]
	d.Guard = guard.New(guard.Config{Protected: prot, Internal: internal, InternalMax: maxAct,
		MinPrefix4: d.Cfg.Policy.MinPrefix4, MinPrefix6: d.Cfg.Policy.MinPrefix6,
		MaxTTL: map[afp.Tier]time.Duration{afp.TierFast: d.Cfg.Policy.MaxTTL.D(), afp.TierPeer: d.Cfg.Crosstalk.MaxTTL.D(),
			afp.TierHuman: 7 * 24 * time.Hour, afp.TierMedium: d.Cfg.Policy.MaxTTL.D(), afp.TierSlow: d.Cfg.Policy.MaxTTL.D()},
		PerMinute: d.Cfg.Budget.PerMinute, MaxActive: d.Cfg.Budget.MaxActive, Mode: d.Cfg.Mode})
	if d.Feeds == nil {
		d.Feeds = reputation.NewManager(d.Cfg.Feeds, d.Cfg.StateDir, d.Cfg.Policy.MinPrefix4, max(d.Cfg.Policy.MinPrefix6, 16), d.Guard.Protected)
	}
	d.Engine = fast.New(fast.Params{H: d.Cfg.Heuristics, P: d.Cfg.Policy, Local: local, Internal: internal,
		SensitivePorts: d.Cfg.SensitivePorts, ServicePorts: d.Cfg.ServicePorts, MaxSubjects: d.Cfg.MaxSubjects, Rep: d.Feeds})
	d.loadTrust()
	d.internal = internal
	d.local = local
	d.adv = newAdviser()
	bg := d.Cfg.BreakGlass
	pc := posture.DefaultConfig()
	pc.Auto, pc.MinRate, pc.Surge, pc.AbsRate, pc.FailRatio = bg.Auto, bg.MinRate, bg.Surge, bg.AbsRate, bg.FailRatio
	pc.Hold, pc.ManualHold = bg.Hold.D(), bg.ManualHold.D()
	d.Posture = posture.New(pc)
	d.Ledger = coverage.New()
	if len(d.Cfg.Canary.Ports) > 0 {
		d.Tarpit = canary.New(canary.Config{Ports: d.Cfg.Canary.Ports, Listen: d.Cfg.Canary.Listen,
			Hold: d.Cfg.Canary.Hold.D(), MaxConns: d.Cfg.Canary.MaxConns}, d.Log)
	}
	d.Graph = graph.New(0)
	n := 0
	for _, f := range JournalFiles(d.Cfg.Log.Path, d.Cfg.Log.Keep) {
		if d.Cfg.Log.Path == "" || d.Cfg.Log.Path == "-" {
			break
		}
		if fh, err := os.Open(f); err == nil {
			n += d.Graph.Load(fh)
			fh.Close()
		}
	}
	if n > 0 {
		d.Log.Info("evidence graph rebuilt from journal", "messages", n, "nodes", d.Graph.Len())
	}
	ic := incident.DefaultConfig()
	ic.AnalystPerHour, ic.AnalystPerDay, ic.Window = d.Cfg.Analyst.PerHour, d.Cfg.Analyst.PerDay, d.Cfg.Analyst.IncidentWindow.D()
	d.Incidents = incident.New(ic)
	if d.Journal == nil {
		j, err := journal.Open(d.Cfg.Log.Path, d.Cfg.Log.MaxMB, d.Cfg.Log.Keep)
		if err != nil {
			return err
		}
		d.Journal = j
	}
	if d.Enforcer == nil {
		n := enforce.NewNFT(d.Cfg.NFT.Binary, d.Cfg.NFT.Table, d.Cfg.NFT.LogGroup, d.Cfg.NFT.LogRate, d.Cfg.Policy.ThrottleRate)
		n.SensitivePorts = d.Cfg.SensitivePorts
		d.Enforcer = n
	}
	if d.Bus == nil && len(d.Cfg.Crosstalk.Peers) > 0 {
		key, err := crosstalk.LoadKey(d.Cfg.Crosstalk.KeyFile)
		if err != nil {
			return fmt.Errorf("crosstalk: %w", err)
		}
		d.Bus = crosstalk.New(d.Cfg.Node, key, d.Cfg.Crosstalk)
	}
	d.Log.Info("protected subjects", "count", len(prot), "list", prot)
	return nil
}

func (d *Daemon) enforcing() bool { return d.Guard.Mode() == "enforce" }

// Run installs the ruleset and processes events until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	d.started = d.Now()
	if err := d.Enforcer.Setup(ctx, d.Guard.Protected(), !d.enforcing()); err != nil {
		return fmt.Errorf("install ruleset: %w", err)
	}
	if d.enforcing() && d.Cfg.Probation > 0 {
		d.probation = d.started.Add(d.Cfg.Probation.D())
		d.Log.Warn("enforcing on probation: run `afw confirm` or enforcement disarms", "at", d.probation.Format(time.RFC3339))
	}
	d.Feeds.LoadCache()
	d.pushReputation(ctx)
	var wg sync.WaitGroup
	start := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	start(func() { d.applier(ctx) })
	start(func() { d.feedLoop(ctx) })
	start(func() { d.housekeeping(ctx) })
	if d.Tarpit != nil {
		start(func() { d.Tarpit.Run(ctx) })
	}
	if sock := d.Cfg.Analyst.Socket; sock != "" {
		start(func() {
			if err := d.ServeAdviser(ctx, sock); err != nil {
				d.Log.Error("adviser socket", "err", err)
			}
		})
	}
	if d.Bus != nil {
		start(func() { d.Bus.Run(ctx) })
		if d.Cfg.Crosstalk.Listen != "" {
			srv := &http.Server{Addr: d.Cfg.Crosstalk.Listen, Handler: d.Bus, ReadHeaderTimeout: 5 * time.Second}
			start(func() {
				if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					d.Log.Error("crosstalk listener", "err", err)
				}
			})
			start(func() { <-ctx.Done(); _ = srv.Close() })
		}
	}
	d.running.Store(true)
	d.loop(ctx)
	d.running.Store(false)
	wg.Wait()
	d.saveTrust()
	d.Journal.Flush()
	close(d.done)
	if d.Cfg.NFT.OnExit == "teardown" && !d.panicked {
		return d.Enforcer.Teardown(context.Background())
	}
	return nil
}

func (d *Daemon) loop(ctx context.Context) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var inbox chan crosstalk.Received
	if d.Bus != nil {
		inbox = d.Bus.Inbox
	}
	var hits chan canary.Hit
	if d.Tarpit != nil {
		hits = d.Tarpit.Hits
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.Events:
			d.ingest(ev)
		case <-tick.C:
			d.tick(ctx, d.Now())
		case r := <-inbox:
			d.peer(r)
		case h := <-hits:
			d.onCanary(h)
		case f := <-d.cmds:
			f()
		}
	}
}

func (d *Daemon) ingest(ev fast.Event) {
	d.Engine.Ingest(ev)
	dir := d.Engine.Direction(ev.Src.Addr().Unmap(), ev.Dst.Addr().Unmap())
	d.Ledger.Observe(ev, dir)
	if d.Cfg.Log.Observations == "all" {
		d.record(ev.Observation(afp.Source{Tier: afp.TierDataplane, Agent: "sensor", Node: d.Cfg.Node}, dir))
	}
}

// record writes a message to the journal (the record of truth) and indexes
// it in the evidence graph. Everything afw says goes through here, so the
// graph can always be rebuilt from the journal and never disagrees with it.
func (d *Daemon) record(msg any) {
	d.Journal.Write(msg)
	if d.Graph != nil {
		d.Graph.Ingest(msg)
	}
}

// JournalFiles lists a journal and its rotations, oldest first.
func JournalFiles(path string, keep int) []string {
	var out []string
	for i := keep; i >= 1; i-- {
		out = append(out, fmt.Sprintf("%s.%d", path, i))
	}
	return append(out, path)
}

// escalate records an escalation through the incident grouper, which folds
// repeats of the same campaign and rations analyst attention.
func (d *Daemon) escalate(e *afp.Escalation, asset string, now time.Time) {
	novel := false
	if e.Class != "" {
		novel = d.Ledger.Classified(asset, e.Class, now)
	}
	if asset != "" && d.Ledger.Novelty(asset, now) >= 0.5 {
		novel = true
	}
	if out := d.Incidents.Admit(e, novel, now); out != nil {
		d.record(out)
	}
}

func assetOf(dec fast.Decision) string {
	if n := len(dec.Evidence); n > 0 {
		return coverage.AssetOf(dec.Evidence[n-1], dec.Direction)
	}
	return ""
}

func (d *Daemon) tick(ctx context.Context, now time.Time) {
	d.checkProbation(ctx, now)
	d.ticks++
	if d.ticks%4 == 0 {
		d.updatePosture(ctx, now)
	}
	if d.ticks%120 == 0 && d.enforcing() {
		_ = d.Enforcer.SetTrusted(ctx, d.Engine.Trusted(now))
	}
	for _, dec := range d.Engine.Tick(now) {
		d.decide(dec, now)
	}
}

// decide runs one decision through the rails and out to every consumer.
func (d *Daemon) decide(dec fast.Decision, now time.Time) *afp.Verdict {
	v, obs := verdictFrom(dec, d.src, d.Cfg.Policy.ThrottleRate)
	v.TS = now.UTC() // the decision clock, so replays carry their original times
	v.Posture = d.Posture.Level().String()
	out := d.Guard.Check(v, now)
	if d.Cfg.Log.Observations != "none" && d.Cfg.Log.Observations != "all" {
		for _, o := range obs {
			d.record(o)
		}
	}
	d.record(v)
	x := explain(v, &dec, out)
	x.TS = v.TS
	d.record(x)
	if v.Escalate || out.BudgetExhausted {
		e := escalation(v, &dec, out)
		e.TS = v.TS
		d.escalate(e, assetOf(dec), now)
	} else if v.Class != "" {
		d.Ledger.Classified(assetOf(dec), v.Class, now)
	}
	if out.Enforce && (v.Action == afp.ActionDrop || v.Action == afp.ActionThrottle) {
		ttl, _ := afp.ParseTTL(v.TTL)
		select {
		case d.applyCh <- enforce.Entry{Prefix: out.Prefix, Action: v.Action, TTL: ttl}:
		default:
			d.Log.Warn("enforcer queue full; verdict logged but not applied", "subject", v.Subject.Value)
		}
	}
	if d.Bus != nil && !dec.PeerDerived && (v.Action.Severity() >= afp.ActionThrottle.Severity() || dec.Internal) {
		d.Bus.Publish(v)
	}
	if v.Action != afp.ActionObserve {
		d.Log.Info("verdict", "subject", v.Subject.Value, "action", v.Action, "ttl", v.TTL, "mode", v.Mode,
			"confidence", v.Confidence, "reason", v.Reason)
	}
	return v
}

// onCanary handles a completed connection to a decoy port. It is proven
// evidence, so the decision is made at once instead of on the next tick:
// against a machine-speed attacker, the time to block is what matters.
func (d *Daemon) onCanary(h canary.Hit) {
	if !h.Src.IsValid() {
		return
	}
	now := d.Now()
	o := &afp.Observation{Envelope: afp.NewEnvelope(afp.TypeObservation, afp.Source{Tier: afp.TierDataplane, Agent: "decoy", Node: d.Cfg.Node}),
		Event: "established", Flow: &afp.Flow{Src: h.Src.String(), Dst: h.Dst.String(), Proto: "tcp",
			Direction: d.Engine.Direction(h.Src.Addr(), h.Dst.Addr()).String()},
		Context: map[string]any{"decoy_port": h.Dst.Port()}}
	o.TS = now.UTC()
	if len(h.Payload) > 0 {
		// Attacker-written bytes: recorded as quoted data, never interpreted.
		o.Context["first_bytes"] = strconv.QuoteToASCII(string(h.Payload))
	}
	d.record(o)
	if h.Followup {
		return // the touch was already counted; this only adds what the client sent
	}
	d.Engine.AddCanary(h.Src, h.Dst, now)
	for _, dec := range d.Engine.Tick(now) {
		d.decide(dec, now)
	}
}

// peer folds a verdict from another node in as evidence, never as a command.
func (d *Daemon) peer(r crosstalk.Received) {
	v := r.Verdict
	d.record(v)
	p, err := v.Subject.Prefix()
	if err != nil {
		return
	}
	if netx.IsHost(p) {
		p = netx.HostKey(p.Addr())
	}
	now := d.Now()
	if v.Action == afp.ActionAllow {
		if d.Engine.Release(p, true, 0, now) && d.enforcing() {
			_ = d.Enforcer.Remove(context.Background(), []netip.Prefix{p})
		}
		return
	}
	ttl, _ := afp.ParseTTL(v.TTL)
	if max := d.Cfg.Crosstalk.MaxTTL.D(); max > 0 && ttl > max {
		ttl = max
	}
	// A peer's drop means its own evidence was non-spoofable; anything less is treated as spoofable here too.
	d.Engine.AddPeer(p, r.Peer.Node, r.Peer.Trust*v.Confidence, v.Action != afp.ActionDrop, ttl,
		fmt.Sprintf("peer %s: %s %s (%s)", r.Peer.Node, v.Action, v.Subject.Value, v.Reason), now)
}

// applier batches enforcer writes so a burst costs one nft transaction.
func (d *Daemon) applier(ctx context.Context) {
	for {
		var batch []enforce.Entry
		select {
		case <-ctx.Done():
			return
		case e := <-d.applyCh:
			batch = append(batch, e)
		}
		timer := time.NewTimer(50 * time.Millisecond)
	collect:
		for len(batch) < 256 {
			select {
			case e := <-d.applyCh:
				batch = append(batch, e)
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		if !d.enforcing() {
			continue
		}
		if err := d.Enforcer.Apply(ctx, batch); err != nil {
			d.Log.Error("enforcer apply failed; failing open for this batch", "err", err, "entries", len(batch))
		}
	}
}

func (d *Daemon) pushReputation(ctx context.Context) {
	if !d.enforcing() {
		return
	}
	l := d.Feeds.Lists()
	if err := d.Enforcer.ReplaceReputation(ctx, enforce.Reputation{DropIn: l.DropIn, DropOut: l.DropOut, ThrottleIn: l.ThrottleIn}); err != nil {
		d.Log.Error("reputation load failed", "err", err)
		return
	}
	d.Log.Info("reputation loaded", "drop_in", len(l.DropIn), "drop_out", len(l.DropOut), "throttle_in", len(l.ThrottleIn))
}

func (d *Daemon) feedLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		changed := false
		for _, f := range d.Feeds.Due(d.Now()) {
			if err := d.Feeds.Refresh(ctx, f); err != nil {
				d.Log.Warn("feed refresh", "err", err)
			} else if f.Action == "drop" || f.Action == "throttle" {
				changed = true
			}
		}
		if changed {
			d.pushReputation(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// housekeeping re-discovers protected subjects (DHCP can move the gateway or
// resolver) and flushes the journal.
func (d *Daemon) housekeeping(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	last := fmt.Sprint(d.Guard.Protected())
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.Journal.Flush()
		if n%10 == 9 {
			d.do(d.saveTrust)
		}
		if n%5 != 4 {
			continue
		}
		prot := d.protectedNow()
		if s := fmt.Sprint(prot); s != last {
			last = s
			d.Guard.SetProtected(prot)
			if err := d.Enforcer.SetProtected(ctx, prot); err != nil {
				d.Log.Error("update protected set", "err", err)
			}
			_ = d.Enforcer.Remove(ctx, prot)
			d.Log.Info("protected subjects changed", "list", prot)
		}
	}
}

func (d *Daemon) checkProbation(ctx context.Context, now time.Time) {
	d.mu.Lock()
	expired := !d.probation.IsZero() && !d.confirmed && now.After(d.probation)
	if expired {
		d.probation = time.Time{}
	}
	d.mu.Unlock()
	if !expired {
		return
	}
	d.Log.Warn("probation expired without `afw confirm`: disarming enforcement (shadow mode)")
	d.setMode(ctx, "shadow")
}

func (d *Daemon) setMode(ctx context.Context, mode string) error {
	if d.Guard.Mode() == mode {
		return nil
	}
	if err := d.Enforcer.Setup(ctx, d.Guard.Protected(), mode != "enforce"); err != nil {
		return err
	}
	d.Guard.SetMode(mode)
	if mode == "enforce" {
		d.applyKernelPosture(ctx, d.Now())
	}
	d.record(map[string]any{"afp": afp.Version, "type": "event", "ts": d.Now().UTC(), "event": "mode", "mode": mode, "node": d.Cfg.Node})
	if mode == "enforce" {
		d.pushReputation(ctx)
	}
	return nil
}

func (d *Daemon) trustPath() string { return filepath.Join(d.Cfg.StateDir, "trust.json") }

// loadTrust restores earned trust. A missing or corrupt file just means no
// source starts out trusted, which is the safe direction.
func (d *Daemon) loadTrust() {
	b, err := os.ReadFile(d.trustPath())
	if err != nil {
		return
	}
	var m map[string]fast.TrustRecord
	if json.Unmarshal(b, &m) == nil {
		d.Engine.LoadTrust(m)
	}
}

func (d *Daemon) saveTrust() {
	b, err := json.Marshal(d.Engine.TrustSnapshot())
	if err != nil || os.MkdirAll(d.Cfg.StateDir, 0o750) != nil {
		return
	}
	tmp := d.trustPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, d.trustPath())
	}
}

func (d *Daemon) updatePosture(ctx context.Context, now time.Time) {
	p := d.Engine.Pressure(now)
	p.ConntrackFill = d.TableFill()
	if d.Posture.Level() == posture.BreakGlass && d.enforcing() {
		if st, err := d.Enforcer.Stats(ctx); err == nil {
			shed := st["breakglass_packets"]
			if shed >= d.lastShed {
				p.ShedPerSec = float64(shed - d.lastShed)
			}
			d.lastShed = shed
		}
	}
	if d.Posture.Update(p, d.Guard.ExhaustedCount(), now) {
		d.onPostureChange(ctx, now)
	}
	if d.Posture.Level() == posture.BreakGlass && d.enforcing() && p.ConntrackFill >= 0.7 {
		d.reclaim(now)
	}
}

// reclaim frees connection-table slots held by half-open or closing
// connections from untrusted sources, so genuine users can connect again.
// It runs off the event loop, at most every 5 seconds.
func (d *Daemon) reclaim(now time.Time) {
	if now.Sub(d.reclaimAt) < 5*time.Second || !d.reclaimMu.TryLock() {
		return
	}
	d.reclaimAt = now
	keepSet := append(append(d.Guard.Protected(), d.Engine.Trusted(now)...), d.internal...)
	go func() {
		defer d.reclaimMu.Unlock()
		n, err := d.Reclaim(func(a netip.Addr) bool { return netx.Contains(keepSet, a) }, 200000)
		if err != nil {
			d.Log.Error("reclaim connection table", "err", err)
			return
		}
		d.Log.Warn("break-glass reclaimed connection-table slots from untrusted half-open or closing connections", "entries", n)
		d.record(map[string]any{"afp": afp.Version, "type": "event", "ts": time.Now().UTC(), "event": "reclaim", "entries": n, "node": d.Cfg.Node})
	}()
}

// onPostureChange applies a new posture everywhere it matters and records
// why. Break-glass widens how hard afw acts, never what it may act on:
// protected subjects, harm direction, TTLs and spoof rules are unchanged.
func (d *Daemon) onPostureChange(ctx context.Context, now time.Time) {
	lvl := d.Posture.Level()
	if lvl == posture.BreakGlass {
		d.Engine.SetSensitivity(d.Cfg.BreakGlass.Sensitivity)
		d.Guard.SetBudgetFactor(d.Cfg.BreakGlass.BudgetFactor)
	} else {
		d.Engine.SetSensitivity(1)
		d.Guard.SetBudgetFactor(1)
	}
	d.applyKernelPosture(ctx, now)
	reasons := strings.Join(d.Posture.Reasons, "; ")
	src := afp.Source{Tier: afp.TierFast, Agent: "posture", Node: d.Cfg.Node}
	o := &afp.Observation{Envelope: afp.NewEnvelope(afp.TypeObservation, src), Event: "sample",
		Context: map[string]any{"posture": lvl.String(), "reasons": d.Posture.Reasons, "baseline_per_sec": d.Posture.Baseline(),
			"incumbents": len(d.Engine.Trusted(now)), "enforced": d.enforcing()}}
	o.TS = now.UTC()
	d.record(o)
	if lvl == posture.BreakGlass {
		e := &afp.Escalation{Envelope: afp.NewEnvelope(afp.TypeEscalation, src),
			Subject: afp.Subject{Kind: afp.SubjectPrefix, Value: "0.0.0.0/0"}, Refs: []string{o.ID},
			Priority: "critical", Target: afp.TierHuman, Class: "dos.flood", Deadline: afp.FormatTTL(d.Cfg.BreakGlass.Hold.D()),
			Question: "Break-glass is on: " + reasons + ". Trusted sources keep full access and newcomers share a capped lane. Is this an attack to ride out, or legitimate demand (a launch, a backup) that needs `afw breakglass off`?"}
		e.TS = now.UTC()
		d.escalate(e, "", now)
		d.Log.Warn("BREAK-GLASS on", "reasons", reasons)
	} else {
		d.Log.Info("posture", "level", lvl.String(), "reasons", reasons)
	}
}

func (d *Daemon) applyKernelPosture(ctx context.Context, now time.Time) {
	if !d.enforcing() {
		return
	}
	var spec *enforce.BreakGlassSpec
	if d.Posture.Level() == posture.BreakGlass {
		_ = d.Enforcer.SetTrusted(ctx, d.Engine.Trusted(now))
		spec = &enforce.BreakGlassSpec{Internal: d.internal, PerSource: d.Cfg.BreakGlass.PerSourceRate, NewcomerRate: d.Cfg.BreakGlass.NewcomerRate}
	}
	if err := d.Enforcer.BreakGlass(ctx, spec); err != nil {
		d.Log.Error("break-glass lane", "err", err)
	}
}

// do runs f on the event loop goroutine and waits for it.
func (d *Daemon) do(f func()) {
	if !d.running.Load() {
		f() // no event loop yet (tests, replay, start-up): nothing to race with
		return
	}
	ch := make(chan struct{})
	select {
	case d.cmds <- func() { f(); close(ch) }:
		<-ch
	case <-d.done:
	}
}
