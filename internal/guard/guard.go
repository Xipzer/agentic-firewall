// Package guard applies the safety rails to every verdict before it can reach
// the enforcer, whatever produced it: the fast tier, a peer or a human.
package guard

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

type Config struct {
	Protected   []netip.Prefix
	Internal    []netip.Prefix
	InternalMax afp.Action
	MinPrefix4  int
	MinPrefix6  int
	MinTTL      time.Duration
	MaxTTL      map[afp.Tier]time.Duration
	PerMinute   int
	MaxActive   int
	Mode        string
}

type Guard struct {
	mu     sync.Mutex
	c      Config
	tokens float64
	refill time.Time
	active map[netip.Prefix]time.Time
	// Exhausted counts verdicts refused by the action budget.
	Exhausted uint64
}

func New(c Config) *Guard {
	if c.MinTTL == 0 {
		c.MinTTL = 30 * time.Second
	}
	return &Guard{c: c, tokens: float64(c.PerMinute), active: map[netip.Prefix]time.Time{}}
}

// Outcome is the verdict after the rails, plus whether the enforcer should act.
type Outcome struct {
	Verdict *afp.Verdict
	Prefix  netip.Prefix
	Enforce bool
	Notes   []string
	// BudgetExhausted means a real action was refused for lack of budget,
	// which itself deserves a high-priority escalation.
	BudgetExhausted bool
}

func (g *Guard) SetMode(m string) { g.mu.Lock(); g.c.Mode = m; g.mu.Unlock() }
func (g *Guard) Mode() string     { g.mu.Lock(); defer g.mu.Unlock(); return g.c.Mode }

// SetProtected replaces the protected list (for example after a re-scan).
func (g *Guard) SetProtected(ps []netip.Prefix) { g.mu.Lock(); g.c.Protected = ps; g.mu.Unlock() }

func (g *Guard) Protected() []netip.Prefix {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]netip.Prefix(nil), g.c.Protected...)
}

var capabilities = map[afp.Tier]map[afp.Action]bool{
	afp.TierFast:   {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
	afp.TierPeer:   {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
	afp.TierMedium: {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
	afp.TierSlow:   {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
	afp.TierHuman:  {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
}

// Check applies every rail in order. It never returns a harsher action than it was given.
func (g *Guard) Check(v *afp.Verdict, now time.Time) Outcome {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := Outcome{Verdict: v}
	note := func(f string, a ...any) { out.Notes = append(out.Notes, fmt.Sprintf(f, a...)) }
	downgrade := func(to afp.Action, why string) {
		if v.Action.Severity() > to.Severity() {
			note("%s downgraded to %s: %s", v.Action, to, why)
			v.Action = to
			v.Escalate = true
		}
	}
	if err := v.Validate(); err != nil {
		note("invalid verdict: %v", err)
		v.Action, v.Escalate = afp.ActionObserve, true
		return out
	}
	p, err := v.Subject.Prefix()
	if err != nil {
		downgrade(afp.ActionObserve, "flow subjects are not enforceable in v0.1")
		return out
	}
	out.Prefix = p
	v.Mode = g.c.Mode
	human := v.Source.Tier == afp.TierHuman

	if v.Action == afp.ActionAllow {
		delete(g.active, p)
		out.Enforce = g.c.Mode == "enforce"
		return out
	}
	if netx.Overlaps(p, g.c.Protected) {
		downgrade(afp.ActionObserve, "subject overlaps a protected subject")
	}
	if (p.Addr().Is4() && p.Bits() < g.c.MinPrefix4) || (p.Addr().Is6() && p.Bits() < g.c.MinPrefix6) {
		downgrade(afp.ActionObserve, fmt.Sprintf("prefix /%d is wider than policy allows", p.Bits()))
	}
	if netx.Overlaps(p, g.c.Internal) {
		downgrade(g.c.InternalMax, "internal subjects are capped by policy; quarantine is a higher-tier decision")
	}
	if !capabilities[v.Source.Tier][v.Action] && v.Action != afp.ActionObserve {
		downgrade(afp.ActionObserve, fmt.Sprintf("%s is not available to the %s tier in v0.1", v.Action, v.Source.Tier))
	}
	if v.Action == afp.ActionDrop && !human && allSpoofable(v.Signals) {
		downgrade(afp.ActionThrottle, "all evidence is spoofable")
	}
	if ttl, err := afp.ParseTTL(v.TTL); err == nil {
		max := g.c.MaxTTL[v.Source.Tier]
		if max == 0 {
			max = 24 * time.Hour
		}
		switch {
		case ttl > max:
			note("ttl %s clamped to %s", v.TTL, afp.FormatTTL(max))
			v.TTL = afp.FormatTTL(max)
		case ttl < g.c.MinTTL:
			v.TTL = afp.FormatTTL(g.c.MinTTL)
		}
	}
	if v.Action.Severity() < afp.ActionThrottle.Severity() {
		return out
	}
	for k, until := range g.active {
		if now.After(until) {
			delete(g.active, k)
		}
	}
	_, already := g.active[p]
	if !human && !already {
		g.tokens = min(float64(g.c.PerMinute), g.tokens+now.Sub(g.refill).Minutes()*float64(g.c.PerMinute))
		g.refill = now
		switch {
		case len(g.active) >= g.c.MaxActive:
			out.BudgetExhausted = true
			g.Exhausted++
			downgrade(afp.ActionObserve, "max active actions reached")
			return out
		case g.tokens < 1:
			out.BudgetExhausted = true
			g.Exhausted++
			downgrade(afp.ActionObserve, "per-minute action budget exhausted")
			return out
		}
		g.tokens--
	}
	ttl, _ := afp.ParseTTL(v.TTL)
	g.active[p] = now.Add(ttl)
	out.Enforce = g.c.Mode == "enforce"
	return out
}

func allSpoofable(sigs []afp.Signal) bool {
	if len(sigs) == 0 {
		return false
	}
	for _, s := range sigs {
		if !s.Spoofable {
			return false
		}
	}
	return true
}

// ActiveCount is the number of subjects with a live throttle or drop.
func (g *Guard) ActiveCount() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.active) }
