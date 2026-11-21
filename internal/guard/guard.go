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
	tokens [2]float64 // per budget class: proven, spoofable
	refill time.Time
	active map[netip.Prefix]activeEntry
	// Exhausted counts verdicts refused by the action budget.
	Exhausted uint64
	factor    float64
}

// SetBudgetFactor scales the action budget (break-glass raises it). Every
// other rail is unchanged: protected subjects, prefix limits, TTL caps and
// the spoofable/proven split still hold.
func (g *Guard) SetBudgetFactor(f float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.factor = max(1, f)
}

func (g *Guard) ExhaustedCount() uint64 { g.mu.Lock(); defer g.mu.Unlock(); return g.Exhausted }

func New(c Config) *Guard {
	if c.MinTTL == 0 {
		c.MinTTL = 30 * time.Second
	}
	g := &Guard{c: c, active: map[netip.Prefix]activeEntry{}, factor: 1}
	g.tokens = [2]float64{g.rate(classProven), g.rate(classSpoof)}
	return g
}

type activeEntry struct {
	until time.Time
	class int
}

const (
	classProven = 0
	classSpoof  = 1
)

// Actions justified only by spoofable evidence draw on a separate, smaller
// budget (half), so fake traffic can never spend the budget that real,
// proven attacks need.
func (g *Guard) rate(class int) float64 {
	f := max(1, g.factor)
	if class == classSpoof {
		return max(1, f*float64(g.c.PerMinute)/2)
	}
	return f * float64(g.c.PerMinute)
}

func (g *Guard) activeOf(class int) int {
	n := 0
	for _, a := range g.active {
		if a.class == class {
			n++
		}
	}
	return n
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
	// Refused means the verdict was rejected outright and nothing changed.
	Refused bool
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
	afp.TierFast: {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
	afp.TierPeer: {afp.ActionObserve: true, afp.ActionThrottle: true, afp.ActionDrop: true},
	// Model tiers are advisers. Their output reaches the engine as weighted,
	// unproven evidence (see daemon.Propose); even a verdict that claimed to
	// come from them directly could never drop.
	afp.TierMedium: {afp.ActionObserve: true, afp.ActionThrottle: true},
	afp.TierSlow:   {afp.ActionObserve: true, afp.ActionThrottle: true},
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
		// Only a person may lift an action. If a model or a peer could, a
		// compromised one would simply unblock the attacker.
		if !human {
			note("allow refused: only a human may lift an action, not the %s tier", v.Source.Tier)
			out.Refused = true
			return out
		}
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
	for k, a := range g.active {
		if now.After(a.until) {
			delete(g.active, k)
		}
	}
	class := classProven
	if allSpoofable(v.Signals) {
		class = classSpoof
	}
	_, already := g.active[p]
	if !human && !already {
		elapsed := now.Sub(g.refill).Minutes()
		for c := range g.tokens {
			g.tokens[c] = min(g.rate(c), g.tokens[c]+elapsed*g.rate(c))
		}
		g.refill = now
		total := int(float64(g.c.MaxActive) * max(1, g.factor))
		maxActive := total
		if class == classSpoof {
			maxActive = max(1, total/2)
		}
		switch {
		case len(g.active) >= total || g.activeOf(class) >= maxActive:
			out.BudgetExhausted = true
			g.Exhausted++
			downgrade(afp.ActionObserve, "max active actions reached")
			return out
		case g.tokens[class] < 1:
			out.BudgetExhausted = true
			g.Exhausted++
			downgrade(afp.ActionObserve, "per-minute action budget exhausted")
			return out
		}
		g.tokens[class]--
	}
	ttl, _ := afp.ParseTTL(v.TTL)
	g.active[p] = activeEntry{until: now.Add(ttl), class: class}
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
