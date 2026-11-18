// Package posture decides when the defence breaks glass.
//
// Normal operation punishes individual sources on evidence about them. That
// fails against a flood of forged or rotating sources: there is no one to
// punish. Break-glass flips the strategy from "block the bad" to "serve the
// known good first": protected subjects and sources with earned trust keep
// full access, newcomers share a capped lane, and thresholds tighten.
//
// The trigger is harm to the service (pressure far above baseline together
// with failing handshakes or an exhausted action budget), not any single
// signal an attacker can fake cheaply. It holds for a minimum period, renews
// while the harm continues, and steps down on its own.
package posture

import (
	"fmt"
	"math"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/fast"
)

type Level int

const (
	Normal Level = iota
	Elevated
	BreakGlass
)

func (l Level) String() string { return [...]string{"normal", "elevated", "breakglass"}[l] }

type Config struct {
	Auto         bool
	MinRate      float64       // new inbound flows/s below which nothing is a surge
	Surge        float64       // multiple of baseline that counts as a surge
	AbsRate      float64       // above this, break glass regardless (what the box can absorb)
	FailRatio    float64       // share of inbound handshakes failing that counts as harm
	MinAttempts  uint32        // ignore fail ratio below this many attempts per minute
	Hold         time.Duration // minimum time in break-glass once entered
	ManualHold   time.Duration // how long a manual break-glass lasts
	BaselineTau  time.Duration // how slowly the baseline learns
	ElevatedCool time.Duration // quiet time before elevated returns to normal
	TableFill    float64       // connection-table fill that breaks glass on its own
}

func DefaultConfig() Config {
	return Config{Auto: true, MinRate: 100, Surge: 5, AbsRate: 2000, FailRatio: 0.6, MinAttempts: 50,
		Hold: 10 * time.Minute, ManualHold: time.Hour, BaselineTau: time.Hour, ElevatedCool: 2 * time.Minute, TableFill: 0.7}
}

type Controller struct {
	c           Config
	level       Level
	since       time.Time
	until       time.Time
	quietSince  time.Time
	manualUntil time.Time
	baseline    float64
	lastUpdate  time.Time
	lastDenied  uint64
	Reasons     []string
}

func New(c Config) *Controller { return &Controller{c: c} }

func (c *Controller) Level() Level      { return c.level }
func (c *Controller) Since() time.Time  { return c.since }
func (c *Controller) Until() time.Time  { return c.until }
func (c *Controller) Baseline() float64 { return c.baseline }

// Manual turns break-glass on for ManualHold, or off immediately.
func (c *Controller) Manual(on bool, now time.Time) {
	if on {
		c.manualUntil = now.Add(c.c.ManualHold)
		return
	}
	c.manualUntil = time.Time{}
	if c.level == BreakGlass {
		c.until = now
	}
}

// Update folds in the latest pressure reading. It returns true when the level changed.
func (c *Controller) Update(p fast.Pressure, denied uint64, now time.Time) bool {
	dt := now.Sub(c.lastUpdate)
	if c.lastUpdate.IsZero() || dt < 0 || dt > time.Minute {
		dt = time.Second
	}
	c.lastUpdate = now
	// Learn the baseline only in calm periods, slowly, and never above what
	// would make AbsRate unreachable: a slow ramp-up cannot teach afw that
	// an attack is normal.
	if c.level == Normal {
		alpha := math.Min(1, dt.Seconds()/c.c.BaselineTau.Seconds())
		c.baseline += alpha * (p.NewPerSec - c.baseline)
		c.baseline = math.Min(c.baseline, c.c.AbsRate/c.c.Surge)
	}
	budget := denied > c.lastDenied
	c.lastDenied = denied

	threshold := math.Max(c.baseline*c.c.Surge, c.c.MinRate)
	surge := p.NewPerSec > threshold
	overload := p.NewPerSec > c.c.AbsRate
	failing := p.Attempts >= c.c.MinAttempts && p.FailRatio >= c.c.FailRatio
	manual := now.Before(c.manualUntil)
	// A nearly full connection table refuses everyone, genuine users first.
	tableFull := p.ConntrackFill >= c.c.TableFill
	// While the lane is shedding a flood, the sensors see less of it; the
	// shed rate keeps the emergency alive instead of letting it flap.
	shedding := c.level == BreakGlass && p.ShedPerSec >= c.c.MinRate/4

	var reasons []string
	if surge {
		reasons = append(reasons, fmt.Sprintf("%.0f new inbound flows/s against a baseline of %.0f", p.NewPerSec, c.baseline))
	}
	if overload {
		reasons = append(reasons, fmt.Sprintf("above the absolute ceiling of %.0f/s", c.c.AbsRate))
	}
	if failing {
		reasons = append(reasons, fmt.Sprintf("%.0f%% of %d inbound handshakes failing", p.FailRatio*100, p.Attempts))
	}
	if budget {
		reasons = append(reasons, "action budget exhausted")
	}
	if tableFull {
		reasons = append(reasons, fmt.Sprintf("connection table %.0f%% full", p.ConntrackFill*100))
	}
	if shedding {
		reasons = append(reasons, fmt.Sprintf("still shedding %.0f attempts/s", p.ShedPerSec))
	}
	if manual {
		reasons = append(reasons, "operator break-glass")
	}

	want := Normal
	switch {
	case manual || (c.c.Auto && (overload || tableFull || shedding || (surge && (failing || budget)))):
		want = BreakGlass
	case surge || failing || budget:
		want = Elevated
	}
	prev := c.level
	switch {
	case want == BreakGlass:
		c.until = now.Add(c.c.Hold)
		c.level = BreakGlass
		c.quietSince = time.Time{}
	case c.level == BreakGlass && now.Before(c.until):
		// hold
	case want == Elevated:
		c.level = Elevated
		c.quietSince = time.Time{}
	case c.level == BreakGlass:
		c.level = Elevated // step down through elevated, never straight to normal
		c.quietSince = now
	case c.level == Elevated:
		if c.quietSince.IsZero() {
			c.quietSince = now
		}
		if now.Sub(c.quietSince) >= c.c.ElevatedCool {
			c.level = Normal
		}
	}
	if len(reasons) > 0 {
		c.Reasons = reasons
	}
	if c.level != prev {
		c.since = now
		return true
	}
	return false
}
