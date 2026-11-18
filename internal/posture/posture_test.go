package posture

import (
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/fast"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func run(c *Controller, from time.Duration, secs int, p fast.Pressure, denied uint64) time.Duration {
	for i := 0; i < secs; i++ {
		c.Update(p, denied, t0.Add(from+time.Duration(i)*time.Second))
	}
	return from + time.Duration(secs)*time.Second
}

func calm() fast.Pressure { return fast.Pressure{NewPerSec: 10, Attempts: 600, FailRatio: 0.05} }

func TestSurgeAloneOnlyElevates(t *testing.T) {
	c := New(DefaultConfig())
	at := run(c, 0, 3600, calm(), 0)
	// A legitimate rush: lots of traffic, but handshakes complete.
	run(c, at, 30, fast.Pressure{NewPerSec: 600, Attempts: 30000, FailRatio: 0.1}, 0)
	if c.Level() != Elevated {
		t.Fatalf("legitimate surge should elevate, not break glass: %s", c.Level())
	}
}

func TestHarmfulFloodBreaksGlassThenStepsDown(t *testing.T) {
	c := New(DefaultConfig())
	at := run(c, 0, 600, calm(), 0)
	at = run(c, at, 5, fast.Pressure{NewPerSec: 800, Attempts: 40000, FailRatio: 0.9}, 0)
	if c.Level() != BreakGlass {
		t.Fatalf("SYN flood with failing handshakes should break glass: %s %v", c.Level(), c.Reasons)
	}
	// Holds for the minimum period even if the flood pauses.
	at = run(c, at, 300, calm(), 0)
	if c.Level() != BreakGlass {
		t.Fatal("dropped out of break-glass before the hold expired")
	}
	at = run(c, at, 360, calm(), 0)
	if c.Level() != Elevated {
		t.Fatalf("should step down through elevated: %s", c.Level())
	}
	run(c, at, 180, calm(), 0)
	if c.Level() != Normal {
		t.Fatalf("should return to normal: %s", c.Level())
	}
}

func TestAbsoluteCeiling(t *testing.T) {
	c := New(DefaultConfig())
	run(c, 0, 3, fast.Pressure{NewPerSec: 2500, Attempts: 10, FailRatio: 0}, 0)
	if c.Level() != BreakGlass {
		t.Fatal("above the absolute ceiling should break glass")
	}
}

func TestBudgetExhaustionCountsAsHarm(t *testing.T) {
	c := New(DefaultConfig())
	at := run(c, 0, 60, calm(), 0)
	run(c, at, 2, fast.Pressure{NewPerSec: 400, Attempts: 100, FailRatio: 0.2}, 7)
	if c.Level() != BreakGlass {
		t.Fatalf("surge plus refused actions should break glass: %s", c.Level())
	}
}

// An attacker ramping up slowly must not teach the baseline that a flood is normal.
func TestSlowRampCannotPoisonBaseline(t *testing.T) {
	c := New(DefaultConfig())
	at := time.Duration(0)
	rate := 10.0
	for h := 0; h < 48; h++ {
		at = run(c, at, 3600, fast.Pressure{NewPerSec: rate, Attempts: 600, FailRatio: 0.05}, 0)
		rate *= 1.3
	}
	if c.Baseline() > DefaultConfig().AbsRate/DefaultConfig().Surge {
		t.Fatalf("baseline %v exceeds the poisoning cap", c.Baseline())
	}
	run(c, at, 3, fast.Pressure{NewPerSec: 2500, Attempts: 100000, FailRatio: 0.9}, 0)
	if c.Level() != BreakGlass {
		t.Fatal("ceiling must still trigger after a slow ramp")
	}
}

func TestAutoOffStillHonoursManual(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auto = false
	c := New(cfg)
	run(c, 0, 5, fast.Pressure{NewPerSec: 5000, Attempts: 99999, FailRatio: 1}, 0)
	if c.Level() == BreakGlass {
		t.Fatal("auto disabled but broke glass")
	}
	c.Manual(true, t0.Add(10*time.Second))
	run(c, 10*time.Second, 1, calm(), 0)
	if c.Level() != BreakGlass {
		t.Fatal("manual break-glass ignored")
	}
	c.Manual(false, t0.Add(12*time.Second))
	run(c, 12*time.Second, 1, calm(), 0)
	if c.Level() == BreakGlass {
		t.Fatal("manual off ignored")
	}
}
