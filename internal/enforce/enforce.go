// Package enforce applies verdicts in the data plane. The reference backend
// is nftables; Memory is used by tests and replay.
package enforce

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

type Entry struct {
	Prefix netip.Prefix
	Action afp.Action // drop or throttle
	TTL    time.Duration
}

// Reputation holds the feed-derived kernel sets. They have no per-entry
// timeout; each refresh replaces them atomically.
type Reputation struct {
	DropIn, DropOut, ThrottleIn []netip.Prefix
}

// BreakGlassSpec describes the emergency lane. Protected, trusted and
// internal sources pass untouched; every other source may open at most
// PerSource new connections, and all of them together share NewcomerRate.
type BreakGlassSpec struct {
	Internal     []netip.Prefix
	PerSource    string
	NewcomerRate int
}

type Enforcer interface {
	// Setup installs the ruleset idempotently, keeping live timed entries.
	Setup(ctx context.Context, protected []netip.Prefix, observeOnly bool) error
	Apply(ctx context.Context, entries []Entry) error
	Remove(ctx context.Context, prefixes []netip.Prefix) error
	ReplaceReputation(ctx context.Context, r Reputation) error
	SetProtected(ctx context.Context, protected []netip.Prefix) error
	// SetTrusted replaces the earned-trust set (the break-glass priority lane).
	SetTrusted(ctx context.Context, trusted []netip.Prefix) error
	// BreakGlass turns the emergency lane on (spec != nil) or off (nil).
	BreakGlass(ctx context.Context, spec *BreakGlassSpec) error
	// Flush removes every verdict and reputation entry but keeps observing.
	Flush(ctx context.Context) error
	Teardown(ctx context.Context) error
	Stats(ctx context.Context) (map[string]uint64, error)
}

// Memory is an in-process enforcer for tests and replay.
type Memory struct {
	mu         sync.Mutex
	Now        func() time.Time
	Entries    map[netip.Prefix]Entry
	Expiry     map[netip.Prefix]time.Time
	Reputation Reputation
	Protected  []netip.Prefix
	Installed  bool
	Calls      int
	Trusted    []netip.Prefix
	Glass      *BreakGlassSpec
}

func (m *Memory) SetTrusted(_ context.Context, ps []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Trusted = ps
	return nil
}

func (m *Memory) BreakGlass(_ context.Context, spec *BreakGlassSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Glass = spec
	return nil
}

func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{Now: now, Entries: map[netip.Prefix]Entry{}, Expiry: map[netip.Prefix]time.Time{}}
}

func (m *Memory) Setup(_ context.Context, protected []netip.Prefix, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Installed, m.Protected = true, protected
	return nil
}

func (m *Memory) Apply(_ context.Context, es []Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls++
	for _, e := range es {
		m.Entries[e.Prefix] = e
		m.Expiry[e.Prefix] = m.Now().Add(e.TTL)
	}
	return nil
}

func (m *Memory) Remove(_ context.Context, ps []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range ps {
		delete(m.Entries, p)
		delete(m.Expiry, p)
	}
	return nil
}

func (m *Memory) ReplaceReputation(_ context.Context, r Reputation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Reputation = r
	return nil
}

func (m *Memory) SetProtected(_ context.Context, ps []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Protected = ps
	return nil
}

func (m *Memory) Flush(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.Entries)
	clear(m.Expiry)
	m.Reputation = Reputation{}
	return nil
}

func (m *Memory) Teardown(ctx context.Context) error {
	_ = m.Flush(ctx)
	m.mu.Lock()
	m.Installed = false
	m.mu.Unlock()
	return nil
}

func (m *Memory) Stats(context.Context) (map[string]uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	n := uint64(0)
	for p, t := range m.Expiry {
		if now.Before(t) {
			n++
		} else {
			delete(m.Entries, p)
			delete(m.Expiry, p)
		}
	}
	return map[string]uint64{"active_entries": n, "reputation_entries": uint64(len(m.Reputation.DropIn) + len(m.Reputation.DropOut) + len(m.Reputation.ThrottleIn))}, nil
}

// Active returns the live action for a prefix, if any.
func (m *Memory) Active(p netip.Prefix) (Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.Entries[p]
	if ok && m.Now().After(m.Expiry[p]) {
		return Entry{}, false
	}
	return e, ok
}
