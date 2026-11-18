package guard

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func g(perMin, maxActive int) *Guard {
	return New(Config{
		Protected:   []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("192.168.1.1/32")},
		Internal:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		InternalMax: afp.ActionObserve, MinPrefix4: 16, MinPrefix6: 32,
		MaxTTL:    map[afp.Tier]time.Duration{afp.TierFast: 24 * time.Hour, afp.TierPeer: time.Hour},
		PerMinute: perMin, MaxActive: maxActive, Mode: "enforce",
	})
}

func verdict(tier afp.Tier, kind afp.SubjectKind, subj string, a afp.Action, ttl string, spoof ...bool) *afp.Verdict {
	v := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, afp.Source{Tier: tier, Agent: "t"}),
		Subject: afp.Subject{Kind: kind, Value: subj}, Action: a, Confidence: 0.9, TTL: ttl, Reason: "test"}
	for _, s := range spoof {
		v.Signals = append(v.Signals, afp.Signal{Name: "x", Weight: 0.9, Spoofable: s})
	}
	return v
}

func TestRails(t *testing.T) {
	cases := []struct {
		name    string
		v       *afp.Verdict
		want    afp.Action
		enforce bool
		note    string
	}{
		{"plain drop", verdict(afp.TierFast, afp.SubjectHost, "45.9.20.7", afp.ActionDrop, "10m", false), afp.ActionDrop, true, ""},
		{"protected resolver", verdict(afp.TierFast, afp.SubjectHost, "1.1.1.1", afp.ActionDrop, "10m", false), afp.ActionObserve, false, "protected"},
		{"prefix covering protected", verdict(afp.TierFast, afp.SubjectPrefix, "1.1.0.0/16", afp.ActionThrottle, "10m", false), afp.ActionObserve, false, "protected"},
		{"too wide", verdict(afp.TierFast, afp.SubjectPrefix, "45.0.0.0/8", afp.ActionDrop, "10m", false), afp.ActionObserve, false, "wider"},
		{"internal host", verdict(afp.TierFast, afp.SubjectHost, "192.168.1.50", afp.ActionDrop, "10m", false), afp.ActionObserve, false, "internal"},
		{"spoofable only", verdict(afp.TierFast, afp.SubjectHost, "45.9.20.8", afp.ActionDrop, "10m", true, true), afp.ActionThrottle, true, "spoofable"},
		{"reroute unsupported", verdict(afp.TierSlow, afp.SubjectHost, "45.9.20.9", afp.ActionReroute, "10m"), afp.ActionObserve, false, "not available"},
		{"invalid ttl", verdict(afp.TierFast, afp.SubjectHost, "45.9.20.10", afp.ActionDrop, ""), afp.ActionObserve, false, "invalid"},
		{"mapped v4 protected", verdict(afp.TierFast, afp.SubjectHost, "::ffff:1.1.1.1", afp.ActionDrop, "10m", false), afp.ActionObserve, false, "protected"},
	}
	for _, c := range cases {
		gd := g(100, 100)
		out := gd.Check(c.v, now)
		if out.Verdict.Action != c.want || out.Enforce != c.enforce {
			t.Errorf("%s: got %s enforce=%v notes=%v", c.name, out.Verdict.Action, out.Enforce, out.Notes)
		}
		if c.note != "" && !strings.Contains(strings.Join(out.Notes, " "), c.note) {
			t.Errorf("%s: notes %v lack %q", c.name, out.Notes, c.note)
		}
	}
}

func TestTTLClampByTier(t *testing.T) {
	gd := g(100, 100)
	out := gd.Check(verdict(afp.TierPeer, afp.SubjectHost, "45.9.20.7", afp.ActionThrottle, "7d", false), now)
	if out.Verdict.TTL != "1h" {
		t.Fatalf("peer ttl not clamped: %s", out.Verdict.TTL)
	}
	out = gd.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.20.8", afp.ActionThrottle, "1s", false), now)
	if out.Verdict.TTL != "30s" {
		t.Fatalf("min ttl: %s", out.Verdict.TTL)
	}
}

func TestBudget(t *testing.T) {
	gd := g(3, 100)
	ips := []string{"45.9.20.1", "45.9.20.2", "45.9.20.3", "45.9.20.4"}
	var got []afp.Action
	for _, ip := range ips {
		got = append(got, gd.Check(verdict(afp.TierFast, afp.SubjectHost, ip, afp.ActionDrop, "10m", false), now).Verdict.Action)
	}
	if got[2] != afp.ActionDrop || got[3] != afp.ActionObserve || gd.Exhausted != 1 {
		t.Fatalf("budget not enforced: %v exhausted=%d", got, gd.Exhausted)
	}
	// Upgrading an already-active subject costs nothing.
	if a := gd.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.20.1", afp.ActionDrop, "20m", false), now).Verdict.Action; a != afp.ActionDrop {
		t.Fatalf("renewal charged against budget: %s", a)
	}
	// Tokens refill over time.
	if a := gd.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.20.9", afp.ActionDrop, "10m", false), now.Add(time.Minute)).Verdict.Action; a != afp.ActionDrop {
		t.Fatalf("budget did not refill: %s", a)
	}
	// Humans are not budgeted.
	gd2 := g(1, 100)
	for _, ip := range ips {
		if a := gd2.Check(verdict(afp.TierHuman, afp.SubjectHost, ip, afp.ActionDrop, "10m"), now).Verdict.Action; a != afp.ActionDrop {
			t.Fatalf("human action budgeted: %s", a)
		}
	}
}

func TestMaxActive(t *testing.T) {
	gd := g(100, 2)
	for i, ip := range []string{"45.9.20.1", "45.9.20.2", "45.9.20.3"} {
		out := gd.Check(verdict(afp.TierFast, afp.SubjectHost, ip, afp.ActionThrottle, "10m", false), now)
		if (i < 2) != (out.Verdict.Action == afp.ActionThrottle) {
			t.Fatalf("max active: %d -> %s", i, out.Verdict.Action)
		}
	}
	// Expiry frees capacity.
	out := gd.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.20.4", afp.ActionThrottle, "10m", false), now.Add(11*time.Minute))
	if out.Verdict.Action != afp.ActionThrottle {
		t.Fatal("expired actions still count")
	}
}

func TestShadowNeverEnforces(t *testing.T) {
	gd := g(100, 100)
	gd.SetMode("shadow")
	out := gd.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.20.7", afp.ActionDrop, "10m", false), now)
	if out.Enforce || out.Verdict.Mode != "shadow" || out.Verdict.Action != afp.ActionDrop {
		t.Fatalf("shadow: %+v", out)
	}
}

func TestSpoofableActionsCannotDrainProvenBudget(t *testing.T) {
	gd := g(4, 100)
	for i := 0; i < 10; i++ {
		gd.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.20."+string(rune('0'+i)), afp.ActionThrottle, "10m", true), now)
	}
	for i, ip := range []string{"103.77.1.1", "103.77.1.2", "103.77.1.3", "103.77.1.4"} {
		if a := gd.Check(verdict(afp.TierFast, afp.SubjectHost, ip, afp.ActionDrop, "10m", false), now).Verdict.Action; a != afp.ActionDrop {
			t.Fatalf("proven drop %d refused after a spoofed flood: %s", i, a)
		}
	}
	gd2 := g(100, 10)
	for i := 0; i < 10; i++ {
		gd2.Check(verdict(afp.TierFast, afp.SubjectHost, "45.9.21."+string(rune('0'+i)), afp.ActionThrottle, "10m", true), now)
	}
	if gd2.activeOf(classSpoof) != 5 {
		t.Fatalf("spoofable actions should be capped at half of max_active, got %d", gd2.activeOf(classSpoof))
	}
}
