package enforce

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

func fakeNFT() (*NFT, *[]string) {
	n := NewNFT("nft", "afw", 7, 1000, "5/second")
	var scripts []string
	n.Run = func(_ context.Context, s string) ([]byte, error) { scripts = append(scripts, s); return nil, nil }
	n.Query = func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }
	return n, &scripts
}

func TestRulesetShape(t *testing.T) {
	n, _ := fakeNFT()
	rs := n.Ruleset([]netip.Prefix{netip.MustParsePrefix("192.168.1.1/32"), netip.MustParsePrefix("2001:db8::1/128")}, false)
	for _, want := range []string{
		"delete table inet afw", "elements = { 192.168.1.1 }", "elements = { 2001:db8::1 }",
		"priority -300", "ct state new ip saddr @thr4", "log group 7", "ip saddr @repin4", "ip daddr @repout4",
		"flags interval,timeout",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	// Protected subjects are accepted before any drop rule.
	pre := rs[strings.Index(rs, "chain pre"):]
	if strings.Index(pre, "@protect4 accept") > strings.Index(pre, "@drop4") {
		t.Error("protected accept must come first")
	}
	shadow := n.Ruleset(nil, true)
	if strings.Contains(shadow, " drop\n") || !strings.Contains(shadow, "log group 7") {
		t.Errorf("shadow ruleset must observe and never drop:\n%s", shadow)
	}
}

func TestPlanResolvesOverlaps(t *testing.T) {
	n, scripts := fakeNFT()
	ctx := context.Background()
	host := netip.MustParsePrefix("45.9.20.7/32")
	net24 := netip.MustParsePrefix("45.9.20.0/24")
	_ = n.Apply(ctx, []Entry{{host, afp.ActionDrop, 10 * time.Minute}})
	_ = n.Apply(ctx, []Entry{{net24, afp.ActionDrop, time.Hour}})
	last := (*scripts)[len(*scripts)-1]
	if !strings.Contains(last, "delete element inet afw drop4 { 45.9.20.7 }") || !strings.Contains(last, "add element inet afw drop4 { 45.9.20.0/24 timeout 3600s }") {
		t.Fatalf("wider entry should replace narrower:\n%s", last)
	}
	before := len(*scripts)
	_ = n.Apply(ctx, []Entry{{host, afp.ActionDrop, time.Minute}})
	if len(*scripts) != before {
		t.Fatalf("covered entry should be skipped, got %q", (*scripts)[len(*scripts)-1])
	}
	_ = n.Apply(ctx, []Entry{{net24, afp.ActionDrop, 2 * time.Hour}})
	last = (*scripts)[len(*scripts)-1]
	if !strings.Contains(last, "delete element") || !strings.Contains(last, "timeout 7200s") {
		t.Fatalf("refresh should delete then re-add:\n%s", last)
	}
	_ = n.Apply(ctx, []Entry{{netip.MustParsePrefix("2a0e:1:0:7::/64"), afp.ActionThrottle, time.Minute}})
	if !strings.Contains((*scripts)[len(*scripts)-1], "thr6 { 2a0e:1:0:7::/64 timeout 60s }") {
		t.Fatal("v6 throttle")
	}
}

func TestReputationScriptIsAtomicAndCollapsed(t *testing.T) {
	n, scripts := fakeNFT()
	_ = n.ReplaceReputation(context.Background(), Reputation{
		DropIn: []netip.Prefix{netip.MustParsePrefix("45.9.20.0/24"), netip.MustParsePrefix("45.9.20.7/32")},
	})
	s := (*scripts)[0]
	if strings.Count(s, "flush set") != 6 || strings.Contains(s, "45.9.20.7") {
		t.Fatalf("script:\n%s", s)
	}
}
