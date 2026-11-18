package reputation

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xipzer/agentic-firewall/internal/config"
)

func strs(ps []netip.Prefix) string {
	var ss []string
	for _, p := range ps {
		ss = append(ss, p.String())
	}
	return strings.Join(ss, " ")
}

func TestParseFormats(t *testing.T) {
	cases := map[string]struct {
		in    string
		min   int
		want  string
		unpar int
	}{
		"spamhaus jsonl": {`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2a06:1280::/29","sblid":"SBL1"}
{"type":"metadata","timestamp":1731900000,"size":2}`, 0, "1.10.16.0/20 2a06:1280::/29", 0},
		"plain with comments": {"# Feodo\n; x\n45.9.20.7\n\n103.77.1.9 # note\nnot-an-ip\n", 0, "45.9.20.7/32 103.77.1.9/32", 1},
		"spamhaus legacy":     {"1.10.16.0/20 ; SBL256894\n", 0, "1.10.16.0/20", 0},
		"ipsum min score":     {"# IPsum\n45.9.20.7\t9\n45.9.20.8\t2\n45.9.20.9\t5\n", 5, "45.9.20.7/32 45.9.20.9/32", 0},
		"isc json array":      {`[{"ipv4":"162.142.125.10","type":"censys"},{"ipv4":"71.6.135.131","type":"shodan"}]`, 0, "162.142.125.10/32 71.6.135.131/32", 0},
		"mapped v6":           {"::ffff:45.9.20.7\n", 0, "45.9.20.7/32", 0},
	}
	for name, c := range cases {
		got, bad := Parse(strings.NewReader(c.in), c.min)
		if strs(got) != c.want || bad != c.unpar {
			t.Errorf("%s: got %q (bad %d), want %q (bad %d)", name, strs(got), bad, c.want, c.unpar)
		}
	}
}

// FireHOL level1 ships RFC1918 and CGNAT as "bogons". Loading it raw on a
// gateway would cut off the whole LAN.
func TestSanitizeStripsLANAndProtected(t *testing.T) {
	in, _ := Parse(strings.NewReader("0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n192.168.0.0/16\n224.0.0.0/3\n1.1.1.0/24\n45.9.20.0/24\n45.9.20.7\n5.0.0.0/6\nfe80::/10\n2a06:1280::/29\n"), 0)
	out, rej := Sanitize(in, []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}, 8, 16)
	if strs(out) != "45.9.20.0/24 2a06:1280::/29" {
		t.Fatalf("sanitized = %q", strs(out))
	}
	if rej.Reserved != 4 || rej.Protected != 1 || rej.TooWide != 3 {
		t.Errorf("rejects = %+v", rej)
	}
}

func writeFeed(t *testing.T, dir, name string, lines []string) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + p
}

func ips(n, off int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("45.%d.%d.1", (i+off)/250, (i+off)%250))
	}
	return out
}

func TestManagerGuardsAgainstPoisonedRefresh(t *testing.T) {
	dir := t.TempDir()
	url := writeFeed(t, dir, "feed.txt", ips(200, 0))
	f := config.Feed{Name: "bl", URL: url, Action: "drop", Direction: "in"}
	m := NewManager([]config.Feed{f}, dir, 8, 16, func() []netip.Prefix { return nil })
	if err := m.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if n := len(m.Lists().DropIn); n != 200 {
		t.Fatalf("drop-in %d", n)
	}
	if len(m.Lists().DropOut) != 0 {
		t.Fatal("inbound-only feed leaked into outbound set")
	}
	writeFeed(t, dir, "feed.txt", ips(200, 1000)) // 100% churn
	if err := m.Refresh(context.Background(), f); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("massive churn accepted: %v", err)
	}
	writeFeed(t, dir, "feed.txt", []string{"# empty today"})
	if err := m.Refresh(context.Background(), f); err == nil {
		t.Fatal("empty feed accepted")
	}
	if n := len(m.Lists().DropIn); n != 200 {
		t.Fatalf("last good copy lost: %d", n)
	}
	// The cache survives a restart.
	m2 := NewManager([]config.Feed{f}, dir, 8, 16, func() []netip.Prefix { return nil })
	m2.LoadCache()
	if n := len(m2.Lists().DropIn); n != 200 {
		t.Fatalf("cache restore: %d", n)
	}
}

func TestObserveAndBenignLookup(t *testing.T) {
	dir := t.TempDir()
	obs := config.Feed{Name: "tor", URL: writeFeed(t, dir, "tor.txt", []string{"185.220.101.4", "2a0b:f4c2::/32"}), Action: "observe", Weight: 0.25}
	ben := config.Feed{Name: "isc", URL: writeFeed(t, dir, "isc.txt", []string{"162.142.125.10"}), Action: "benign"}
	m := NewManager([]config.Feed{obs, ben}, dir, 8, 16, func() []netip.Prefix { return nil })
	for _, f := range []config.Feed{obs, ben} {
		if err := m.Refresh(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	if f, w, ok := m.Lookup(netip.MustParseAddr("185.220.101.4")); !ok || f != "tor" || w != 0.25 {
		t.Errorf("observe lookup: %v %v %v", f, w, ok)
	}
	if _, _, ok := m.Lookup(netip.MustParseAddr("2a0b:f4c2:1::9")); !ok {
		t.Error("v6 prefix lookup")
	}
	if _, _, ok := m.Lookup(netip.MustParseAddr("185.220.101.5")); ok {
		t.Error("false hit")
	}
	if !m.Benign(netip.MustParseAddr("162.142.125.10")) || m.Benign(netip.MustParseAddr("185.220.101.4")) {
		t.Error("benign lookup")
	}
	if m.Lists().Len() != 0 {
		t.Error("observe/benign feeds must not reach kernel sets")
	}
}

func TestHTTPOnly(t *testing.T) {
	f := config.Feed{Name: "x", URL: "http://example.com/list.txt", Action: "drop"}
	m := NewManager([]config.Feed{f}, t.TempDir(), 8, 16, func() []netip.Prefix { return nil })
	if err := m.Refresh(context.Background(), f); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http accepted: %v", err)
	}
}
