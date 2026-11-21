package graph

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRedactHidesTheNetworkMapOnly(t *testing.T) {
	hide := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("1.1.1.1/32")}
	key := []byte("k")
	in := strings.Join([]string{
		"# subject 103.77.1.9",
		"first 2026-11-18T03:00:00Z, last 2026-11-18T03:00:26Z, 26 messages",
		"assets: 192.168.1.2:22/tcp, [fd00::2]:443/tcp",
		"nodes: pi-gateway",
		"subjects: 192.168.1.50, 45.9.20.0/24, 192.168.1.0/24.",
		"03:00:26Z verdict ver_1a1eef5511 drop 10m conf=0.879: resolver 1.1.1.1 and access.bruteforce",
	}, "\n")
	out := Redact(in, hide, key)
	for _, leak := range []string{"192.168.1.", "fd00::2", "pi-gateway", "1.1.1.1"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"103.77.1.9", "45.9.20.0/24", "2026-11-18T03:00:26Z", ":22/tcp", "]:443/tcp", "ver_1a1eef5511", "conf=0.879", "access.bruteforce", "/24."} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q:\n%s", keep, out)
		}
	}
	// Stable under one key, different under another.
	tok := Token(netip.MustParseAddr("192.168.1.2"), key)
	if strings.Count(Redact("192.168.1.2 then 192.168.1.2:80", hide, key), tok) != 2 {
		t.Error("the same address must map to the same token")
	}
	if Token(netip.MustParseAddr("192.168.1.2"), []byte("other")) == tok {
		t.Error("tokens must depend on the key")
	}
}
