package coverage

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/fast"
)

var t0 = time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)

func ev(src string, port uint16, at time.Time) fast.Event {
	return fast.Event{Time: at, Kind: fast.KindNew, Proto: fast.ProtoTCP, Src: netip.MustParseAddrPort(src),
		Dst: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.2"), port)}
}

func TestSaturationRisesWithRepetitionAndDropsOnNovelty(t *testing.T) {
	l := New()
	asset := "192.168.1.2/443/tcp"
	// The same handful of client ranges, over and over: saturated.
	for i := 0; i < 500; i++ {
		l.Observe(ev(fmt.Sprintf("81.2.%d.10:4000", i%5), 443, t0.Add(time.Duration(i)*time.Second)), fast.DirInbound)
	}
	if n := l.Novelty(asset, t0.Add(500*time.Second)); n > 0.02 {
		t.Fatalf("routine traffic should be saturated, novelty %v", n)
	}
	// A wave from many new ranges.
	for i := 0; i < 200; i++ {
		l.Observe(ev(fmt.Sprintf("45.%d.%d.1:5000", i/200+10, i), 443, t0.Add(600*time.Second)), fast.DirInbound)
	}
	if n := l.Novelty(asset, t0.Add(600*time.Second)); n < 0.25 {
		t.Fatalf("new sources should lower saturation, novelty %v", n)
	}
	if !l.Classified(asset, "access.bruteforce", t0) || l.Classified(asset, "access.bruteforce", t0) {
		t.Fatal("a class is novel only the first time on an asset")
	}
	r := l.Report(t0.Add(600 * time.Second))
	if len(r.Assets) != 1 || r.Assets[0].SourceRanges != 205 {
		t.Fatalf("report: %+v", r.Assets)
	}
	if r.Exercised <= 0 || r.Exercised >= 1 {
		t.Fatalf("exercised share %v", r.Exercised)
	}
}

func TestLedgerIsBounded(t *testing.T) {
	l := New()
	for i := 0; i < 3000; i++ {
		l.Observe(ev("81.2.69.1:4000", uint16(1000+i), t0), fast.DirInbound)
	}
	if len(l.assets) > maxAssets {
		t.Fatalf("assets unbounded: %d", len(l.assets))
	}
}
