package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/canary"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
	"github.com/Xipzer/agentic-firewall/internal/fast"
)

// RunDemo runs the whole daemon against simulated traffic, with an
// in-memory enforcer. It needs no root and touches no firewall, so the
// interface can be tried, or shown to someone, on any machine.
func RunDemo(ctx context.Context, listen string, log *slog.Logger, ready func(stateDir string)) error {
	dir, err := os.MkdirTemp("", "afw-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg := config.Default()
	cfg.Node, cfg.Mode = "demo", "enforce"
	off := false
	cfg.AutoProtect = &off
	cfg.Protected = []string{"192.168.1.1", "1.1.1.1"}
	cfg.StateDir, cfg.Log.Path, cfg.ControlSocket = dir, filepath.Join(dir, "afw.jsonl"), filepath.Join(dir, "afw.sock")
	cfg.UI.Listen = listen
	if err := cfg.Validate(); err != nil {
		return err
	}
	d := New(cfg, log)
	d.discover = func() config.Discovered {
		return config.Discovered{Self: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")}}
	}
	d.TableFill = func() float64 { return 0 }
	clock := time.Now().Add(-50 * time.Minute)
	d.Now = func() time.Time { return clock }
	mem := enforce.NewMemory(d.Now)
	d.Enforcer = mem
	if err := d.Init(); err != nil {
		return err
	}
	day := time.Now().Unix()/86400 - 1
	d.Engine.LoadTrust(map[string]fast.TrustRecord{"81.2.69.160/32": {Sessions: 12, Days: 5, LastDay: day, LastSeen: time.Now()},
		"82.132.1.50/32": {Sessions: 7, Days: 3, LastDay: day, LastSeen: time.Now()}})

	script := demoScript(clock, time.Now().Add(45*time.Minute))
	// Past: replay the first 50 minutes on a simulated clock so the interface opens with history.
	i := 0
	for now := time.Now(); clock.Before(now); {
		clock = clock.Add(250 * time.Millisecond)
		for ; i < len(script) && !script[i].t.After(clock); i++ {
			d.demoEvent(script[i])
		}
		for _, dec := range d.Engine.Tick(clock) {
			d.decide(dec, clock)
		}
		for drained := false; !drained; {
			select {
			case e := <-d.applyCh:
				_ = mem.Apply(ctx, []enforce.Entry{e})
			default:
				drained = true
			}
		}
	}
	// Present: real time from here on.
	d.Now, mem.Now = time.Now, time.Now
	go func() {
		for ; i < len(script); i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Until(script[i].t)):
			}
			ev := script[i]
			if ev.decoy {
				d.do(func() { d.demoEvent(ev) })
			} else {
				d.Events <- ev.ev
			}
		}
	}()
	if ready != nil {
		go func() {
			for n := 0; n < 100; n++ {
				if _, err := os.Stat(filepath.Join(dir, "ui-token")); err == nil {
					ready(dir)
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
	}
	return d.Run(ctx)
}

type demoEv struct {
	t     time.Time
	ev    fast.Event
	decoy bool
}

func (d *Daemon) demoEvent(e demoEv) {
	if e.decoy {
		d.onCanary(canary.Hit{Time: e.t, Src: e.ev.Src, Dst: e.ev.Dst})
		return
	}
	d.ingest(e.ev)
}

// demoScript is a fixed cast of visitors and attackers, placed on a timeline.
func demoScript(from, to time.Time) []demoEv {
	rng := rand.New(rand.NewPCG(7, 11))
	var out []demoEv
	const self = "192.168.1.2"
	flow := func(t time.Time, k fast.Kind, src string, sport int, dst string, dport int) {
		out = append(out, demoEv{t: t, ev: fast.Event{Time: t, Kind: k, Proto: fast.ProtoTCP,
			Src: netip.AddrPortFrom(netip.MustParseAddr(src), uint16(sport)), Dst: netip.AddrPortFrom(netip.MustParseAddr(dst), uint16(dport))}})
	}
	session := func(t time.Time, src string, sport, dport int, length time.Duration) {
		flow(t, fast.KindNew, src, sport, self, dport)
		flow(t.Add(40*time.Millisecond), fast.KindEstablished, src, sport, self, dport)
		flow(t.Add(length), fast.KindEnd, src, sport, self, dport)
	}
	brute := func(t time.Time, src string, port, n int) {
		for i := 0; i < n; i++ {
			session(t.Add(time.Duration(i)*time.Second), src, 50000+i, port, 900*time.Millisecond)
		}
	}
	scan := func(t time.Time, src string, ports int, gap time.Duration) {
		for i := 0; i < ports; i++ {
			flow(t.Add(time.Duration(i)*gap), fast.KindNew, src, 40000, self, 1000+i*7)
		}
	}
	decoy := func(t time.Time, src string, port int) {
		out = append(out, demoEv{t: t, decoy: true, ev: fast.Event{Time: t, Src: netip.MustParseAddrPort(src + ":41000"),
			Dst: netip.AddrPortFrom(netip.MustParseAddr(self), uint16(port))}})
	}
	// Ordinary visitors all the way through.
	for t := from; t.Before(to); t = t.Add(time.Duration(8+rng.IntN(10)) * time.Second) {
		who := []string{"81.2.69.160", "82.132.1.50", "86.14.3.77", "92.40.11.5", "2.25.160.9"}[rng.IntN(5)]
		session(t, who, 30000+rng.IntN(20000), 443, time.Duration(40+rng.IntN(120))*time.Second)
	}
	at := func(min float64) time.Time { return from.Add(time.Duration(min * float64(time.Minute))) }
	// The past 50 minutes.
	scan(at(3), "45.9.20.7", 160, 50*time.Millisecond)
	brute(at(6), "103.77.1.9", 22, 40)
	scan(at(12), "193.32.162.5", 140, 4*time.Second) // slow scan
	decoy(at(17), "80.82.77.33", 2323)
	for h := 0; h < 14; h++ { // one range working together
		scan(at(21).Add(time.Duration(h)*400*time.Millisecond), fmt.Sprintf("185.224.128.%d", 10+h), 6, 90*time.Millisecond)
	}
	brute(at(27), "141.98.11.20", 3389, 35)
	for i := 0; i < 40; i++ { // an inside device probing its neighbours
		t := at(33).Add(time.Duration(i) * 150 * time.Millisecond)
		out = append(out, demoEv{t: t, ev: fast.Event{Time: t, Kind: fast.KindNew, Proto: fast.ProtoTCP,
			Src: netip.MustParseAddrPort("192.168.1.77:44000"), Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, byte(100 + i)}), 445)}})
	}
	// A break-in chain that ends a few minutes before "now", so it is still restricted.
	scan(at(41), "194.26.135.84", 45, 60*time.Millisecond)
	brute(at(42), "194.26.135.84", 22, 32)
	decoy(at(43.2), "194.26.135.84", 6379)
	brute(at(45), "103.77.1.9", 22, 40) // the first attacker returns: a repeat offence
	scan(at(47.5), "62.210.14.3", 120, 40*time.Millisecond)
	decoy(at(48.6), "5.188.206.18", 5900)
	// The future: something new every half minute or so while the demo runs.
	for t, n := at(51), 0; t.Before(to); t, n = t.Add(time.Duration(20+rng.IntN(25))*time.Second), n+1 {
		src := fmt.Sprintf("%d.%d.%d.%d", []int{45, 91, 103, 141, 185, 193}[rng.IntN(6)], 10+rng.IntN(200), rng.IntN(250), 1+rng.IntN(250))
		switch n % 4 {
		case 0:
			scan(t, src, 100+rng.IntN(80), 40*time.Millisecond)
		case 1:
			brute(t, src, []int{22, 3389, 5432}[rng.IntN(3)], 34)
		case 2:
			decoy(t, src, []int{2323, 5900, 6379}[rng.IntN(3)])
		default:
			scan(t, src, 120, 3*time.Second)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].t.Before(out[j].t) })
	return out
}
