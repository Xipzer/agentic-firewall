//go:build lab && linux

// Lab tests run against a real kernel inside a throwaway network namespace:
//
//	lab/run.sh
//
// They need CAP_NET_ADMIN in the namespace (unshare -rn gives it without
// sudo) and AFW_NFT pointing at an nft binary.
package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/sensor"
)

const (
	target    = "10.99.0.1"
	scanner   = "45.9.20.7"
	bruteSrc  = "103.77.1.9"
	protected = "1.1.1.1"
	bystander = "81.2.69.160"
)

func labSetup(t *testing.T) string {
	t.Helper()
	nft := os.Getenv("AFW_NFT")
	if nft == "" || os.Geteuid() != 0 {
		t.Skip("lab test: run lab/run.sh")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", target + "/32", "dev", "lo"},
		{"addr", "add", scanner + "/32", "dev", "lo"}, {"addr", "add", bruteSrc + "/32", "dev", "lo"},
		{"addr", "add", protected + "/32", "dev", "lo"}, {"addr", "add", bystander + "/32", "dev", "lo"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil && !strings.Contains(string(out), "File exists") && !strings.Contains(string(out), "already assigned") {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	return nft
}

func nftList(t *testing.T, nft, set string) string {
	out, _ := exec.Command(nft, "list", "set", "inet", "afw", set).CombinedOutput()
	return string(out)
}

func dial(src, dst string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, err := d.Dial("tcp", dst)
	if err == nil {
		c.Close()
	}
	return err
}

// listen accepts connections and closes them quickly, like a login prompt rejecting a guess.
func listen(t *testing.T, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(100 * time.Millisecond); c.Close() }()
		}
	}()
}

func eventually(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestLabEnforcerPrimitives(t *testing.T) {
	nft := labSetup(t)
	n := enforce.NewNFT(nft, "afw", 7, 1000, "5/second")
	ctx := context.Background()
	prot := []netip.Prefix{netip.MustParsePrefix(protected + "/32")}
	if err := n.Setup(ctx, prot, false); err != nil {
		t.Fatal(err)
	}
	defer n.Teardown(ctx)
	host := netip.MustParsePrefix(scanner + "/32")
	if err := n.Apply(ctx, []enforce.Entry{{Prefix: host, Action: afp.ActionDrop, TTL: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	if err := n.Apply(ctx, []enforce.Entry{{Prefix: netip.MustParsePrefix("45.9.20.0/24"), Action: afp.ActionDrop, TTL: time.Hour}}); err != nil {
		t.Fatalf("wider entry over narrower: %v", err)
	}
	if err := n.Apply(ctx, []enforce.Entry{{Prefix: netip.MustParsePrefix("45.9.20.0/24"), Action: afp.ActionDrop, TTL: 2 * time.Hour}}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if s := nftList(t, nft, "drop4"); !strings.Contains(s, "45.9.20.0/24") || strings.Contains(s, "45.9.20.7 ") {
		t.Fatalf("drop4:\n%s", s)
	}
	// Restart keeps live entries.
	if err := n.Setup(ctx, prot, false); err != nil {
		t.Fatal(err)
	}
	if s := nftList(t, nft, "drop4"); !strings.Contains(s, "45.9.20.0/24") {
		t.Fatalf("entries lost across restart:\n%s", s)
	}
	// Short entries expire in the kernel on their own.
	if err := n.Apply(ctx, []enforce.Entry{{Prefix: netip.MustParsePrefix("5.6.7.8/32"), Action: afp.ActionThrottle, TTL: time.Second}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	if s := nftList(t, nft, "thr4"); strings.Contains(s, "5.6.7.8") {
		t.Fatalf("entry did not expire:\n%s", s)
	}
	// Apply after a kernel-side expiry must resync, not fail.
	if err := n.Apply(ctx, []enforce.Entry{{Prefix: netip.MustParsePrefix("5.6.7.8/32"), Action: afp.ActionThrottle, TTL: time.Minute}}); err != nil {
		t.Fatalf("apply after expiry: %v", err)
	}
	if err := n.ReplaceReputation(ctx, enforce.Reputation{DropIn: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/24"), netip.MustParsePrefix("2a06:1280::/29")}}); err != nil {
		t.Fatal(err)
	}
	if err := n.Remove(ctx, []netip.Prefix{netip.MustParsePrefix("45.9.20.0/24")}); err != nil {
		t.Fatal(err)
	}
	if s := nftList(t, nft, "drop4"); strings.Contains(s, "45.9.20") {
		t.Fatalf("remove failed:\n%s", s)
	}
	st, err := n.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st["drop_verdict_packets"]; !ok {
		t.Fatalf("stats: %v", st)
	}
}

type labDaemon struct {
	d       *Daemon
	cancel  func()
	journal string
	done    chan error
}

func startLab(t *testing.T, nft, mode string) *labDaemon {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Node, cfg.Mode, cfg.Probation = "lab", mode, 0
	f := false
	cfg.AutoProtect = &f
	cfg.Protected = []string{protected}
	cfg.StateDir = dir
	cfg.ControlSocket = filepath.Join(dir, "afw.sock")
	cfg.Log.Path = filepath.Join(dir, "afw.jsonl")
	cfg.NFT.Binary = nft
	cfg.NFT.OnExit = "teardown"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	d := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.discover = func() config.Discovered {
		return config.Discovered{Self: []netip.Prefix{netip.MustParsePrefix(target + "/32")}}
	}
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var c sensor.Counters
	go func() { _ = sensor.RunNFLOG(ctx, cfg.NFT.LogGroup, d.Events, &c) }()
	go func() { _ = sensor.RunConntrack(ctx, d.Events, &c) }()
	go func() { _ = d.ServeControl(ctx, cfg.ControlSocket, cancel) }()
	ld := &labDaemon{d: d, cancel: cancel, journal: cfg.Log.Path, done: make(chan error, 1)}
	go func() { ld.done <- d.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)
	t.Cleanup(func() {
		cancel()
		<-ld.done
		if t.Failed() {
			b, _ := os.ReadFile(ld.journal)
			t.Logf("journal:\n%s\nsensors: nflog=%d conntrack=%d overflow=%d", b, c.Packets.Load(), c.Conntrack.Load(), c.Overflow.Load())
		}
	})
	return ld
}

func (l *labDaemon) verdicts(t *testing.T) []afp.Verdict {
	l.d.Journal.Flush()
	f, err := os.Open(l.journal)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []afp.Verdict
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		var v afp.Verdict
		if json.Unmarshal(s.Bytes(), &v) == nil && v.Type == afp.TypeVerdict {
			out = append(out, v)
		}
	}
	return out
}

func (l *labDaemon) has(t *testing.T, subject string, a afp.Action) bool {
	for _, v := range l.verdicts(t) {
		if v.Subject.Value == subject && v.Action == a {
			return true
		}
	}
	return false
}

func scan(src string, ports int) {
	for p := 0; p < ports; p++ {
		_ = dial(src, fmt.Sprintf("%s:%d", target, 20000+p), 200*time.Millisecond)
	}
}

func brute(src string, n int) {
	for i := 0; i < n; i++ {
		_ = dial(src, target+":22", 300*time.Millisecond)
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLabEndToEnd(t *testing.T) {
	nft := labSetup(t)
	listen(t, target+":22")
	l := startLab(t, nft, "enforce")

	if err := dial(bruteSrc, target+":22", time.Second); err != nil {
		t.Fatalf("baseline connection failed: %v", err)
	}

	// 1. A SYN scan is spoofable evidence: throttled, never dropped.
	scan(scanner, 120)
	eventually(t, "scanner throttled in the kernel", 5*time.Second, func() bool { return strings.Contains(nftList(t, nft, "thr4"), scanner) })
	if strings.Contains(nftList(t, nft, "drop4"), scanner) {
		t.Fatal("scanner was dropped on spoofable evidence")
	}

	// 2. Brute force completes handshakes: dropped, and the kernel enforces it.
	brute(bruteSrc, 30)
	eventually(t, "brute-forcer dropped", 8*time.Second, func() bool { return strings.Contains(nftList(t, nft, "drop4"), bruteSrc) })
	if err := dial(bruteSrc, target+":22", 700*time.Millisecond); err == nil {
		t.Fatal("dropped source still connects")
	}
	if err := dial(bystander, target+":22", time.Second); err != nil {
		t.Fatalf("bystander collateral: %v", err)
	}
	// A blocked subject can no longer start connections to us, but anything
	// we start towards it still works: a block can never cut us off.
	listen(t, bruteSrc+":8443")
	if err := dial(target, bruteSrc+":8443", time.Second); err != nil {
		t.Fatalf("our outbound connection to a dropped subject failed: %v", err)
	}

	// 3. A protected subject behaving badly is only observed.
	brute(protected, 30)
	time.Sleep(2 * time.Second)
	if s := nftList(t, nft, "drop4") + nftList(t, nft, "thr4"); strings.Contains(s, protected) {
		t.Fatal("protected subject was blocked")
	}
	if !l.has(t, protected, afp.ActionObserve) {
		t.Fatal("protected subject's verdict was not journalled as observe")
	}

	// 4. Operator unblock lifts the drop and it stays lifted under the same evidence.
	if _, err := l.d.Unblock(context.Background(), bruteSrc, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := dial(bruteSrc, target+":22", time.Second); err != nil {
		t.Fatalf("unblocked source cannot connect: %v", err)
	}
	brute(bruteSrc, 30)
	time.Sleep(2 * time.Second)
	if strings.Contains(nftList(t, nft, "drop4"), bruteSrc) {
		t.Fatal("re-blocked during grace")
	}

	// 5. Every journal line is a valid AFP message.
	l.d.Journal.Flush()
	b, _ := os.ReadFile(l.journal)
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var env afp.Envelope
		if json.Unmarshal([]byte(line), &env) == nil && env.Type == "event" {
			continue
		}
		if _, err := afp.Decode([]byte(line)); err != nil {
			t.Errorf("journal line %d invalid: %v\n%s", i+1, err, line)
		}
	}

	// 6. Panic removes everything.
	if err := l.d.Panic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command(nft, "list", "tables").CombinedOutput(); strings.Contains(string(out), "afw") {
		t.Fatalf("table still present after panic: %s", out)
	}
}

func TestLabShadowNeverBlocks(t *testing.T) {
	nft := labSetup(t)
	listen(t, target+":22")
	l := startLab(t, nft, "shadow")
	brute(bruteSrc, 30)
	eventually(t, "shadow verdict journalled", 8*time.Second, func() bool { return l.has(t, bruteSrc, afp.ActionDrop) })
	if err := dial(bruteSrc, target+":22", time.Second); err != nil {
		t.Fatalf("shadow mode blocked traffic: %v", err)
	}
	out, _ := exec.Command(nft, "list", "table", "inet", "afw").CombinedOutput()
	if regexp.MustCompile(`(?m) drop$`).Match(out) {
		t.Fatalf("shadow ruleset contains drop rules:\n%s", out)
	}
}

func TestLabProbationDisarms(t *testing.T) {
	nft := labSetup(t)
	listen(t, target+":22")
	l := startLab(t, nft, "enforce")
	l.d.mu.Lock()
	l.d.probation = time.Now().Add(6 * time.Second)
	l.d.mu.Unlock()
	brute(bruteSrc, 30)
	eventually(t, "dropped while armed", 8*time.Second, func() bool { return strings.Contains(nftList(t, nft, "drop4"), bruteSrc) })
	eventually(t, "probation disarmed enforcement", 12*time.Second, func() bool { return l.d.Guard.Mode() == "shadow" })
	if err := dial(bruteSrc, target+":22", time.Second); err != nil {
		t.Fatalf("still blocked after disarm: %v", err)
	}
}

// A Pi must load the full default feed set (about 28k entries) in one go.
func TestLabLargeReputationLoad(t *testing.T) {
	nft := labSetup(t)
	n := enforce.NewNFT(nft, "afw", 7, 1000, "5/second")
	ctx := context.Background()
	if err := n.Setup(ctx, nil, false); err != nil {
		t.Fatal(err)
	}
	defer n.Teardown(ctx)
	var thr, drop []netip.Prefix
	for i := 0; i < 28000; i++ {
		thr = append(thr, netip.PrefixFrom(netip.AddrFrom4([4]byte{45, byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	for i := 0; i < 1700; i++ {
		drop = append(drop, netip.PrefixFrom(netip.AddrFrom4([4]byte{91, byte(i >> 8), byte(i), 0}), 24))
	}
	start := time.Now()
	if err := n.ReplaceReputation(ctx, enforce.Reputation{DropIn: drop, DropOut: drop, ThrottleIn: thr}); err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded %d entries in %v", len(thr)+2*len(drop), time.Since(start))
	if err := n.ReplaceReputation(ctx, enforce.Reputation{DropIn: drop, DropOut: drop, ThrottleIn: thr}); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

// Under a flood from rotating sources there is nobody to block. Break-glass
// must keep trusted users and protected hosts fully served while the flood
// shares a small capped lane.
func TestLabBreakGlassKeepsTrustedUsersServed(t *testing.T) {
	nft := labSetup(t)
	if out, err := exec.Command("ip", "addr", "add", "45.10.0.0/16", "dev", "lo").CombinedOutput(); err != nil && !strings.Contains(string(out), "already") && !strings.Contains(string(out), "File exists") {
		t.Fatalf("%v %s", err, out)
	}
	listen(t, target+":22")
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Node, cfg.Mode, cfg.Probation = "lab", "enforce", 0
	f := false
	cfg.AutoProtect = &f
	cfg.Protected = []string{protected}
	cfg.StateDir, cfg.ControlSocket, cfg.Log.Path = dir, filepath.Join(dir, "s"), filepath.Join(dir, "afw.jsonl")
	cfg.NFT.Binary, cfg.NFT.OnExit = nft, "teardown"
	cfg.BreakGlass.MinRate, cfg.BreakGlass.AbsRate, cfg.BreakGlass.Surge = 20, 3000, 3
	cfg.BreakGlass.NewcomerRate, cfg.BreakGlass.PerSourceRate = 20, "1/second"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// A wrong trust file must not stop the daemon.
	_ = os.WriteFile(filepath.Join(dir, "trust.json"), []byte("{not json"), 0o600)
	d := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.discover = func() config.Discovered {
		return config.Discovered{Self: []netip.Prefix{netip.MustParsePrefix(target + "/32")}}
	}
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	day := time.Now().Unix()/86400 - 1
	d.Engine.LoadTrust(map[string]fast.TrustRecord{bystander + "/32": {Sessions: 9, Days: 4, LastDay: day, LastSeen: time.Now()}})
	ctx, cancel := context.WithCancel(context.Background())
	var c sensor.Counters
	go func() { _ = sensor.RunNFLOG(ctx, cfg.NFT.LogGroup, d.Events, &c) }()
	go func() { _ = sensor.RunConntrack(ctx, d.Events, &c) }()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()
	time.Sleep(300 * time.Millisecond)

	stop := make(chan struct{})
	var floodTried, floodOK atomic.Int64
	for w := 0; w < 16; w++ {
		go func(w int) {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				src := fmt.Sprintf("45.10.%d.%d", (w*37+i/250)%250+1, i%250+1)
				floodTried.Add(1)
				if dial(src, target+":9", 150*time.Millisecond) == nil {
					floodOK.Add(1)
				}
				_ = dial(src, target+":22", 150*time.Millisecond)
			}
		}(w)
	}
	defer close(stop)
	eventually(t, "break-glass", 15*time.Second, func() bool {
		var lvl string
		d.do(func() { lvl = d.Posture.Level().String() })
		return lvl == "breakglass"
	})
	eventually(t, "break-glass lane in the kernel", 5*time.Second, func() bool {
		out, _ := exec.Command(nft, "list", "chain", "inet", "afw", "breakglass").CombinedOutput()
		return strings.Contains(string(out), "@trusted4") && strings.Contains(string(out), "limit rate over 20/second")
	})
	if s := nftList(t, nft, "trusted4"); !strings.Contains(s, bystander) {
		t.Fatalf("trusted user not in the priority lane:\n%s", s)
	}
	ok := 0
	for i := 0; i < 10; i++ {
		if err := dial(bystander, target+":22", time.Second); err == nil {
			ok++
		} else {
			t.Logf("trusted dial: %v", err)
		}
	}
	if ok != 10 {
		cnt, _ := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
		t.Logf("conntrack entries %s flood tried %d ok %d", cnt, floodTried.Load(), floodOK.Load())
		t.Fatalf("trusted user served %d/10 during the flood", ok)
	}
	if err := dial(protected, target+":22", time.Second); err != nil {
		t.Fatalf("protected host refused during break-glass: %v", err)
	}
	// Our own outbound is never in the lane.
	listen(t, "45.10.200.200:8443")
	if err := dial(target, "45.10.200.200:8443", time.Second); err != nil {
		t.Fatalf("outbound broken during break-glass: %v", err)
	}
	d.Journal.Flush()
	if !l2has(t, cfg.Log.Path, `"class":"dos.flood"`) {
		t.Fatal("break-glass escalation not journalled")
	}
	t.Logf("flood connections that got through: %d of %d", floodOK.Load(), floodTried.Load())

	if lvl := d.SetBreakGlass(context.Background(), false); lvl == "breakglass" {
		t.Logf("auto mode re-armed break-glass while the flood continues (expected): %s", lvl)
	}
}

func l2has(t *testing.T, path, needle string) bool {
	b, _ := os.ReadFile(path)
	return strings.Contains(string(b), needle)
}
