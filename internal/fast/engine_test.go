package fast

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

type fakeRep struct{ listed, benign map[netip.Addr]bool }

func (f fakeRep) Lookup(a netip.Addr) (string, float64, bool) {
	if f.listed[a] {
		return "test-feed", 0.3, true
	}
	return "", 0, false
}
func (f fakeRep) Benign(a netip.Addr) bool { return f.benign[a] }

func newEngine() *Engine {
	c := config.Default()
	return New(Params{H: c.Heuristics, P: c.Policy, Local: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")},
		Internal: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, SensitivePorts: c.SensitivePorts,
		ServicePorts: []uint16{443}, MaxSubjects: 1024, Rep: fakeRep{}})
}

// sim drives an engine on a simulated clock with a 250 ms tick, like the daemon.
type sim struct {
	e   *Engine
	now time.Time
	out []Decision
}

func (s *sim) at(d time.Duration) time.Time { return t0.Add(d) }

func (s *sim) advance(to time.Time) {
	for s.now.Before(to) {
		s.now = s.now.Add(250 * time.Millisecond)
		s.out = append(s.out, s.e.Tick(s.now)...)
	}
}

func (s *sim) ev(at time.Time, k Kind, src, dst string) {
	s.advance(at)
	s.e.Ingest(Event{Time: at, Kind: k, Proto: ProtoTCP, Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst)})
}

func (s *sim) last(subject string) (Decision, bool) {
	p := netip.MustParsePrefix(subject)
	for i := len(s.out) - 1; i >= 0; i-- {
		if s.out[i].Subject == p {
			return s.out[i], true
		}
	}
	return Decision{}, false
}

func newSim() *sim { return &sim{e: newEngine(), now: t0} }

func addrport(ip string, port int) string {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port)).String()
}

func TestSYNPortScanIsThrottledNotDropped(t *testing.T) {
	s := newSim()
	for i := 0; i < 200; i++ {
		s.ev(s.at(time.Duration(i)*20*time.Millisecond), KindNew, "45.9.20.7:40000", addrport("192.168.1.2", 1000+i))
	}
	s.advance(s.at(10 * time.Second))
	d, ok := s.last("45.9.20.7/32")
	if !ok {
		t.Fatal("no decision for scanner")
	}
	if d.Action != afp.ActionThrottle || !d.SpoofLimited || !d.Escalate {
		t.Fatalf("want spoof-limited throttle with escalation, got %+v", d)
	}
	if d.NonSpoofScore != 0 {
		t.Errorf("SYN-only evidence must carry no non-spoofable weight, got %v", d.NonSpoofScore)
	}
}

func TestSSHBruteForceIsDropped(t *testing.T) {
	s := newSim()
	src := "103.77.1.9"
	for i := 0; i < 30; i++ {
		at := s.at(time.Duration(i) * 1500 * time.Millisecond)
		sp := addrport(src, 50000+i)
		s.ev(at, KindNew, sp, "192.168.1.2:22")
		s.ev(at.Add(40*time.Millisecond), KindEstablished, sp, "192.168.1.2:22")
		s.ev(at.Add(1200*time.Millisecond), KindEnd, sp, "192.168.1.2:22")
	}
	s.advance(s.at(50 * time.Second))
	d, ok := s.last(src + "/32")
	if !ok || d.Action != afp.ActionDrop {
		t.Fatalf("want drop for brute force, got %+v (ok=%v)", d, ok)
	}
	if d.TTL != 10*time.Minute {
		t.Errorf("first offence ttl = %v", d.TTL)
	}
}

func TestNormalUsageStaysQuiet(t *testing.T) {
	s := newSim()
	// An internal laptop loading pages: 40 hosts over 10 s, all handshakes complete.
	for i := 0; i < 40; i++ {
		at := s.at(time.Duration(i) * 250 * time.Millisecond)
		sp := addrport("192.168.1.50", 40000+i)
		dst := addrport("151.101.1."+itoa(i+1), 443)
		s.ev(at, KindNew, sp, dst)
		s.ev(at.Add(30*time.Millisecond), KindEstablished, sp, dst)
	}
	// A visitor to a published HTTPS service: 20 quick connections.
	for i := 0; i < 20; i++ {
		at := s.at(time.Duration(i) * 200 * time.Millisecond)
		sp := addrport("81.2.69.160", 30000+i)
		s.ev(at, KindNew, sp, "192.168.1.2:443")
		s.ev(at.Add(20*time.Millisecond), KindEstablished, sp, "192.168.1.2:443")
	}
	s.advance(s.at(20 * time.Second))
	for _, d := range s.out {
		if d.Action != afp.ActionObserve {
			t.Errorf("benign traffic produced %s on %s: %s", d.Action, d.Subject, d.Reason)
		}
	}
}

func itoa(i int) string { return netip.AddrFrom4([4]byte{0, 0, 0, byte(i)}).String()[6:] }

func TestDistributedScanCaughtAtAggregate(t *testing.T) {
	s := newSim()
	// 16 hosts in one /24, each touching only 6 ports: below host thresholds.
	for h := 0; h < 16; h++ {
		for p := 0; p < 6; p++ {
			at := s.at(time.Duration(h*6+p) * 90 * time.Millisecond)
			s.ev(at, KindNew, addrport("80.82.77."+itoa(h+10), 40000), addrport("192.168.1.2", 2000+h*6+p))
		}
	}
	s.advance(s.at(12 * time.Second))
	if _, ok := s.last("80.82.77.10/32"); ok {
		if d, _ := s.last("80.82.77.10/32"); d.Action.Severity() > afp.ActionObserve.Severity() {
			t.Errorf("single member should not be acted on: %+v", d)
		}
	}
	d, ok := s.last("80.82.77.0/24")
	if !ok || d.Action.Severity() < afp.ActionThrottle.Severity() || !d.Aggregate {
		t.Fatalf("want aggregate throttle on /24, got %+v ok=%v", d, ok)
	}
}

func TestSlowScanCaughtOverLongWindow(t *testing.T) {
	s := newSim()
	for i := 0; i < 130; i++ {
		s.ev(s.at(time.Duration(i)*4*time.Second), KindNew, "193.32.162.5:51000", addrport("192.168.1.2", 3000+i))
	}
	s.advance(s.at(9 * time.Minute))
	d, ok := s.last("193.32.162.5/32")
	if !ok || d.Action.Severity() < afp.ActionThrottle.Severity() {
		t.Fatalf("slow scan missed: %+v ok=%v", d, ok)
	}
	found := false
	for _, sg := range d.Signals {
		found = found || sg.Name == "slow_scan"
	}
	if !found {
		t.Errorf("slow_scan signal missing: %+v", d.Signals)
	}
}

func TestRepeatOffenderTTLGrowsAndCaps(t *testing.T) {
	s := newSim()
	src := "103.77.1.9"
	var ttls []time.Duration
	for round := 0; round < 5; round++ {
		base := time.Duration(round) * 3 * time.Hour
		for i := 0; i < 30; i++ {
			at := s.at(base + time.Duration(i)*1500*time.Millisecond)
			sp := addrport(src, 50000+i)
			s.ev(at, KindNew, sp, "192.168.1.2:22")
			s.ev(at.Add(40*time.Millisecond), KindEstablished, sp, "192.168.1.2:22")
			s.ev(at.Add(time.Second), KindEnd, sp, "192.168.1.2:22")
		}
		s.advance(s.at(base + time.Minute))
		d, _ := s.last(src + "/32")
		ttls = append(ttls, d.TTL)
		s.e.Release(netip.MustParsePrefix(src+"/32"), false, 0, s.now) // simulate expiry between rounds
	}
	want := []time.Duration{10 * time.Minute, 40 * time.Minute, 160 * time.Minute, 640 * time.Minute, 24 * time.Hour}
	for i := range want {
		if ttls[i] != want[i] {
			t.Fatalf("ttl progression %v, want %v", ttls, want)
		}
	}
}

func TestUnblockGraceHolds(t *testing.T) {
	s := newSim()
	src := "103.77.1.9"
	brute := func(base time.Duration) {
		for i := 0; i < 30; i++ {
			at := s.at(base + time.Duration(i)*1500*time.Millisecond)
			sp := addrport(src, 50000+i)
			s.ev(at, KindNew, sp, "192.168.1.2:22")
			s.ev(at.Add(40*time.Millisecond), KindEstablished, sp, "192.168.1.2:22")
			s.ev(at.Add(time.Second), KindEnd, sp, "192.168.1.2:22")
		}
	}
	brute(0)
	s.advance(s.at(46 * time.Second))
	s.e.Release(netip.MustParsePrefix(src+"/32"), false, time.Hour, s.now)
	n := len(s.out)
	brute(time.Minute)
	s.advance(s.at(2 * time.Minute))
	if len(s.out) != n {
		t.Fatalf("subject in grace was re-decided: %+v", s.out[n:])
	}
}

func TestPeerEvidenceSpoofabilityPropagates(t *testing.T) {
	s := newSim()
	p := netip.MustParsePrefix("185.220.101.4/32")
	s.e.AddPeer(p, "gw", 0.9*0.95, true, time.Hour, "peer throttle", s.now)
	s.advance(s.at(time.Second))
	d, _ := s.last(p.String())
	if d.Action != afp.ActionThrottle || !d.PeerDerived {
		t.Fatalf("spoofable peer evidence must cap at throttle, got %+v", d)
	}
	q := netip.MustParsePrefix("185.220.101.5/32")
	s.e.AddPeer(q, "gw", 0.9*0.95, false, time.Hour, "peer drop", s.now)
	s.advance(s.at(2 * time.Second))
	d, _ = s.last(q.String())
	if d.Action != afp.ActionDrop || !d.PeerDerived {
		t.Fatalf("trusted non-spoofable peer drop should drop, got %+v", d)
	}
	if !s.e.Release(q, true, 0, s.now) {
		t.Error("peer-only release should lift a peer-derived action")
	}
}

func TestBoundedMemory(t *testing.T) {
	s := newSim()
	for i := 0; i < 5000; i++ {
		ip := netip.AddrFrom4([4]byte{45, byte(i >> 8), byte(i), 1})
		s.e.Ingest(Event{Time: s.now, Kind: KindNew, Proto: ProtoTCP, Src: netip.AddrPortFrom(ip, 1), Dst: netip.MustParseAddrPort("192.168.1.2:80")})
	}
	if len(s.e.subjects) > 1024 {
		t.Fatalf("subjects unbounded: %d", len(s.e.subjects))
	}
	if s.e.Stats.Evicted == 0 {
		t.Error("expected evictions")
	}
}

func TestSelfTrafficIgnored(t *testing.T) {
	s := newSim()
	for i := 0; i < 300; i++ {
		s.ev(s.at(time.Duration(i)*10*time.Millisecond), KindNew, "192.168.1.2:40000", addrport("8.8.8.8", 1000+i))
	}
	s.advance(s.at(5 * time.Second))
	if len(s.out) != 0 {
		t.Fatalf("own traffic produced decisions: %+v", s.out)
	}
}

func TestIPv6RotationWithinSlash64(t *testing.T) {
	s := newSim()
	for i := 0; i < 150; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x2a, 0x0e, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)}), 40000)
		at := s.at(time.Duration(i) * 30 * time.Millisecond)
		s.advance(at)
		s.e.Ingest(Event{Time: at, Kind: KindNew, Proto: ProtoTCP, Src: src, Dst: netip.MustParseAddrPort("[2001:db8::2]:" + itoa(i%250+1))})
	}
	s.advance(s.at(8 * time.Second))
	d, ok := s.last("2a0e:1:0:7::/64")
	if !ok || d.Action.Severity() < afp.ActionThrottle.Severity() {
		t.Fatalf("rotating v6 scanner not grouped by /64: %+v ok=%v", d, ok)
	}
}

// longSession records a real, completed session from src lasting a minute.
func (s *sim) longSession(at time.Time, src string, port int) {
	sp := addrport(src, port)
	s.ev(at, KindNew, sp, "192.168.1.2:443")
	s.ev(at.Add(50*time.Millisecond), KindEstablished, sp, "192.168.1.2:443")
	s.ev(at.Add(time.Minute), KindEnd, sp, "192.168.1.2:443")
}

func TestIncumbentCannotBeFramedBySpoofing(t *testing.T) {
	s := newSim()
	phone := "82.132.1.50"
	// Three real sessions over two days earn trust. One day is not enough.
	s.longSession(s.at(0), phone, 40001)
	s.longSession(s.at(2*time.Hour), phone, 40002)
	s.longSession(s.at(4*time.Hour), phone, 40003)
	if s.e.Incumbent(netip.MustParsePrefix(phone+"/32"), s.now) {
		t.Fatal("trust earned in a single day")
	}
	s.longSession(s.at(26*time.Hour), phone, 40004)
	if !s.e.Incumbent(netip.MustParsePrefix(phone+"/32"), s.now) {
		t.Fatal("trust not earned after sessions on two days")
	}
	// Attacker spoofs a SYN scan "from" the phone.
	base := s.at(27 * time.Hour)
	for i := 0; i < 300; i++ {
		s.ev(base.Add(time.Duration(i)*10*time.Millisecond), KindNew, addrport(phone, 50000), addrport("192.168.1.2", 1000+i))
	}
	s.advance(base.Add(10 * time.Second))
	for _, d := range s.out {
		if d.Subject.Addr().String() == phone && d.Action != afp.ActionObserve {
			t.Fatalf("spoofed evidence acted on an incumbent: %+v", d)
		}
	}
	// Real brute force from the same address is still stopped.
	base = s.at(28 * time.Hour)
	for i := 0; i < 40; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		sp := addrport(phone, 51000+i)
		s.ev(at, KindNew, sp, "192.168.1.2:22")
		s.ev(at.Add(40*time.Millisecond), KindEstablished, sp, "192.168.1.2:22")
		s.ev(at.Add(time.Second), KindEnd, sp, "192.168.1.2:22")
	}
	s.advance(base.Add(45 * time.Second))
	d, _ := s.last(phone + "/32")
	if d.Action != afp.ActionDrop || !d.Incumbent || !d.Escalate {
		t.Fatalf("proven abuse from an incumbent should drop and escalate: %+v", d)
	}
}

func TestSpoofedEvidenceNeverLengthensPunishment(t *testing.T) {
	s := newSim()
	victim := "8.8.4.4"
	for round := 0; round < 4; round++ {
		base := time.Duration(round) * time.Hour
		for i := 0; i < 200; i++ {
			s.ev(s.at(base+time.Duration(i)*20*time.Millisecond), KindNew, addrport(victim, 53), addrport("192.168.1.2", 1000+i))
		}
		s.advance(s.at(base + 15*time.Second))
		d, _ := s.last(victim + "/32")
		if d.Action != afp.ActionThrottle || d.TTL != 10*time.Minute {
			t.Fatalf("round %d: spoofable evidence gave %s for %v", round, d.Action, d.TTL)
		}
	}
}

func TestClassification(t *testing.T) {
	cases := map[string]Decision{
		"access.bruteforce":               {Signals: []afp.Signal{{Name: "short_sessions", Weight: 0.9}}},
		"recon.scan.vertical":             {Signals: []afp.Signal{{Name: "conn_rate", Weight: 0.8}, {Name: "port_fanout", Weight: 0.7}}},
		"dos.syn-flood":                   {Signals: []afp.Signal{{Name: "handshake_fail", Weight: 0.8}, {Name: "conn_rate", Weight: 0.7}}},
		"recon.scan.slow":                 {Signals: []afp.Signal{{Name: "slow_scan", Weight: 0.6}}},
		"lateral.scan.horizontal":         {Signals: []afp.Signal{{Name: "host_fanout", Weight: 0.6}}, Internal: true},
		"recon.scan.vertical.distributed": {Signals: []afp.Signal{{Name: "port_fanout", Weight: 0.7}}, Aggregate: true},
		"peer.reported":                   {Signals: []afp.Signal{{Name: "peer:gw", Weight: 0.7}}},
		"infra.known-bad":                 {Signals: []afp.Signal{{Name: "reputation", Weight: 0.3}}},
	}
	for want, d := range cases {
		if got := Classify(d); got != want {
			t.Errorf("Classify = %q, want %q", got, want)
		}
	}
}
