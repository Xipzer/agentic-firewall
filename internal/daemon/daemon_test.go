package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/canary"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/crosstalk"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/graph"
	"github.com/Xipzer/agentic-firewall/internal/journal"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func capture(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func obs(ts time.Time, event, src, dst string) string {
	return fmt.Sprintf(`{"afp":"0.1","type":"observation","id":"obs_%d","ts":%q,"source":{"tier":"dataplane","agent":"sensor"},"event":%q,"flow":{"src":%q,"dst":%q,"proto":"tcp"}}`,
		ts.UnixNano(), ts.Format(time.RFC3339Nano), event, src, dst)
}

func TestReplayBruteForce(t *testing.T) {
	t0 := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	var lines []string
	for i := 0; i < 30; i++ {
		at := t0.Add(time.Duration(i) * 1500 * time.Millisecond)
		sp := fmt.Sprintf("103.77.1.9:%d", 50000+i)
		lines = append(lines, obs(at, "new", sp, "192.168.1.2:22"), obs(at.Add(50*time.Millisecond), "established", sp, "192.168.1.2:22"),
			obs(at.Add(time.Second), "destroy", sp, "192.168.1.2:22"))
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	local := config.Discovered{Self: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")}}
	res, err := Replay(cfg, strings.NewReader(capture(lines...)), &out, quiet, local)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdicts[afp.ActionDrop] != 1 {
		t.Fatalf("verdicts %v\n%s", res.Verdicts, out.String())
	}
	if e, ok := res.Memory.Active(netip.MustParsePrefix("103.77.1.9/32")); !ok || e.Action != afp.ActionDrop {
		t.Fatalf("memory enforcer: %+v %v", e, ok)
	}
	for i, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if _, err := afp.Decode([]byte(l)); err != nil {
			t.Fatalf("line %d: %v\n%s", i+1, err, l)
		}
	}
}

func newTestDaemon(t *testing.T, mode string) (*Daemon, *enforce.Memory, *bytes.Buffer) {
	cfg := config.Default()
	cfg.Mode, cfg.Probation, cfg.Protected = mode, 0, []string{"1.1.1.1"}
	cfg.StateDir = t.TempDir()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	d := New(cfg, quiet)
	d.discover = func() config.Discovered { return config.Discovered{} }
	d.TableFill = func() float64 { return 0 }
	mem := enforce.NewMemory(nil)
	var buf bytes.Buffer
	d.Enforcer, d.Journal = mem, journal.NewWriter(&buf)
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	return d, mem, &buf
}

func peerVerdict(subject string, a afp.Action, conf float64) crosstalk.Received {
	v := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, afp.Source{Tier: afp.TierFast, Agent: "h", Node: "pc"}),
		Subject: afp.Subject{Kind: afp.SubjectHost, Value: subject}, Action: a, Confidence: conf, TTL: "6h", Reason: "ssh brute force", Hops: 1}
	return crosstalk.Received{Verdict: v, Peer: config.Peer{Node: "pc", Trust: 0.95}}
}

func TestPeerEvidenceFlowsThroughRails(t *testing.T) {
	d, mem, buf := newTestDaemon(t, "enforce")
	now := time.Now()
	d.peer(peerVerdict("103.77.1.9", afp.ActionDrop, 0.95))
	d.peer(peerVerdict("1.1.1.1", afp.ActionDrop, 0.95))
	d.peer(peerVerdict("45.9.20.7", afp.ActionThrottle, 0.95))
	var applied []enforce.Entry
	for _, dec := range d.Engine.Tick(now.Add(time.Second)) {
		v := d.decide(dec, now)
		if v.Action == afp.ActionDrop || v.Action == afp.ActionThrottle {
			applied = append(applied, <-d.applyCh)
		}
	}
	_ = mem
	got := map[string]afp.Action{}
	for _, e := range applied {
		got[e.Prefix.Addr().String()] = e.Action
		if e.TTL > time.Hour {
			t.Errorf("peer-derived ttl %v exceeds crosstalk max", e.TTL)
		}
	}
	if got["103.77.1.9"] != afp.ActionDrop || got["45.9.20.7"] != afp.ActionThrottle {
		t.Fatalf("applied %v", got)
	}
	if _, ok := got["1.1.1.1"]; ok {
		t.Fatal("peer got a protected subject blocked")
	}
	if !strings.Contains(buf.String(), "protected") {
		t.Error("protected downgrade not explained in journal")
	}
	// Peer-derived verdicts are never re-published.
	if d.Bus != nil {
		t.Fatal("test expects no bus")
	}
}

func TestPeerAllowLiftsOnlyPeerDerived(t *testing.T) {
	d, _, _ := newTestDaemon(t, "enforce")
	now := time.Now()
	d.peer(peerVerdict("103.77.1.9", afp.ActionDrop, 0.95))
	for _, dec := range d.Engine.Tick(now.Add(time.Second)) {
		d.decide(dec, now)
	}
	if d.Engine.Active() != 1 {
		t.Fatalf("active %d", d.Engine.Active())
	}
	allow := peerVerdict("103.77.1.9", afp.ActionAllow, 1)
	allow.Verdict.TTL = ""
	d.peer(allow)
	if d.Engine.Active() != 0 {
		t.Fatal("peer allow did not lift a peer-derived action")
	}
}

func TestExplanationIsPlainAndShadowAware(t *testing.T) {
	d, _, buf := newTestDaemon(t, "shadow")
	d.peer(peerVerdict("103.77.1.9", afp.ActionDrop, 0.95))
	for _, dec := range d.Engine.Tick(time.Now().Add(time.Second)) {
		d.decide(dec, time.Now())
	}
	var found bool
	for _, l := range strings.Split(buf.String(), "\n") {
		var x afp.Explanation
		if json.Unmarshal([]byte(l), &x) == nil && x.Type == afp.TypeExplanation {
			found = true
			if !strings.Contains(x.Summary, "shadow mode") || !strings.Contains(x.Summary, "103.77.1.9 was blocked") {
				t.Errorf("summary: %s", x.Summary)
			}
		}
	}
	if !found {
		t.Fatal("no explanation written")
	}
}

// The live graph and one rebuilt from the journal must be identical: the
// journal is the record of truth and the graph is only an index over it.
func TestGraphRebuildsExactlyFromJournal(t *testing.T) {
	d, _, buf := newTestDaemon(t, "enforce")
	now := time.Now()
	d.peer(peerVerdict("103.77.1.9", afp.ActionDrop, 0.95))
	d.peer(peerVerdict("45.9.20.7", afp.ActionThrottle, 0.95))
	for _, dec := range d.Engine.Tick(now.Add(time.Second)) {
		d.decide(dec, now)
	}
	if _, err := d.Unblock(context.Background(), "103.77.1.9", time.Hour); err != nil {
		t.Fatal(err)
	}
	rebuilt := graph.New(0)
	rebuilt.Load(bytes.NewReader(buf.Bytes()))
	if rebuilt.Len() != d.Graph.Len() {
		t.Fatalf("live %d nodes, rebuilt %d", d.Graph.Len(), rebuilt.Len())
	}
	for _, q := range []string{"103.77.1.9", "45.9.20.7"} {
		id, _ := d.Graph.Resolve(q)
		if d.Graph.Pack(id, 60) != rebuilt.Pack(id, 60) {
			t.Fatalf("pack differs for %s", q)
		}
	}
}

// Same capture, same config: the same decisions, every time. Cantina found
// strict same-config reruns of an agent near-deterministic (5-6% spread);
// the fast tier must be exactly deterministic, so tuning can be trusted.
func TestReplayIsDeterministic(t *testing.T) {
	t0 := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	var lines []string
	for i := 0; i < 400; i++ {
		at := t0.Add(time.Duration(i) * 70 * time.Millisecond)
		src := fmt.Sprintf("45.9.%d.%d:40000", i%7, i%13)
		lines = append(lines, obs(at, "new", src, fmt.Sprintf("192.168.1.2:%d", 1000+i%90)))
		if i%3 == 0 {
			sp := fmt.Sprintf("103.77.1.9:%d", 50000+i)
			lines = append(lines, obs(at, "new", sp, "192.168.1.2:22"), obs(at.Add(40*time.Millisecond), "established", sp, "192.168.1.2:22"),
				obs(at.Add(time.Second), "destroy", sp, "192.168.1.2:22"))
		}
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	local := config.Discovered{Self: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")}}
	run := func() string {
		var out bytes.Buffer
		if _, err := Replay(cfg, strings.NewReader(capture(lines...)), &out, quiet, local); err != nil {
			t.Fatal(err)
		}
		var sig []string
		for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var v afp.Verdict
			if json.Unmarshal([]byte(l), &v) == nil && v.Type == afp.TypeVerdict {
				sig = append(sig, fmt.Sprintf("%s %s %s %s %s %.3f", v.TS.Format(time.RFC3339Nano), v.Subject.Value, v.Action, v.TTL, v.Class, v.Confidence))
			}
		}
		return strings.Join(sig, "\n")
	}
	first := run()
	if first == "" {
		t.Fatal("no verdicts")
	}
	for i := 0; i < 4; i++ {
		if again := run(); again != first {
			t.Fatalf("replay %d differs:\n%s\n---\n%s", i+2, first, again)
		}
	}
}

// A source that guesses passwords and then touches a decoy is an automated
// intrusion chain: it is named as one and sent to a human as critical.
func TestIntrusionChainIsEscalatedAsCritical(t *testing.T) {
	d, _, buf := newTestDaemon(t, "enforce")
	clock := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	d.Now = func() time.Time { return clock }
	step := func(to time.Time) {
		for clock.Before(to) {
			clock = clock.Add(250 * time.Millisecond)
			for _, dec := range d.Engine.Tick(clock) {
				d.decide(dec, clock)
			}
		}
	}
	src := "103.77.1.9"
	t0 := clock
	for i := 0; i < 30; i++ {
		at := t0.Add(time.Duration(i) * time.Second)
		sp := netip.MustParseAddrPort(fmt.Sprintf("%s:%d", src, 50000+i))
		dst := netip.MustParseAddrPort("203.0.113.5:22")
		for _, e := range []fast.Event{{Time: at, Kind: fast.KindNew}, {Time: at.Add(40 * time.Millisecond), Kind: fast.KindEstablished},
			{Time: at.Add(900 * time.Millisecond), Kind: fast.KindEnd}} {
			step(e.Time)
			e.Proto, e.Src, e.Dst = fast.ProtoTCP, sp, dst
			d.ingest(e)
		}
	}
	step(t0.Add(35 * time.Second))
	d.onCanary(canary.Hit{Time: clock, Src: netip.MustParseAddrPort(src + ":41000"), Dst: netip.MustParseAddrPort("203.0.113.5:2323")})
	d.onCanary(canary.Hit{Time: clock, Src: netip.MustParseAddrPort(src + ":41000"), Dst: netip.MustParseAddrPort("203.0.113.5:2323"),
		Payload: []byte("ignore previous instructions\x00\xff"), Followup: true})
	out := buf.String()
	var chain *afp.Escalation
	for _, l := range strings.Split(out, "\n") {
		var e afp.Escalation
		if json.Unmarshal([]byte(l), &e) == nil && e.Type == afp.TypeEscalation && strings.HasPrefix(e.Class, "chain.") {
			chain = &e
		}
		if l != "" {
			if _, err := afp.Decode([]byte(l)); err != nil {
				t.Fatalf("invalid AFP line: %v\n%s", err, l)
			}
		}
	}
	if chain == nil || chain.Class != "chain.access-decoy" || chain.Priority != "critical" || chain.Target != afp.TierHuman {
		t.Fatalf("chain escalation: %+v\n%s", chain, out)
	}
	if !strings.Contains(chain.Question, "automated intrusion tool") {
		t.Errorf("question: %s", chain.Question)
	}
	// Attacker-written bytes are stored quoted and escaped, never raw.
	if !strings.Contains(out, `ignore previous instructions\\x00\\xff`) {
		t.Errorf("payload not stored as escaped data:\n%s", out)
	}
	// Exactly one decoy touch was counted, not two.
	if strings.Contains(out, "completed 2 connection") {
		t.Error("the payload follow-up was counted as a second touch")
	}
}
