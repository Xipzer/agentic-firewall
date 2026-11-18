package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/crosstalk"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
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
