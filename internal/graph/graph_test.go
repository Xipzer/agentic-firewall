package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

var t0 = time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)

func src() afp.Source { return afp.Source{Tier: afp.TierFast, Agent: "t", Node: "gw"} }

// campaign writes a journal: n verdicts against one subject, each with an
// observation, an explanation and an escalation folded into one incident.
func campaign(n int) []byte {
	var buf bytes.Buffer
	w := func(m any) { b, _ := json.Marshal(m); buf.Write(b); buf.WriteByte('\n') }
	for i := 0; i < n; i++ {
		at := t0.Add(time.Duration(i) * time.Second)
		o := &afp.Observation{Envelope: afp.NewEnvelope(afp.TypeObservation, src()), Event: "new",
			Flow: &afp.Flow{Src: fmt.Sprintf("103.77.1.9:%d", 40000+i), Dst: "192.168.1.2:22", Proto: "tcp", Direction: "inbound"}}
		o.TS = at
		v := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, src()), Subject: afp.Subject{Kind: afp.SubjectHost, Value: "103.77.1.9"},
			Action: afp.ActionDrop, Confidence: 0.95, TTL: "10m", Reason: "short sessions", Class: "access.bruteforce", Refs: []string{o.ID}}
		v.TS = at
		x := &afp.Explanation{Envelope: afp.NewEnvelope(afp.TypeExplanation, src()), About: v.ID, Summary: "blocked"}
		x.TS = at
		e := &afp.Escalation{Envelope: afp.NewEnvelope(afp.TypeEscalation, src()), Subject: v.Subject, Refs: []string{v.ID},
			Question: "q", Priority: "normal", Class: "access.bruteforce", Incident: "inc_1"}
		e.TS = at
		w(o)
		w(v)
		w(x)
		w(e)
	}
	u := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, afp.Source{Tier: afp.TierHuman, Agent: "cli"}),
		Subject: afp.Subject{Kind: afp.SubjectHost, Value: "103.77.1.9"}, Action: afp.ActionAllow, Confidence: 1, Reason: "operator unblock"}
	u.TS = t0.Add(time.Duration(n) * time.Second)
	w(u)
	return buf.Bytes()
}

func TestResolveAndLinks(t *testing.T) {
	g := New(0)
	if n := g.Load(bytes.NewReader(campaign(3))); n != 13 {
		t.Fatalf("indexed %d", n)
	}
	for q, want := range map[string]string{"103.77.1.9": "subject:103.77.1.9", "::ffff:103.77.1.9": "subject:103.77.1.9",
		"access.bruteforce": "class:access.bruteforce", "inc_1": "inc_1"} {
		if id, ok := g.Resolve(q); !ok || id != want {
			t.Errorf("Resolve(%q) = %q %v", q, id, ok)
		}
	}
	n, _ := g.Node("subject:103.77.1.9")
	if n.Attrs["state"] != "lifted" {
		t.Errorf("unblock not reflected: %v", n.Attrs)
	}
	kinds := map[Kind]int{}
	for _, x := range g.Neighbours("inc_1", 0) {
		kinds[x.Node.Kind]++
	}
	if kinds[KindEscalation] != 3 || kinds[KindClass] != 1 {
		t.Errorf("incident links: %v", kinds)
	}
	if _, ok := g.Resolve("asset:192.168.1.2:22/tcp"); !ok {
		t.Error("asset node missing")
	}
}

// The pack an agent gets is bounded however large the campaign, and the
// same journal always gives the same pack.
func TestPackBoundedAndDeterministic(t *testing.T) {
	small, big := New(0), New(0)
	small.Load(bytes.NewReader(campaign(5)))
	j := campaign(2000)
	big.Load(bytes.NewReader(j))
	p := big.Pack("subject:103.77.1.9", 60)
	if n := strings.Count(p, "\n"); n > 61 {
		t.Fatalf("pack has %d lines", n)
	}
	if !strings.Contains(p, "verdicts: 2001 (drop 2000, allow 1)") || !strings.Contains(p, "access.bruteforce 2000") {
		t.Fatalf("tallies wrong:\n%s", p)
	}
	if !strings.Contains(p, "older entries omitted") {
		t.Fatal("trimming not stated")
	}
	again := New(0)
	again.Load(bytes.NewReader(j))
	if again.Pack("subject:103.77.1.9", 60) != p {
		t.Fatal("pack is not deterministic for the same journal")
	}
	t.Logf("journal %d KB -> pack %d bytes", len(j)/1024, len(p))
}

func TestBoundedKeepsSpine(t *testing.T) {
	g := New(500)
	g.Load(bytes.NewReader(campaign(400)))
	if g.Len() > 500 {
		t.Fatalf("graph unbounded: %d", g.Len())
	}
	for _, id := range []string{"subject:103.77.1.9", "inc_1", "class:access.bruteforce"} {
		if _, ok := g.Node(id); !ok {
			t.Errorf("spine node %s evicted", id)
		}
	}
}
