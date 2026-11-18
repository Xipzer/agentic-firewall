package incident

import (
	"fmt"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

var t0 = time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)

func esc(subject, class, prio string, target afp.Tier) *afp.Escalation {
	return &afp.Escalation{Envelope: afp.NewEnvelope(afp.TypeEscalation, afp.Source{Tier: afp.TierFast, Agent: "t"}),
		Subject: afp.Subject{Kind: afp.SubjectHost, Value: subject}, Refs: []string{"ver_1"}, Question: "q",
		Priority: prio, Target: target, Class: class}
}

// A campaign from a thousand addresses is one incident, not a thousand alerts.
func TestCampaignFoldsIntoOneIncident(t *testing.T) {
	g := New(DefaultConfig())
	emitted := 0
	var id string
	for i := 0; i < 1000; i++ {
		at := t0.Add(time.Duration(i) * 300 * time.Millisecond)
		if e := g.Admit(esc(fmt.Sprintf("45.9.%d.%d", i/250, i%250), "access.bruteforce", "normal", afp.TierMedium), false, at); e != nil {
			emitted++
			if id == "" {
				id = e.Incident
			} else if e.Incident != id {
				t.Fatal("campaign split into several incidents")
			}
		}
	}
	// 1000 escalations over 5 minutes: the first, then nothing until the 10-minute summary.
	if emitted != 1 || g.Folded != 999 {
		t.Fatalf("emitted %d folded %d", emitted, g.Folded)
	}
	if e := g.Admit(esc("45.9.9.9", "access.bruteforce", "normal", afp.TierMedium), false, t0.Add(11*time.Minute)); e == nil ||
		e.Context["incident_escalations"].(int) != 1001 {
		t.Fatalf("summary missing or wrong: %+v", e)
	}
}

func TestNoveltyAndPriorityBreakThrough(t *testing.T) {
	g := New(DefaultConfig())
	g.Admit(esc("1.2.3.4", "recon.scan.vertical", "normal", afp.TierMedium), false, t0)
	if g.Admit(esc("1.2.3.5", "recon.scan.vertical", "normal", afp.TierMedium), false, t0.Add(time.Second)) != nil {
		t.Fatal("repeat should fold")
	}
	if e := g.Admit(esc("1.2.3.6", "recon.scan.vertical", "normal", afp.TierMedium), true, t0.Add(2*time.Second)); e == nil || e.Priority != "high" {
		t.Fatal("novel activity must surface and be raised to high")
	}
	if g.Admit(esc("1.2.3.7", "recon.scan.vertical", "critical", afp.TierHuman), false, t0.Add(3*time.Second)) == nil {
		t.Fatal("higher priority must surface")
	}
	if g.Admit(esc("1.2.3.7", "recon.scan.vertical.distributed", "normal", afp.TierMedium), false, t0.Add(4*time.Second)) != nil {
		t.Fatal("distributed variant belongs to the same campaign")
	}
	// The incident closes after the window and a new one opens.
	if e := g.Admit(esc("1.2.3.8", "recon.scan.vertical", "normal", afp.TierMedium), false, t0.Add(time.Hour)); e == nil {
		t.Fatal("new incident after window")
	}
}

func TestAnalystBudgetRationsModelsNotHumans(t *testing.T) {
	c := DefaultConfig()
	c.AnalystPerHour, c.AnalystPerDay = 2, 3
	g := New(c)
	var got []string
	for i, class := range []string{"a.x", "b.x", "c.x", "d.x"} {
		e := g.Admit(esc("1.1.1."+fmt.Sprint(i), class, "normal", afp.TierMedium), false, t0.Add(time.Duration(i)*time.Minute))
		got = append(got, e.Context["analyst"].(string))
	}
	if fmt.Sprint(got) != "[queued queued over-budget over-budget]" {
		t.Fatalf("hourly cap: %v", got)
	}
	e := g.Admit(esc("9.9.9.9", "dos.flood", "critical", afp.TierHuman), false, t0.Add(5*time.Minute))
	if e.Context["analyst"] != "human" {
		t.Fatal("human escalations must never be rationed")
	}
	if e := g.Admit(esc("1.1.1.9", "e.x", "normal", afp.TierMedium), false, t0.Add(2*time.Hour)); e.Context["analyst"] != "queued" {
		t.Fatal("hourly budget should refill")
	}
	if e := g.Admit(esc("1.1.1.10", "f.x", "normal", afp.TierMedium), false, t0.Add(3*time.Hour)); e.Context["analyst"] != "over-budget" {
		t.Fatal("daily cap ignored")
	}
}
