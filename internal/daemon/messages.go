package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/guard"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

func subjectOf(d fast.Decision) afp.Subject {
	if netx.IsHost(d.Subject) && d.Subject.Addr().Is4() {
		return afp.Subject{Kind: afp.SubjectHost, Value: d.Subject.Addr().String()}
	}
	return afp.Subject{Kind: afp.SubjectPrefix, Value: d.Subject.String()}
}

// verdictFrom turns a fast-tier decision into an AFP verdict, with the
// observations behind it so the journal can be replayed.
func verdictFrom(d fast.Decision, src afp.Source, throttleRate string) (*afp.Verdict, []*afp.Observation) {
	v := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, src), Subject: subjectOf(d), Action: d.Action,
		Confidence: d.Score, TTL: afp.FormatTTL(d.TTL), Reason: d.Reason, Escalate: d.Escalate, Signals: d.Signals}
	switch d.Action {
	case afp.ActionThrottle:
		v.Params = map[string]any{"rate": throttleRate, "scope": "new connections the subject starts"}
	case afp.ActionDrop:
		v.Params = map[string]any{"scope": "connections the subject starts; replies to ours still flow"}
	}
	obsSrc := afp.Source{Tier: afp.TierDataplane, Agent: "sensor", Node: src.Node}
	var obs []*afp.Observation
	for _, ev := range d.Evidence {
		o := ev.Observation(obsSrc, d.Direction)
		obs = append(obs, o)
		v.Refs = append(v.Refs, o.ID)
	}
	return v, obs
}

var plain = map[afp.Action]string{
	afp.ActionObserve:  "flagged for watching",
	afp.ActionThrottle: "slowed down",
	afp.ActionDrop:     "blocked",
	afp.ActionAllow:    "allowed",
}

func explain(v *afp.Verdict, d *fast.Decision, out guard.Outcome) *afp.Explanation {
	who := v.Subject.Value
	var b strings.Builder
	fmt.Fprintf(&b, "%s was %s", who, plain[v.Action])
	if v.Action != afp.ActionAllow && v.TTL != "" {
		fmt.Fprintf(&b, " for %s", v.TTL)
	}
	if v.Mode == "shadow" && v.Action != afp.ActionObserve {
		b.WriteString(" (shadow mode: nothing was actually enforced)")
	}
	b.WriteString(". ")
	if v.Reason != "" {
		fmt.Fprintf(&b, "Why: %s.", strings.TrimSuffix(v.Reason, "."))
	}
	if d != nil && d.Offences > 1 {
		fmt.Fprintf(&b, " Repeat offence #%d, so the duration was lengthened.", d.Offences)
	}
	for _, n := range out.Notes {
		fmt.Fprintf(&b, " Safety rail: %s.", n)
	}
	x := &afp.Explanation{Envelope: afp.NewEnvelope(afp.TypeExplanation, v.Source), About: v.ID,
		Summary: b.String(), Confidence: v.Confidence}
	for _, s := range v.Signals {
		x.Evidence = append(x.Evidence, afp.Evidence{Note: fmt.Sprintf("%s (weight %.2f%s): %s", s.Name, s.Weight, spoofNote(s), s.Detail)})
	}
	return x
}

func spoofNote(s afp.Signal) string {
	if s.Spoofable {
		return ", spoofable"
	}
	return ""
}

func escalation(v *afp.Verdict, d *fast.Decision, out guard.Outcome) *afp.Escalation {
	e := &afp.Escalation{Envelope: afp.NewEnvelope(afp.TypeEscalation, v.Source), Subject: v.Subject,
		Refs: append([]string{v.ID}, v.Refs...), Priority: "normal", Target: afp.TierMedium, Deadline: v.TTL}
	switch {
	case out.BudgetExhausted:
		e.Priority, e.Target = "critical", afp.TierHuman
		e.Question = "The action budget is exhausted. Is this a distributed attack that needs a wider response, or is a heuristic misfiring?"
	case d != nil && d.Internal:
		e.Priority = "high"
		e.Question = "An internal device is behaving like a scanner or attacker. Is it compromised, and should it be quarantined?"
	case d != nil && d.SpoofLimited:
		e.Question = "Throttled on spoofable evidence only. Is this a real attacker that should be dropped, or spoofed traffic?"
	case d != nil && d.Aggregate:
		e.Question = "Several addresses in this range are acting together. Is the whole range hostile, or is it shared infrastructure such as CGNAT or a cloud provider?"
	case len(out.Notes) > 0:
		e.Question = "A safety rail changed this verdict: " + strings.Join(out.Notes, "; ") + ". Is a different response needed?"
	default:
		e.Question = "Fast-tier confidence is moderate. Confirm, extend or lift this action."
	}
	if e.Deadline == "" {
		e.Deadline = afp.FormatTTL(10 * time.Minute)
	}
	return e
}
