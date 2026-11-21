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
		Confidence: d.Score, TTL: afp.FormatTTL(d.TTL), Reason: d.Reason, Escalate: d.Escalate, Signals: d.Signals, Class: d.Class}
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
		if ttl, err := afp.ParseTTL(v.TTL); err == nil {
			fmt.Fprintf(&b, " for %s", fast.Words(ttl))
		}
	}
	if v.Mode == "shadow" && v.Action != afp.ActionObserve {
		b.WriteString(" (shadow mode: nothing was actually enforced)")
	}
	b.WriteString(". ")
	if v.Reason != "" {
		fmt.Fprintf(&b, "Why: %s.", strings.TrimSuffix(v.Reason, "."))
	}
	if d != nil && d.Offences > 1 {
		fmt.Fprintf(&b, " This is offence number %d from this source, so it lasts longer.", d.Offences)
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
		Refs: append([]string{v.ID}, v.Refs...), Priority: "normal", Target: afp.TierMedium, Deadline: v.TTL, Class: v.Class}
	switch {
	case out.BudgetExhausted:
		e.Priority, e.Target = "critical", afp.TierHuman
		e.Question = "afw reached its safety limit on new actions, so this one was not taken. Is this a widespread attack that needs a wider response, or is afw misreading normal traffic?"
	case d != nil && len(d.Stages) >= 2:
		e.Priority = "high"
		if d.Internal || d.ProvenStages >= 2 {
			e.Priority, e.Target = "critical", afp.TierHuman
		}
		e.Question = fmt.Sprintf("This source went from %s in quick succession, the pattern of an automated intrusion tool working at machine speed. Did any attempt succeed, and is anything it reached compromised?", fast.StageWords(d.Stages, " to "))
	case d != nil && d.Internal:
		e.Priority = "high"
		e.Question = "A device inside your network is behaving like a scanner or attacker. afw is watching it but has not blocked it. Is it compromised, and should it be taken off the network?"
	case d != nil && d.SpoofLimited:
		e.Question = "Slowed, not blocked, because this evidence could be faked. Is it a real attacker that should be blocked, or faked traffic?"
	case d != nil && d.Aggregate:
		e.Question = "Several addresses in this range are acting together. Is the whole range hostile, or is it shared by many people, such as a mobile network or a cloud provider?"
	case len(out.Notes) > 0:
		e.Question = "A safety rail changed this verdict: " + strings.Join(out.Notes, "; ") + ". Is a different response needed?"
	default:
		e.Question = "afw is fairly, not fully, sure about this one. Worth a second look: keep, extend or lift it."
	}
	if e.Deadline == "" {
		e.Deadline = afp.FormatTTL(10 * time.Minute)
	}
	return e
}
