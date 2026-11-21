package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/graph"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

// The adviser boundary.
//
// Any model afw consults, local or remote, is treated as untrusted: its
// provider can be compromised, its endpoint redirected, its weights tampered
// with, or attacker-written text can steer an honest model. From here all of
// those look the same: the answers cannot be trusted. So the design does not
// try to detect a bad model first. It bounds what any answer can do:
//
//   - The adviser has one door: a socket that serves redacted briefings and
//     accepts proposals. It cannot reach the firewall, the admin socket, keys
//     or the off switch.
//   - A proposal is never executed. It becomes weighted, unproven evidence
//     for the fast tier, which decides and then passes every safety rail.
//     Unproven evidence can slow a source, never block one.
//   - It may only speak about sources the fast tier itself already flagged,
//     so it cannot point afw at a victim. It can never lift or allow.
//   - Its words never enter the memory other models read.
//   - Things an honest adviser would not do count as strikes. Three strikes
//     suspend it, undo its influence and call a human.

// Proposal is the only thing an adviser can say to afw.
type Proposal struct {
	Subject    string  `json:"subject"`
	Action     string  `json:"action"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Incident   string  `json:"incident,omitempty"`
}

type ProposalResult struct {
	Accepted  bool   `json:"accepted"`
	Refused   string `json:"refused,omitempty"`
	Strikes   int    `json:"strikes"`
	Suspended bool   `json:"suspended"`
}

const (
	maxProposalBytes = 8 << 10
	strikeLimit      = 3
	strikeWindow     = 24 * time.Hour
	adviceTTL        = 10 * time.Minute // how long one piece of advice counts
)

type adviser struct {
	mu         sync.Mutex
	strikes    []time.Time
	suspended  time.Time
	recent     []time.Time
	influenced map[netip.Prefix]time.Time
	redactKey  []byte
	accepted   uint64
	refused    uint64
}

func newAdviser() *adviser {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &adviser{influenced: map[netip.Prefix]time.Time{}, redactKey: key}
}

func (d *Daemon) adviserNode() string { return "analyst:" + d.Cfg.Analyst.Provider }

// hidden is everything a briefing must not reveal: the LAN, this machine and
// the protected subjects (router, resolvers, admin hosts).
func (d *Daemon) hidden() []netip.Prefix {
	return append(append(append([]netip.Prefix(nil), d.internal...), d.local...), d.Guard.Protected()...)
}

// Briefing is the redacted context pack an adviser receives.
func (d *Daemon) Briefing(q string) (string, bool) {
	id, ok := d.Graph.Resolve(q)
	if !ok {
		return "", false
	}
	return graph.Redact(d.Graph.Pack(id, 60), d.hidden(), d.adv.redactKey), true
}

// Propose takes one raw answer from the adviser. It returns what afw did with it.
func (d *Daemon) Propose(ctx context.Context, raw []byte) ProposalResult {
	a := d.adv
	now := d.Now()
	a.mu.Lock()
	suspended := now.Before(a.suspended)
	cut := now.Add(-time.Hour)
	for len(a.recent) > 0 && a.recent[0].Before(cut) {
		a.recent = a.recent[1:]
	}
	overRate := len(a.recent) >= d.Cfg.Analyst.ProposalsPerHour
	if !suspended && !overRate {
		a.recent = append(a.recent, now)
	}
	a.mu.Unlock()
	switch {
	case suspended:
		return d.proposalOutcome(ctx, nil, "the adviser is suspended", false, now)
	case overRate:
		return d.proposalOutcome(ctx, nil, "hourly proposal limit reached", false, now)
	case len(raw) > maxProposalBytes:
		return d.proposalOutcome(ctx, nil, "answer too large", true, now)
	}
	var p Proposal
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() {
		return d.proposalOutcome(ctx, nil, "answer is not a single well-formed proposal", true, now)
	}
	if p.Confidence < 0 || p.Confidence > 1 || p.Confidence != p.Confidence {
		return d.proposalOutcome(ctx, &p, "confidence out of range", true, now)
	}
	switch p.Action {
	case "observe", "throttle", "drop":
	default:
		// Includes allow and unblock: an adviser can never lift an action.
		return d.proposalOutcome(ctx, &p, fmt.Sprintf("an adviser may not %q; it can only advise watching or restricting", clip(p.Action, 24)), true, now)
	}
	if strings.HasPrefix(p.Subject, "lan-") {
		return d.proposalOutcome(ctx, &p, "devices inside the network are not the adviser's to act on", false, now)
	}
	subj, err := netx.ParsePrefixOrAddr(p.Subject)
	if err != nil {
		return d.proposalOutcome(ctx, &p, "subject is not an address or range", true, now)
	}
	if netx.IsHost(subj) {
		subj = netx.HostKey(subj.Addr())
	}
	if netx.Overlaps(subj, d.hidden()) {
		// It was never shown these addresses, so naming one is not an honest mistake.
		return d.proposalOutcome(ctx, &p, "subject is protected or inside the network", true, now)
	}
	var flagged bool
	d.do(func() { flagged = d.Engine.Flagged(subj, now) })
	if !flagged {
		return d.proposalOutcome(ctx, &p, "the firewall's own evidence has not flagged this source, so the adviser cannot act on it", true, now)
	}

	d.proposalRecord(&p, "", now)
	if p.Action != "observe" {
		// Our words, not the model's: nothing it wrote reaches verdicts,
		// explanations or the briefings other models read.
		detail := fmt.Sprintf("adviser %s suggested %s (confidence %.2f)", d.Cfg.Analyst.Provider, p.Action, p.Confidence)
		d.do(func() {
			// Always unproven evidence: it can raise "watch" to "slow down",
			// never produce a block, and never touch a source with earned trust.
			d.Engine.AddPeer(subj, d.adviserNode(), d.Cfg.Analyst.Trust*p.Confidence, true, adviceTTL, detail, now)
		})
		a.mu.Lock()
		a.influenced[subj] = now
		for k, t := range a.influenced {
			if now.Sub(t) > 2*time.Hour {
				delete(a.influenced, k)
			}
		}
		a.mu.Unlock()
	}
	a.mu.Lock()
	a.accepted++
	res := ProposalResult{Accepted: true, Strikes: len(a.strikes)}
	a.mu.Unlock()
	return res
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// proposalRecord journals what the adviser said. Its text is attacker-grade
// input (a compromised model wrote it), so it is stored clipped and escaped,
// as data, in a record that briefings never include.
func (d *Daemon) proposalRecord(p *Proposal, refused string, now time.Time) *afp.Observation {
	o := &afp.Observation{Envelope: afp.NewEnvelope(afp.TypeObservation, afp.Source{Tier: afp.TierSlow, Agent: d.adviserNode(), Node: d.Cfg.Node}),
		Event: "sample", Context: map[string]any{"proposal": true}}
	o.TS = now.UTC()
	if p != nil {
		o.Context["subject"] = strconv.QuoteToASCII(clip(p.Subject, 64))
		o.Context["action"] = strconv.QuoteToASCII(clip(p.Action, 24))
		o.Context["confidence"] = p.Confidence
		o.Context["adviser_text"] = strconv.QuoteToASCII(clip(p.Reason, 300))
	}
	if refused != "" {
		o.Context["refused"] = refused
	}
	d.record(o)
	return o
}

func (d *Daemon) proposalOutcome(ctx context.Context, p *Proposal, why string, strike bool, now time.Time) ProposalResult {
	a := d.adv
	o := d.proposalRecord(p, why, now)
	a.mu.Lock()
	a.refused++
	suspendNow := false
	if strike {
		cut := now.Add(-strikeWindow)
		for len(a.strikes) > 0 && a.strikes[0].Before(cut) {
			a.strikes = a.strikes[1:]
		}
		a.strikes = append(a.strikes, now)
		if len(a.strikes) >= strikeLimit && !now.Before(a.suspended) {
			a.suspended = now.Add(strikeWindow)
			suspendNow = true
		}
	}
	res := ProposalResult{Refused: why, Strikes: len(a.strikes), Suspended: now.Before(a.suspended)}
	var undo []netip.Prefix
	if suspendNow {
		for k := range a.influenced {
			undo = append(undo, k)
		}
		clear(a.influenced)
	}
	a.mu.Unlock()
	if suspendNow {
		d.suspendAdviser(ctx, undo, o.ID, why, now)
	}
	return res
}

// suspendAdviser undoes everything the adviser influenced and calls a human.
// afw keeps running exactly as it does with no adviser at all.
func (d *Daemon) suspendAdviser(ctx context.Context, undo []netip.Prefix, ref, why string, now time.Time) {
	var lifted []netip.Prefix
	d.do(func() {
		for _, p := range undo {
			d.Engine.DropPeer(p, d.adviserNode())
			if d.Engine.Release(p, true, 0, now) {
				lifted = append(lifted, p)
			}
		}
	})
	if len(lifted) > 0 && d.enforcing() {
		_ = d.Enforcer.Remove(ctx, lifted)
	}
	e := &afp.Escalation{Envelope: afp.NewEnvelope(afp.TypeEscalation, afp.Source{Tier: afp.TierFast, Agent: "adviser-guard", Node: d.Cfg.Node}),
		Subject: afp.Subject{Kind: afp.SubjectPrefix, Value: "0.0.0.0/0"}, Refs: []string{ref}, Priority: "critical",
		Target: afp.TierHuman, Class: "defence.manipulation", Deadline: afp.FormatTTL(strikeWindow),
		Question: fmt.Sprintf("The adviser %q was suspended after %d answers an honest one would not give (latest: %s). Its influence on %d source(s) was undone. Is the provider, its endpoint or its model compromised, or is attacker text steering it? Run `afw analyst resume` once checked.",
			d.Cfg.Analyst.Provider, strikeLimit, why, len(lifted))}
	e.TS = now.UTC()
	d.do(func() { d.escalate(e, "", now) })
	d.Log.Warn("ADVISER SUSPENDED", "provider", d.Cfg.Analyst.Provider, "latest", why, "undone", len(lifted))
}

// ResumeAdviser clears the suspension and strikes. Admin socket only.
func (d *Daemon) ResumeAdviser() {
	d.adv.mu.Lock()
	d.adv.suspended, d.adv.strikes = time.Time{}, nil
	d.adv.mu.Unlock()
}

func (d *Daemon) adviserStatus() map[string]any {
	a := d.adv
	a.mu.Lock()
	defer a.mu.Unlock()
	st := map[string]any{"provider": d.Cfg.Analyst.Provider, "accepted": a.accepted, "refused": a.refused, "strikes": len(a.strikes),
		"suspended": d.Now().Before(a.suspended), "door": d.Cfg.Analyst.Socket != ""}
	if d.Now().Before(a.suspended) {
		st["suspended_until"] = a.suspended.UTC().Format(time.RFC3339)
	}
	return st
}

// ServeAdviser opens the adviser's door: briefings out, proposals in, and
// nothing else. Whatever runs the model should be a separate, unprivileged
// process whose only access to afw is this socket.
func (d *Daemon) ServeAdviser(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o660)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /briefing", func(w http.ResponseWriter, r *http.Request) {
		text, ok := d.Briefing(r.URL.Query().Get("q"))
		if !ok {
			http.Error(w, "nothing matches", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, text)
	})
	mux.HandleFunc("GET /incidents", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(d.Incidents.Open())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, graph.Redact(string(b), d.hidden(), d.adv.redactKey))
	})
	mux.HandleFunc("POST /propose", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxProposalBytes+1))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.Propose(r.Context(), raw))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close(); _ = os.Remove(path) }()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
