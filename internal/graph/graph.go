// Package graph is the evidence graph: a deterministic index over every AFP
// message afw has produced.
//
// Agents lose context (compaction, restarts, model swaps). The graph does
// not: it is rebuilt from the append-only journal, which stays the record of
// truth, so the two can never disagree. Every edge comes from an explicit
// AFP field (subject, refs, about, incident, class), never from inference,
// so the graph is complete by construction. An agent can always fall back on
// it for "what do we already know about X" and spend its budget on what is
// unknown instead of re-reading history.
package graph

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

type Kind string

const (
	KindSubject     Kind = "subject"
	KindAsset       Kind = "asset"
	KindClass       Kind = "class"
	KindIncident    Kind = "incident"
	KindVerdict     Kind = "verdict"
	KindEscalation  Kind = "escalation"
	KindExplanation Kind = "explanation"
	KindObservation Kind = "observation"
	KindRule        Kind = "rule"
	KindNode        Kind = "node" // an afw node (peer or self)
)

type EdgeType string

const (
	EdgeAbout      EdgeType = "about"      // verdict/escalation -> subject
	EdgeEvidence   EdgeType = "evidence"   // verdict/escalation -> observation or verdict
	EdgeClassified EdgeType = "classified" // verdict/escalation/incident -> class
	EdgePartOf     EdgeType = "part_of"    // escalation -> incident
	EdgeExplains   EdgeType = "explains"   // explanation -> verdict
	EdgeTouched    EdgeType = "touched"    // observation -> asset
	EdgeFrom       EdgeType = "from"       // observation -> subject
	EdgeIssuedBy   EdgeType = "issued_by"  // verdict -> node
	EdgeLifts      EdgeType = "lifts"      // allow verdict -> subject
	EdgeProvenance EdgeType = "provenance" // rule -> incident/explanation/verdict
)

type Node struct {
	ID    string         `json:"id"`
	Kind  Kind           `json:"kind"`
	First time.Time      `json:"first"`
	Last  time.Time      `json:"last"`
	Count int            `json:"count"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Type EdgeType `json:"type"`
}

// Graph is safe for concurrent use. It is bounded: when full, the oldest
// observations go first, then the oldest verdicts and explanations. Subjects,
// assets, classes and incidents (the spine) are kept longest.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	out   map[string]map[edgeKey]struct{}
	in    map[string]map[edgeKey]struct{}
	max   int
}

type edgeKey struct {
	other string
	typ   EdgeType
}

func New(maxNodes int) *Graph {
	if maxNodes <= 0 {
		maxNodes = 200000
	}
	return &Graph{nodes: map[string]*Node{}, out: map[string]map[edgeKey]struct{}{}, in: map[string]map[edgeKey]struct{}{}, max: maxNodes}
}

func (g *Graph) touch(id string, k Kind, t time.Time) *Node {
	n, ok := g.nodes[id]
	if !ok {
		n = &Node{ID: id, Kind: k, First: t, Last: t}
		g.nodes[id] = n
	}
	if t.After(n.Last) {
		n.Last = t
	}
	if !t.IsZero() && (n.First.IsZero() || t.Before(n.First)) {
		n.First = t
	}
	n.Count++
	return n
}

func (g *Graph) link(from, to string, t EdgeType) {
	if from == "" || to == "" {
		return
	}
	if g.out[from] == nil {
		g.out[from] = map[edgeKey]struct{}{}
	}
	if g.in[to] == nil {
		g.in[to] = map[edgeKey]struct{}{}
	}
	g.out[from][edgeKey{to, t}] = struct{}{}
	g.in[to][edgeKey{from, t}] = struct{}{}
}

// SubjectID normalises an address or prefix so every message about the same
// source lands on the same node.
func SubjectID(s afp.Subject) string {
	if p, err := s.Prefix(); err == nil {
		if netx.IsHost(p) && p.Addr().Is4() {
			return "subject:" + p.Addr().String()
		}
		if netx.IsHost(p) {
			return "subject:" + netx.HostKey(p.Addr()).String()
		}
		return "subject:" + p.String()
	}
	return "subject:" + s.Value
}

func endpointSubject(ep string) string {
	var a netip.Addr
	if ap, err := netip.ParseAddrPort(ep); err == nil {
		a = ap.Addr()
	} else if x, err := netip.ParseAddr(ep); err == nil {
		a = x
	} else {
		return ""
	}
	a = a.Unmap()
	return SubjectID(afp.Subject{Kind: afp.SubjectPrefix, Value: netip.PrefixFrom(a, a.BitLen()).String()})
}

// Ingest indexes one AFP message. Unknown or invalid input is ignored.
func (g *Graph) Ingest(msg any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch m := msg.(type) {
	case *afp.Observation:
		n := g.touch(m.ID, KindObservation, m.TS)
		n.Attrs = map[string]any{"event": m.Event}
		if m.Flow != nil {
			n.Attrs["flow"] = m.Flow.Src + " -> " + m.Flow.Dst + " " + m.Flow.Proto
			if s := endpointSubject(m.Flow.Src); s != "" {
				g.touch(s, KindSubject, m.TS)
				g.link(m.ID, s, EdgeFrom)
			}
			if m.Flow.Direction == "inbound" || m.Flow.Direction == "internal" {
				a := "asset:" + m.Flow.Dst + "/" + m.Flow.Proto
				g.touch(a, KindAsset, m.TS)
				g.link(m.ID, a, EdgeTouched)
			}
		}
		if p, ok := m.Context["posture"]; ok {
			n.Attrs["posture"] = p
			n.Attrs["reasons"] = m.Context["reasons"]
		}
	case *afp.Verdict:
		n := g.touch(m.ID, KindVerdict, m.TS)
		n.Attrs = map[string]any{"action": m.Action, "ttl": m.TTL, "confidence": m.Confidence, "reason": m.Reason,
			"mode": m.Mode, "posture": m.Posture, "tier": m.Source.Tier}
		s := SubjectID(m.Subject)
		sn := g.touch(s, KindSubject, m.TS)
		if m.Action == afp.ActionAllow {
			g.link(m.ID, s, EdgeLifts)
			sn.Attrs = setAttr(sn.Attrs, "state", "lifted")
		} else {
			g.link(m.ID, s, EdgeAbout)
			if m.Action != afp.ActionObserve {
				sn.Attrs = setAttr(sn.Attrs, "state", string(m.Action))
				sn.Attrs = setAttr(sn.Attrs, "state_until", m.TS.Add(ttlOf(m.TTL)).UTC().Format(time.RFC3339))
			}
		}
		if m.Class != "" {
			g.touch("class:"+m.Class, KindClass, m.TS)
			g.link(m.ID, "class:"+m.Class, EdgeClassified)
		}
		if m.Source.Node != "" {
			g.touch("node:"+m.Source.Node, KindNode, m.TS)
			g.link(m.ID, "node:"+m.Source.Node, EdgeIssuedBy)
		}
		for _, r := range m.Refs {
			g.link(m.ID, r, EdgeEvidence)
		}
	case *afp.Escalation:
		n := g.touch(m.ID, KindEscalation, m.TS)
		n.Attrs = map[string]any{"priority": m.Priority, "question": m.Question, "target": m.Target, "analyst": m.Context["analyst"]}
		g.link(m.ID, SubjectID(m.Subject), EdgeAbout)
		g.touch(SubjectID(m.Subject), KindSubject, m.TS)
		for _, r := range m.Refs {
			g.link(m.ID, r, EdgeEvidence)
		}
		if m.Class != "" {
			g.touch("class:"+m.Class, KindClass, m.TS)
			g.link(m.ID, "class:"+m.Class, EdgeClassified)
		}
		if m.Incident != "" {
			in := g.touch(m.Incident, KindIncident, m.TS)
			in.Attrs = setAttr(in.Attrs, "priority", m.Priority)
			in.Attrs = setAttr(in.Attrs, "escalations", m.Context["incident_escalations"])
			g.link(m.ID, m.Incident, EdgePartOf)
			if m.Class != "" {
				g.link(m.Incident, "class:"+m.Class, EdgeClassified)
			}
		}
	case *afp.Explanation:
		n := g.touch(m.ID, KindExplanation, m.TS)
		n.Attrs = map[string]any{"summary": m.Summary}
		g.link(m.ID, m.About, EdgeExplains)
	case *afp.Rule:
		n := g.touch(m.ID, KindRule, m.TS)
		n.Attrs = map[string]any{"action": m.Action, "ttl": m.TTL, "match": m.Match}
		for _, r := range append([]string{m.Provenance.Incident, m.Provenance.Explanation}, m.Provenance.Verdicts...) {
			g.link(m.ID, r, EdgeProvenance)
		}
	}
	g.evict()
}

func setAttr(m map[string]any, k string, v any) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	m[k] = v
	return m
}

func ttlOf(s string) time.Duration {
	d, _ := afp.ParseTTL(s)
	return d
}

var evictOrder = []Kind{KindObservation, KindExplanation, KindVerdict, KindEscalation}

func (g *Graph) evict() {
	if len(g.nodes) <= g.max {
		return
	}
	target := g.max * 9 / 10
	for _, k := range evictOrder {
		var ids []string
		for id, n := range g.nodes {
			if n.Kind == k {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return g.nodes[ids[i]].Last.Before(g.nodes[ids[j]].Last) })
		for _, id := range ids {
			if len(g.nodes) <= target {
				return
			}
			g.remove(id)
		}
	}
}

func (g *Graph) remove(id string) {
	for e := range g.out[id] {
		delete(g.in[e.other], edgeKey{id, e.typ})
	}
	for e := range g.in[id] {
		delete(g.out[e.other], edgeKey{id, e.typ})
	}
	delete(g.out, id)
	delete(g.in, id)
	delete(g.nodes, id)
}

// Decode parses one journal line into an AFP message (nil if not one).
func Decode(line []byte) any {
	var env afp.Envelope
	if json.Unmarshal(line, &env) != nil {
		return nil
	}
	var m any
	switch env.Type {
	case afp.TypeObservation:
		m = &afp.Observation{}
	case afp.TypeVerdict:
		m = &afp.Verdict{}
	case afp.TypeEscalation:
		m = &afp.Escalation{}
	case afp.TypeExplanation:
		m = &afp.Explanation{}
	case afp.TypeRule:
		m = &afp.Rule{}
	default:
		return nil
	}
	if json.Unmarshal(line, m) != nil {
		return nil
	}
	return m
}

// Load replays a journal into the graph and returns how many messages it indexed.
func (g *Graph) Load(r io.Reader) int {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for s.Scan() {
		if m := Decode(s.Bytes()); m != nil {
			g.Ingest(m)
			n++
		}
	}
	return n
}

func (g *Graph) Len() int { g.mu.RLock(); defer g.mu.RUnlock(); return len(g.nodes) }

// Resolve maps what a human or agent types (an IP, a prefix, an id, a class
// name) to a node id.
func (g *Graph) Resolve(q string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	cands := []string{q, "class:" + q, "asset:" + q}
	if p, err := netx.ParsePrefixOrAddr(q); err == nil {
		cands = append(cands, SubjectID(afp.Subject{Kind: afp.SubjectPrefix, Value: p.String()}))
	}
	for _, c := range cands {
		if _, ok := g.nodes[c]; ok {
			return c, true
		}
	}
	return "", false
}

type Neighbour struct {
	Edge EdgeType `json:"edge"`
	Dir  string   `json:"dir"`
	Node *Node    `json:"node"`
}

// Neighbours lists a node's edges, newest first, at most limit.
func (g *Graph) Neighbours(id string, limit int) []Neighbour {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []Neighbour
	for e := range g.out[id] {
		if n, ok := g.nodes[e.other]; ok {
			c := *n
			out = append(out, Neighbour{e.typ, "out", &c})
		}
	}
	for e := range g.in[id] {
		if n, ok := g.nodes[e.other]; ok {
			c := *n
			out = append(out, Neighbour{e.typ, "in", &c})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Node.Last.Equal(out[j].Node.Last) {
			return out[i].Node.Last.After(out[j].Node.Last)
		}
		return out[i].Node.ID < out[j].Node.ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (g *Graph) Node(id string) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok {
		return Node{}, false
	}
	return *n, true
}
