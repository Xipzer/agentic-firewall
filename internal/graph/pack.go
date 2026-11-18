package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Pack renders a bounded, deterministic context pack about one node: what
// an analyst agent needs to reason about it, built from the graph rather
// than by re-reading the journal. Its size does not grow with attack
// volume: a campaign of a million packets packs into the same few hundred
// lines as a campaign of ten. Same graph, same pack, byte for byte.
func (g *Graph) Pack(id string, maxLines int) string {
	if maxLines <= 0 {
		maxLines = 60
	}
	n, ok := g.Node(id)
	if !ok {
		return "unknown: " + id + "\n"
	}
	var b strings.Builder
	line := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	line("# %s %s", n.Kind, strings.TrimPrefix(strings.TrimPrefix(n.ID, "subject:"), "class:"))
	line("first %s, last %s, %d messages", ts(n.First), ts(n.Last), n.Count)
	for _, k := range sortedKeys(n.Attrs) {
		line("%s: %v", k, n.Attrs[k])
	}
	nb := g.Neighbours(id, 0)
	byKind := map[Kind][]Neighbour{}
	for _, x := range nb {
		byKind[x.Node.Kind] = append(byKind[x.Node.Kind], x)
	}
	// Tallies first: they are what stays true as detail is trimmed.
	if vs := byKind[KindVerdict]; len(vs) > 0 {
		actions, classes := map[string]int{}, map[string]int{}
		for _, v := range vs {
			actions[fmt.Sprint(v.Node.Attrs["action"])]++
			for _, c := range g.Neighbours(v.Node.ID, 0) {
				if c.Node.Kind == KindClass {
					classes[strings.TrimPrefix(c.Node.ID, "class:")]++
				}
			}
		}
		line("verdicts: %d (%s)", len(vs), tally(actions))
		if len(classes) > 0 {
			line("attack classes: %s", tally(classes))
		}
	}
	for _, k := range []Kind{KindIncident, KindClass, KindSubject, KindAsset, KindNode} {
		if xs := byKind[k]; len(xs) > 0 {
			var ids []string
			for _, x := range xs {
				ids = append(ids, trimID(x.Node.ID))
			}
			sort.Strings(ids)
			if len(ids) > 12 {
				ids = append(ids[:12], fmt.Sprintf("+%d more", len(ids)-12))
			}
			line("%ss: %s", k, strings.Join(ids, ", "))
		}
	}
	line("## timeline (newest first)")
	budget := maxLines - strings.Count(b.String(), "\n") - 1
	var timeline []Neighbour
	for _, k := range []Kind{KindVerdict, KindEscalation, KindExplanation} {
		timeline = append(timeline, byKind[k]...)
	}
	sort.Slice(timeline, func(i, j int) bool {
		if !timeline[i].Node.Last.Equal(timeline[j].Node.Last) {
			return timeline[i].Node.Last.After(timeline[j].Node.Last)
		}
		return timeline[i].Node.ID < timeline[j].Node.ID
	})
	for i, x := range timeline {
		if i >= budget {
			line("(%d older entries omitted; query them by id)", len(timeline)-i)
			break
		}
		a := x.Node.Attrs
		switch x.Node.Kind {
		case KindVerdict:
			line("%s verdict %s %v %v conf=%v: %v", ts(x.Node.Last), x.Node.ID, a["action"], a["ttl"], a["confidence"], a["reason"])
		case KindEscalation:
			line("%s escalation %s [%v]: %v", ts(x.Node.Last), x.Node.ID, a["priority"], a["question"])
		case KindExplanation:
			line("%s explanation %s: %v", ts(x.Node.Last), x.Node.ID, a["summary"])
		}
	}
	return b.String()
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func trimID(id string) string {
	for _, p := range []string{"subject:", "class:", "asset:", "node:"} {
		id = strings.TrimPrefix(id, p)
	}
	return id
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func tally(m map[string]int) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if m[ks[i]] != m[ks[j]] {
			return m[ks[i]] > m[ks[j]]
		}
		return ks[i] < ks[j]
	})
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}
