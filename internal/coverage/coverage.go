// Package coverage keeps a ledger of what afw has actually examined, per
// asset, and how saturated that examination is.
//
// Saturation borrows from code-audit practice: once more looking at the same
// place keeps finding nothing new, extra effort there is waste, and the
// effort (model tokens, human attention) should go where coverage is thin or
// where something new just appeared. Low saturation is also a signal in its
// own right: an asset that suddenly sees new kinds of sources or attacks.
package coverage

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/netx"
	"github.com/Xipzer/agentic-firewall/internal/saturation"
)

const (
	maxAssets       = 1024
	maxSourcesAsset = 4096
	window          = time.Hour
	buckets         = 12
)

// rolling counts observations and novel observations over the last hour.
type rolling struct {
	obs, novel [buckets]uint32
	last       int64
}

func (r *rolling) slot(t time.Time) int {
	idx := t.UnixNano() / int64(window/buckets)
	if idx > r.last {
		for i := max(r.last+1, idx-buckets+1); i <= idx; i++ {
			r.obs[i%buckets], r.novel[i%buckets] = 0, 0
		}
		r.last = idx
	}
	return int(idx % buckets)
}

func (r *rolling) add(t time.Time, novel bool) {
	i := r.slot(t)
	r.obs[i]++
	if novel {
		r.novel[i]++
	}
}

func (r *rolling) sums(t time.Time) (obs, novel uint32) {
	r.slot(t)
	for i := range r.obs {
		obs += r.obs[i]
		novel += r.novel[i]
	}
	return
}

type asset struct {
	name      string
	first     time.Time
	last      time.Time
	total     uint64
	sources   map[netip.Prefix]struct{}
	saturated bool // source map full: further sources are not counted as novel
	classes   map[string]uint64
	roll      rolling
	curve     saturation.Curve // distinct source ranges against flows observed
	distinct  hll
}

// sourceCount is exact until the set is full, then estimated.
func (a *asset) sourceCount() float64 {
	if !a.saturated {
		return float64(len(a.sources))
	}
	return math.Max(float64(len(a.sources)), a.distinct.estimate())
}

// Ledger is safe for concurrent use.
type Ledger struct {
	mu     sync.Mutex
	assets map[string]*asset
	seen   map[string]uint64 // attack classes seen anywhere
	flows  uint64
	curve  saturation.Curve // distinct attack classes against flows observed, network-wide
}

func New() *Ledger { return &Ledger{assets: map[string]*asset{}, seen: map[string]uint64{}} }

// AssetOf names what an event touched on our side: a local or LAN service
// for inbound traffic, or the LAN device itself for its outbound behaviour.
func AssetOf(ev fast.Event, dir fast.Direction) string {
	switch dir {
	case fast.DirInbound, fast.DirInternal:
		return fmt.Sprintf("%s/%s", ev.Dst.Addr().Unmap(), portProto(ev))
	case fast.DirOutbound:
		return ev.Src.Addr().Unmap().String() + " (outbound)"
	}
	return ""
}

func portProto(ev fast.Event) string {
	p := "tcp"
	switch ev.Proto {
	case fast.ProtoUDP:
		p = "udp"
	case fast.ProtoICMP, fast.ProtoICMPv6:
		return "icmp"
	}
	return fmt.Sprintf("%d/%s", ev.Dst.Port(), p)
}

func (l *Ledger) get(name string, now time.Time) *asset {
	a, ok := l.assets[name]
	if ok {
		return a
	}
	if len(l.assets) >= maxAssets {
		var oldest string
		var ot time.Time
		for k, x := range l.assets {
			if ot.IsZero() || x.last.Before(ot) {
				oldest, ot = k, x.last
			}
		}
		delete(l.assets, oldest)
	}
	a = &asset{name: name, first: now, sources: map[netip.Prefix]struct{}{}, classes: map[string]uint64{}}
	l.assets[name] = a
	return a
}

// Observe records one new flow. A flow is novel when its source range has
// never touched this asset before.
func (l *Ledger) Observe(ev fast.Event, dir fast.Direction) {
	if ev.Kind != fast.KindNew {
		return
	}
	name := AssetOf(ev, dir)
	if name == "" {
		return
	}
	src := netx.AggKey(ev.Src.Addr())
	if dir == fast.DirOutbound {
		src = netx.AggKey(ev.Dst.Addr())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.get(name, ev.Time)
	a.last = ev.Time
	a.total++
	novel := false
	if _, ok := a.sources[src]; !ok && !a.saturated {
		if len(a.sources) >= maxSourcesAsset {
			a.saturated = true
		} else {
			a.sources[src] = struct{}{}
			novel = true
		}
	}
	a.distinct.add(src)
	a.roll.add(ev.Time, novel)
	a.curve.Add(float64(a.total), a.sourceCount())
	l.flows++
}

// Classified records a decision's attack class against the asset it hit.
// A class never seen on this asset before is novel.
func (l *Ledger) Classified(asset, class string, now time.Time) (novel bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen[class]++
	if l.seen[class] == 1 {
		l.curve.Add(float64(max(l.flows, 1)), float64(len(l.seen)))
	}
	if asset == "" {
		return l.seen[class] == 1
	}
	a := l.get(asset, now)
	a.classes[class]++
	novel = a.classes[class] == 1
	a.roll.add(now, novel)
	return novel
}

// Novelty is the share of the last hour's activity on an asset that was new
// (0 = fully saturated, 1 = everything new). Unknown assets count as new.
func (l *Ledger) Novelty(asset string, now time.Time) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.assets[asset]
	if !ok {
		return 1
	}
	obs, novel := a.roll.sums(now)
	if obs == 0 {
		return 0
	}
	return float64(novel) / float64(obs)
}

type AssetReport struct {
	Asset         string            `json:"asset"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
	Flows         uint64            `json:"flows"`
	SourceRanges  int               `json:"source_ranges"` // estimated once above 4096
	Classes       map[string]uint64 `json:"classes,omitempty"`
	FlowsLastHour uint32            `json:"flows_last_hour"`
	Saturation    float64           `json:"saturation"`
	// Discovery fits the asset's whole history of new source ranges:
	// "saturating" means a stable population (ceiling estimated), "scaling"
	// means it keeps meeting new sources, as anything internet-facing does.
	Discovery saturation.Result `json:"discovery"`
}

type ClassReport struct {
	Class  string `json:"class"`
	Family string `json:"family"`
	See    string `json:"see"`
	Act    string `json:"act"`
	Seen   uint64 `json:"seen"`
}

type Report struct {
	Assets  []AssetReport `json:"assets"`
	Classes []ClassReport `json:"attack_universe"`
	// Exercised is the share of detectable classes actually seen at least once.
	Exercised float64 `json:"exercised"`
	// ClassDiscovery fits new attack classes against traffic seen. Saturating
	// means this network has shown us its usual threats; a new class after
	// that is news.
	ClassDiscovery saturation.Result `json:"class_discovery"`
}

// Report summarises coverage, least saturated assets first: that is where
// attention buys the most.
func (l *Ledger) Report(now time.Time) Report {
	l.mu.Lock()
	defer l.mu.Unlock()
	var r Report
	for _, a := range l.assets {
		obs, novel := a.roll.sums(now)
		sat := 1.0
		if obs > 0 {
			sat = 1 - float64(novel)/float64(obs)
		}
		cl := make(map[string]uint64, len(a.classes))
		for k, v := range a.classes {
			cl[k] = v
		}
		r.Assets = append(r.Assets, AssetReport{Asset: a.name, FirstSeen: a.first, LastSeen: a.last, Flows: a.total,
			SourceRanges: int(a.sourceCount()), Classes: cl, FlowsLastHour: obs, Saturation: float64(int(sat*1000)) / 1000,
			Discovery: saturation.Fit(a.curve.Points)})
	}
	sort.Slice(r.Assets, func(i, j int) bool {
		if r.Assets[i].Saturation != r.Assets[j].Saturation {
			return r.Assets[i].Saturation < r.Assets[j].Saturation
		}
		return r.Assets[i].Asset < r.Assets[j].Asset
	})
	detectable, exercised := 0, 0
	for _, c := range Taxonomy {
		n := uint64(0)
		for k, v := range l.seen {
			if k == c.Class || len(k) > len(c.Class) && k[:len(c.Class)+1] == c.Class+"." {
				n += v
			}
		}
		r.Classes = append(r.Classes, ClassReport{Class: c.Class, Family: c.Family, See: c.See, Act: c.Act, Seen: n})
		if c.See != "no" {
			detectable++
			if n > 0 {
				exercised++
			}
		}
	}
	r.ClassDiscovery = saturation.Fit(l.curve.Points)
	if detectable > 0 {
		r.Exercised = float64(int(float64(exercised)/float64(detectable)*1000)) / 1000
	}
	return r
}
