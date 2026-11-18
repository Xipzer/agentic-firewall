package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/enforce"
	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/journal"
)

// ReplayResult summarises an offline run.
type ReplayResult struct {
	Events   int
	Verdicts map[afp.Action]int
	Memory   *enforce.Memory
}

// Replay runs recorded AFP observations through the fast tier and the guard
// on a simulated clock, in shadow, and writes the resulting messages to w.
// Use it to test heuristics or a config change against a captured incident
// before letting it near a live network.
func Replay(cfg config.Config, r io.Reader, w io.Writer, log *slog.Logger, local config.Discovered) (ReplayResult, error) {
	var evs []fast.Event
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		var env afp.Envelope
		if json.Unmarshal(s.Bytes(), &env) != nil || env.Type != afp.TypeObservation {
			continue
		}
		var o afp.Observation
		if json.Unmarshal(s.Bytes(), &o) != nil {
			continue
		}
		if ev, err := fast.EventFromObservation(&o); err == nil {
			evs = append(evs, ev)
		}
	}
	if err := s.Err(); err != nil {
		return ReplayResult{}, err
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	res := ReplayResult{Events: len(evs), Verdicts: map[afp.Action]int{}}
	if len(evs) == 0 {
		return res, nil
	}
	clock := evs[0].Time
	cfg.Mode = "enforce" // enforce against memory only, so verdicts show what would have happened
	cfg.Probation = 0
	d := New(cfg, log)
	d.Now = func() time.Time { return clock }
	d.discover = func() config.Discovered { return local }
	mem := enforce.NewMemory(d.Now)
	d.Enforcer, d.Journal = mem, journal.NewWriter(w)
	d.Feeds = nil
	if err := d.Init(); err != nil {
		return res, err
	}
	res.Memory = mem
	ctx := context.Background()
	step := 250 * time.Millisecond
	next := clock.Add(step)
	flush := func(until time.Time) {
		for !next.After(until) {
			clock = next
			for _, dec := range d.Engine.Tick(clock) {
				v := d.decide(dec, clock)
				res.Verdicts[v.Action]++
				if v.Action == afp.ActionDrop || v.Action == afp.ActionThrottle {
					// decide queues to the applier; apply directly in replay
					select {
					case e := <-d.applyCh:
						_ = mem.Apply(ctx, []enforce.Entry{e})
					default:
					}
				}
			}
			next = next.Add(step)
		}
	}
	for _, ev := range evs {
		flush(ev.Time)
		clock = ev.Time
		d.Engine.Ingest(ev)
	}
	flush(clock.Add(cfg.Heuristics.HandshakeWait.D() + 2*step))
	return res, nil
}
