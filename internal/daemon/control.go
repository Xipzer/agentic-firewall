package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

// Status is what `afw status` prints.
type Status struct {
	Node         string                       `json:"node"`
	Role         string                       `json:"role"`
	Mode         string                       `json:"mode"`
	Uptime       string                       `json:"uptime"`
	Probation    string                       `json:"probation,omitempty"`
	Protected    []string                     `json:"protected"`
	ActiveGuard  int                          `json:"active_actions"`
	BudgetDenied uint64                       `json:"budget_denied"`
	Engine       any                          `json:"engine"`
	Enforcer     map[string]uint64            `json:"enforcer,omitempty"`
	EnforcerErr  string                       `json:"enforcer_error,omitempty"`
	Feeds        any                          `json:"feeds"`
	Crosstalk    map[string]uint64            `json:"crosstalk,omitempty"`
	Sensors      map[string]uint64            `json:"sensors,omitempty"`
	JournalDrop  uint64                       `json:"journal_dropped"`
	Extra        map[string]map[string]uint64 `json:"-"`
}

// SensorStats is filled in by the caller that owns the sensors.
var SensorStats func() map[string]uint64

func (d *Daemon) Status(ctx context.Context) Status {
	s := Status{Node: d.Cfg.Node, Role: d.Cfg.Role, Mode: d.Guard.Mode(), Uptime: d.Now().Sub(d.started).Round(time.Second).String(),
		ActiveGuard: d.Guard.ActiveCount(), BudgetDenied: d.Guard.Exhausted, Feeds: d.Feeds.States(), JournalDrop: d.Journal.Dropped}
	for _, p := range d.Guard.Protected() {
		s.Protected = append(s.Protected, p.String())
	}
	d.mu.Lock()
	if !d.probation.IsZero() && !d.confirmed {
		s.Probation = "disarms at " + d.probation.Format(time.RFC3339) + " unless `afw confirm` is run"
	}
	d.mu.Unlock()
	d.do(func() { s.Engine = map[string]any{"stats": d.Engine.Stats, "active": d.Engine.Active()} })
	if st, err := d.Enforcer.Stats(ctx); err != nil {
		s.EnforcerErr = err.Error()
	} else {
		s.Enforcer = st
	}
	if d.Bus != nil {
		s.Crosstalk = d.Bus.Snapshot()
	}
	if SensorStats != nil {
		s.Sensors = SensorStats()
	}
	return s
}

func (d *Daemon) Confirm() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	was := !d.probation.IsZero() && !d.confirmed
	d.confirmed = true
	return was
}

// Unblock is a human allow verdict: it lifts the action everywhere it lives
// and holds the subject in grace so the same evidence does not re-block it.
func (d *Daemon) Unblock(ctx context.Context, subject string, grace time.Duration) (*afp.Verdict, error) {
	p, err := netx.ParsePrefixOrAddr(subject)
	if err != nil {
		return nil, err
	}
	key := p
	if netx.IsHost(p) {
		key = netx.HostKey(p.Addr())
	}
	sub := afp.Subject{Kind: afp.SubjectPrefix, Value: key.String()}
	if key.Addr().Is4() && key.Bits() == 32 {
		sub = afp.Subject{Kind: afp.SubjectHost, Value: key.Addr().String()}
	}
	v := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, afp.Source{Tier: afp.TierHuman, Agent: "afw-cli", Node: d.Cfg.Node}),
		Subject: sub, Action: afp.ActionAllow, Confidence: 1, Reason: "operator unblock"}
	out := d.Guard.Check(v, d.Now())
	d.do(func() { d.Engine.Release(key, false, grace, d.Now()) })
	if err := d.Enforcer.Remove(ctx, []netip.Prefix{key}); err != nil {
		return v, err
	}
	d.Journal.Write(v)
	d.Journal.Write(explain(v, nil, out))
	if d.Bus != nil {
		d.Bus.Publish(v)
	}
	return v, nil
}

func (d *Daemon) SetMode(ctx context.Context, mode string) error {
	if mode != "enforce" && mode != "shadow" {
		return errors.New("mode must be enforce or shadow")
	}
	var err error
	d.do(func() {
		if err = d.setMode(ctx, mode); err == nil && mode == "enforce" && d.Cfg.Probation > 0 {
			d.mu.Lock()
			d.probation, d.confirmed = d.Now().Add(d.Cfg.Probation.D()), false
			d.mu.Unlock()
		}
	})
	return err
}

// Panic removes the whole table. Nothing afw installed stays in the kernel.
func (d *Daemon) Panic(ctx context.Context) error {
	d.mu.Lock()
	d.panicked = true
	d.mu.Unlock()
	d.Guard.SetMode("shadow")
	return d.Enforcer.Teardown(ctx)
}

// ServeControl exposes the local admin API on a unix socket (root only).
func (d *Daemon) ServeControl(ctx context.Context, path string, onPanic func()) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			v = map[string]string{"error": err.Error()}
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { reply(w, d.Status(r.Context()), nil) })
	mux.HandleFunc("POST /confirm", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]bool{"was_on_probation": d.Confirm()}, nil)
	})
	mux.HandleFunc("POST /mode", func(w http.ResponseWriter, r *http.Request) {
		err := d.SetMode(r.Context(), r.URL.Query().Get("m"))
		reply(w, map[string]string{"mode": d.Guard.Mode()}, err)
	})
	mux.HandleFunc("POST /unblock", func(w http.ResponseWriter, r *http.Request) {
		grace := time.Hour
		if g := r.URL.Query().Get("grace"); g != "" {
			if gd, err := afp.ParseTTL(g); err == nil {
				grace = gd
			}
		}
		v, err := d.Unblock(r.Context(), r.URL.Query().Get("subject"), grace)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /panic", func(w http.ResponseWriter, r *http.Request) {
		err := d.Panic(r.Context())
		reply(w, map[string]string{"result": "table removed; afw is stopping"}, err)
		if err == nil && onPanic != nil {
			go onPanic()
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close(); _ = os.Remove(path) }()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
