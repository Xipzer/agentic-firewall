package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/fast"
	"github.com/Xipzer/agentic-firewall/internal/graph"
	"github.com/Xipzer/agentic-firewall/internal/netx"
	"github.com/Xipzer/agentic-firewall/internal/posture"
	"github.com/Xipzer/agentic-firewall/internal/ui"
)

// Version is set by the command that embeds the daemon.
var Version = "dev"

// The web interface is a view over what afw already records, plus the same
// few actions the command line offers. It is an attack surface on a
// firewall, so:
//
//   - it is off unless configured, and binds to loopback by default;
//   - every data request needs a token that only root can read;
//   - the Host header must be one we serve (stops DNS rebinding);
//   - actions exist only on loopback; a LAN listener is read-only;
//   - the page loads nothing from anywhere else (strict CSP), and the
//     script only ever writes text, never HTML, because much of what it
//     shows was written by attackers.

// Decision is one verdict as the interface shows it.
type Decision struct {
	TS         time.Time    `json:"ts"`
	ID         string       `json:"id"`
	Subject    string       `json:"subject"`
	Action     afp.Action   `json:"action"`
	TTL        string       `json:"ttl,omitempty"`
	Mode       string       `json:"mode,omitempty"`
	Class      string       `json:"class,omitempty"`
	Confidence float64      `json:"confidence"`
	Reason     string       `json:"reason"`
	Tier       afp.Tier     `json:"tier"`
	Escalated  bool         `json:"escalated,omitempty"`
	Summary    string       `json:"summary,omitempty"`
	Signals    []afp.Signal `json:"signals,omitempty"`
}

const maxDecisions = 2000

type activity struct {
	mu    sync.Mutex
	items []Decision
	hours [24]hourCount
}

type hourCount struct {
	hour                    int64
	drop, throttle, observe int
}

func (a *activity) add(msg any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch m := msg.(type) {
	case *afp.Verdict:
		if m.Hops > 0 {
			return // a peer's verdict is evidence here, not a decision of ours
		}
		a.items = append(a.items, Decision{TS: m.TS, ID: m.ID, Subject: m.Subject.Value, Action: m.Action, TTL: m.TTL, Mode: m.Mode,
			Class: m.Class, Confidence: m.Confidence, Reason: m.Reason, Tier: m.Source.Tier, Signals: m.Signals})
		if len(a.items) > maxDecisions {
			a.items = append(a.items[:0:0], a.items[len(a.items)-maxDecisions*3/4:]...)
		}
		h := m.TS.Unix() / 3600
		b := &a.hours[h%24]
		if b.hour != h {
			*b = hourCount{hour: h}
		}
		switch m.Action {
		case afp.ActionDrop:
			b.drop++
		case afp.ActionThrottle:
			b.throttle++
		case afp.ActionObserve:
			b.observe++
		}
	case *afp.Explanation:
		if i := a.find(m.About); i >= 0 {
			a.items[i].Summary = m.Summary
		}
	case *afp.Escalation:
		if len(m.Refs) > 0 {
			if i := a.find(m.Refs[0]); i >= 0 {
				a.items[i].Escalated = true
			}
		}
	}
}

// find looks from the newest end: an explanation follows its verdict at once.
func (a *activity) find(id string) int {
	for i := len(a.items) - 1; i >= 0 && i >= len(a.items)-64; i-- {
		if a.items[i].ID == id {
			return i
		}
	}
	return -1
}

func (a *activity) last24(now time.Time) (drop, throttle, observe int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := now.Unix() / 3600
	for _, b := range a.hours {
		if h-b.hour < 24 && b.hour <= h {
			drop, throttle, observe = drop+b.drop, throttle+b.throttle, observe+b.observe
		}
	}
	return
}

// page returns decisions newest first, filtered, at most limit, older than before.
func (a *activity) page(filter, query string, before time.Time, limit int) (out []Decision, more bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.items) - 1; i >= 0; i-- {
		d := a.items[i]
		if !before.IsZero() && !d.TS.Before(before) {
			continue
		}
		switch filter {
		case "drop", "throttle", "observe", "allow":
			if string(d.Action) != filter {
				continue
			}
		case "review":
			if !d.Escalated {
				continue
			}
		}
		if query != "" && !strings.Contains(d.Subject, query) {
			continue
		}
		if len(out) == limit {
			return out, true
		}
		out = append(out, d)
	}
	return out, false
}

func (a *activity) latestFor(subject string) (Decision, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.items) - 1; i >= 0; i-- {
		if a.items[i].Subject == subject && a.items[i].Action != afp.ActionObserve && a.items[i].Action != afp.ActionAllow {
			return a.items[i], true
		}
	}
	return Decision{}, false
}

// Attention is one thing that needs the person looking at the screen.
type Attention struct {
	Level  string `json:"level"` // "act" (red), "check" (amber)
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	// Do names an action the interface can offer for it.
	Do      string   `json:"do,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Sources []string `json:"sources,omitempty"`
	Since   string   `json:"since,omitempty"`
}

type Restricted struct {
	Subject  string     `json:"subject"`
	Action   afp.Action `json:"action"`
	Until    time.Time  `json:"until"`
	Class    string     `json:"class,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Advised  bool       `json:"advised,omitempty"`
	Unproven bool       `json:"unproven,omitempty"`
}

type uiState struct {
	Node       string       `json:"node"`
	Role       string       `json:"role"`
	Version    string       `json:"version"`
	Now        time.Time    `json:"now"`
	Started    time.Time    `json:"started"`
	Mode       string       `json:"mode"`
	Posture    string       `json:"posture"`
	ReadOnly   bool         `json:"read_only"`
	Attention  []Attention  `json:"attention"`
	Restricted []Restricted `json:"restricted"`
	Day        struct {
		Blocked int `json:"blocked"`
		Slowed  int `json:"slowed"`
		Watched int `json:"watched"`
	} `json:"day"`
	KnownUsers int `json:"known_users"`
	// Handled counts open incidents afw dealt with on its own.
	Handled int `json:"handled"`
}

func subjectLabel(p netip.Prefix) string {
	if netx.IsHost(p) && p.Addr().Is4() {
		return p.Addr().String()
	}
	return p.String()
}

func (d *Daemon) uiState(ctx context.Context, readOnly bool) uiState {
	now := d.Now()
	s := uiState{Node: d.Cfg.Node, Role: d.Cfg.Role, Version: Version, Now: now.UTC(), Started: d.started.UTC(),
		Mode: d.Guard.Mode(), ReadOnly: readOnly, Attention: []Attention{}, Restricted: []Restricted{}}
	var active []fast.ActiveInfo
	var lvl posture.Level
	var reasons []string
	var holds time.Time
	d.do(func() {
		active = d.Engine.ActiveList(now)
		lvl, reasons, holds = d.Posture.Level(), d.Posture.Reasons, d.Posture.Until()
		s.KnownUsers = len(d.Engine.Trusted(now))
	})
	s.Posture = lvl.String()
	for _, a := range active {
		r := Restricted{Subject: subjectLabel(a.Subject), Action: a.Action, Until: a.Until.UTC(), Advised: a.Advised, Unproven: a.Unproven}
		if dec, ok := d.act.latestFor(r.Subject); ok {
			r.Class, r.Reason = dec.Class, dec.Reason
		}
		s.Restricted = append(s.Restricted, r)
	}
	s.Day.Blocked, s.Day.Slowed, s.Day.Watched = d.act.last24(now)

	add := func(a Attention) { s.Attention = append(s.Attention, a) }
	d.mu.Lock()
	if !d.probation.IsZero() && !d.confirmed {
		add(Attention{Level: "act", Title: "Confirm you can still reach this machine",
			Detail: "Blocking was switched on recently. It switches itself off at " + d.probation.Local().Format("15:04") + " unless you confirm, in case a rule has locked you out.",
			Do:     "confirm"})
	}
	d.mu.Unlock()
	if lvl == posture.BreakGlass {
		add(Attention{Level: "act", Title: "Emergency mode is on",
			Detail: "Known users and your own devices are served first; everyone else shares a limited lane. " + sentence(strings.Join(reasons, "; ")) + " It holds until at least " + holds.Local().Format("15:04") + ".",
			Do:     "breakglass-off"})
	}
	if st := d.adviserStatus(); st["suspended"] == true {
		add(Attention{Level: "act", Title: "The AI adviser was suspended",
			Detail: "It gave answers an honest adviser would not, so its influence was undone. Check the provider before resuming it.", Do: "adviser-resume"})
	}
	incs := d.Incidents.Open()
	sort.Slice(incs, func(i, j int) bool { return incs[i].Last.After(incs[j].Last) })
	handled := 0
	for _, inc := range incs {
		// Only what a person has to decide belongs here: critical incidents,
		// and anything about a device inside the network, which afw watches
		// but will not block. The rest afw has already dealt with.
		inside := strings.HasPrefix(inc.Class, "lateral.") || strings.HasPrefix(inc.Class, "c2.")
		if inc.Priority != "critical" && !inside {
			handled++
			continue
		}
		level := "check"
		if inc.Priority == "critical" {
			level = "act"
		}
		a := Attention{Level: level, Title: inc.Class, Detail: inc.Question, Sources: inc.Subjects, Since: inc.First.UTC().Format(time.RFC3339)}
		if len(inc.Subjects) == 1 && inc.Subjects[0] != "0.0.0.0/0" {
			a.Subject = inc.Subjects[0]
		}
		add(a)
	}
	s.Handled = handled
	bad := 0
	for _, f := range d.Feeds.States() {
		if f.Error != "" && f.Error != "not loaded yet" {
			bad++
		}
	}
	if bad > 0 {
		add(Attention{Level: "check", Title: fmt.Sprintf("%d threat list(s) failed to update", bad),
			Detail: "The last good copy is still in use. See System for which one.", Do: "open-system"})
	}
	if SensorStats != nil {
		if st := SensorStats(); st["overflow"] > 0 {
			add(Attention{Level: "check", Title: "The sensors were overloaded at some point",
				Detail: fmt.Sprintf("%d events were not examined. Nothing was blocked wrongly, but something may have been missed.", st["overflow"]), Do: "open-system"})
		}
	}
	if d.Journal.Dropped > 0 {
		add(Attention{Level: "check", Title: "Some log lines were dropped",
			Detail: fmt.Sprintf("%d lines were not written, to protect the disk from a flood of logging.", d.Journal.Dropped), Do: "open-system"})
	}
	return s
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// SourceView is everything known about one address, for the detail panel.
type SourceView struct {
	Subject    string       `json:"subject"`
	Known      bool         `json:"known"`
	First      time.Time    `json:"first"`
	Last       time.Time    `json:"last"`
	Restricted *Restricted  `json:"restricted,omitempty"`
	Protected  bool         `json:"protected"`
	Inside     bool         `json:"inside"`
	KnownUser  bool         `json:"known_user"`
	Classes    []string     `json:"classes"`
	Latest     *Decision    `json:"latest,omitempty"`
	Timeline   []TimelineEv `json:"timeline"`
}

type TimelineEv struct {
	TS       time.Time  `json:"ts"`
	Kind     string     `json:"kind"`
	Action   afp.Action `json:"action,omitempty"`
	TTL      string     `json:"ttl,omitempty"`
	Text     string     `json:"text"`
	Priority string     `json:"priority,omitempty"`
}

func (d *Daemon) sourceView(q string) (SourceView, error) {
	p, err := netx.ParsePrefixOrAddr(strings.TrimSpace(q))
	if err != nil {
		return SourceView{}, errors.New("that is not an address or a range")
	}
	if netx.IsHost(p) {
		p = netx.HostKey(p.Addr())
	}
	now := d.Now()
	v := SourceView{Subject: subjectLabel(p), Classes: []string{}, Timeline: []TimelineEv{}}
	v.Protected = netx.Overlaps(p, d.Guard.Protected())
	v.Inside = netx.Overlaps(p, d.internal) || netx.Overlaps(p, d.local)
	d.do(func() {
		v.KnownUser = d.Engine.Incumbent(p, now)
		for _, a := range d.Engine.ActiveList(now) {
			if a.Subject == p {
				v.Restricted = &Restricted{Subject: v.Subject, Action: a.Action, Until: a.Until.UTC(), Advised: a.Advised, Unproven: a.Unproven}
			}
		}
	})
	id := graph.SubjectID(afp.Subject{Kind: afp.SubjectPrefix, Value: p.String()})
	n, ok := d.Graph.Node(id)
	if !ok {
		return v, nil
	}
	v.Known, v.First, v.Last = true, n.First.UTC(), n.Last.UTC()
	seen := map[string]bool{}
	for _, nb := range d.Graph.Neighbours(id, 0) {
		a := nb.Node.Attrs
		switch nb.Node.Kind {
		case graph.KindVerdict:
			act, _ := a["action"].(afp.Action)
			ttl, _ := a["ttl"].(string)
			v.Timeline = append(v.Timeline, TimelineEv{TS: nb.Node.Last.UTC(), Kind: "decision", Action: act, TTL: ttl, Text: fmt.Sprint(a["reason"])})
			for _, c := range d.Graph.Neighbours(nb.Node.ID, 0) {
				if c.Node.Kind == graph.KindClass && !seen[c.Node.ID] {
					seen[c.Node.ID] = true
					v.Classes = append(v.Classes, strings.TrimPrefix(c.Node.ID, "class:"))
				}
			}
		case graph.KindEscalation:
			v.Timeline = append(v.Timeline, TimelineEv{TS: nb.Node.Last.UTC(), Kind: "question", Text: fmt.Sprint(a["question"]), Priority: fmt.Sprint(a["priority"])})
		}
		if len(v.Timeline) >= 60 {
			break
		}
	}
	sort.Strings(v.Classes)
	if dec, ok := d.act.latestFor(v.Subject); ok {
		v.Latest = &dec
	}
	return v, nil
}

// uiToken returns the access token, creating it on first use. It is stored
// readable by root only; `afw ui` prints the address that carries it.
func uiToken(stateDir string) (string, error) {
	path := filepath.Join(stateDir, "ui-token")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return "", err
	}
	return tok, os.WriteFile(path, []byte(tok+"\n"), 0o600)
}

// UIAddress is what `afw ui` prints: the page address carrying the token.
func UIAddress(listen, stateDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "ui-token"))
	if err != nil {
		return "", fmt.Errorf("no token yet: is afw running with ui.listen set? (%w)", err)
	}
	return "http://" + listen + "/#t=" + strings.TrimSpace(string(b)), nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// UIHandler builds the interface. Exposed for tests.
func (d *Daemon) UIHandler(listen, token string, readOnly bool) http.Handler {
	host, port, _ := net.SplitHostPort(listen)
	allowed := map[string]bool{listen: true}
	if loopback(host) {
		for _, h := range []string{"localhost", "127.0.0.1", "[::1]"} {
			allowed[h+":"+port] = true
		}
	} else {
		readOnly = true // never offer actions over an unencrypted LAN connection
	}
	static, _ := fs.Sub(ui.Files, "static")
	files := http.FileServer(http.FS(static))
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			v = map[string]string{"error": err.Error()}
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { reply(w, d.uiState(r.Context(), readOnly), nil) })
	mux.HandleFunc("GET /api/activity", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before, _ := time.Parse(time.RFC3339Nano, q.Get("before"))
		items, more := d.act.page(q.Get("show"), strings.TrimSpace(q.Get("q")), before, 60)
		if items == nil {
			items = []Decision{}
		}
		reply(w, map[string]any{"items": items, "more": more}, nil)
	})
	mux.HandleFunc("GET /api/source", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.sourceView(r.URL.Query().Get("q"))
		reply(w, v, err)
	})
	mux.HandleFunc("GET /api/coverage", func(w http.ResponseWriter, r *http.Request) { reply(w, d.Ledger.Report(d.Now()), nil) })
	mux.HandleFunc("GET /api/system", func(w http.ResponseWriter, r *http.Request) {
		st := d.Status(r.Context())
		reply(w, map[string]any{"status": st, "decoy_ports": d.Cfg.Canary.Ports, "peers": len(d.Cfg.Crosstalk.Peers),
			"adviser_door": d.Cfg.Analyst.Socket != "", "feeds_configured": len(d.Cfg.Feeds), "log_path": d.Cfg.Log.Path}, nil)
	})
	mux.HandleFunc("POST /api/do", func(w http.ResponseWriter, r *http.Request) {
		if readOnly {
			http.Error(w, "this view is read-only", http.StatusForbidden)
			return
		}
		var req struct{ Action, Subject, Value string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			reply(w, nil, errors.New("bad request"))
			return
		}
		var err error
		switch req.Action {
		case "confirm":
			d.Confirm()
		case "unblock":
			_, err = d.Unblock(r.Context(), req.Subject, time.Hour)
		case "mode":
			err = d.SetMode(r.Context(), req.Value)
		case "breakglass":
			if req.Value != "on" && req.Value != "off" {
				err = errors.New("value must be on or off")
			} else {
				d.SetBreakGlass(r.Context(), req.Value == "on")
			}
		case "adviser-resume":
			d.ResumeAdviser()
		case "panic":
			if err = d.Panic(r.Context()); err == nil && d.OnPanic != nil {
				go d.OnPanic()
			}
		default:
			err = errors.New("unknown action")
		}
		d.Log.Info("interface action", "action", req.Action, "subject", req.Subject, "value", req.Value, "err", err)
		reply(w, map[string]bool{"ok": err == nil}, err)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if !allowed[r.Host] {
			http.Error(w, "unexpected host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "token required", http.StatusUnauthorized)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			mux.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// ServeUI runs the interface until ctx ends.
func (d *Daemon) ServeUI(ctx context.Context, listen string, readOnly bool) error {
	token, err := uiToken(d.Cfg.StateDir)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: d.UIHandler(listen, token, readOnly), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	d.Log.Info("interface listening; run `afw ui` for the address", "listen", listen, "read_only", readOnly || !loopback(strings.Split(listen, ":")[0]))
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
