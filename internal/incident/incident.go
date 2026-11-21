// Package incident folds escalations into incidents and rations analyst
// attention.
//
// Escalations are cheap to trigger, so an attacker who can trigger them can
// burn model tokens and human attention (denial of wallet) or bury a real
// incident under noise. The grouper makes cost scale with the number of
// distinct incidents, not with attack volume: one brute-force campaign from a
// thousand addresses is one incident. Model attention is budgeted per hour
// and per day and given first to what is new (low coverage saturation).
package incident

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

type Config struct {
	Window         time.Duration // an incident closes after this long without escalations
	Resummarise    time.Duration // re-emit a summary of an ongoing incident at most this often
	AnalystPerHour int
	AnalystPerDay  int
}

func DefaultConfig() Config {
	return Config{Window: 30 * time.Minute, Resummarise: 10 * time.Minute, AnalystPerHour: 10, AnalystPerDay: 50}
}

type Incident struct {
	ID          string    `json:"id"`
	Class       string    `json:"class"`
	Priority    string    `json:"priority"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	Escalations int       `json:"escalations"`
	Subjects    []string  `json:"subjects"`
	Analyst     string    `json:"analyst"`
	Question    string    `json:"question"`
	subjects    map[string]bool
	lastEmit    time.Time
}

type Grouper struct {
	mu       sync.Mutex
	c        Config
	open     map[string]*Incident
	hour     int64
	day      int64
	inHour   int
	inDay    int
	Folded   uint64 // escalations absorbed into an existing incident
	Rationed uint64 // incidents refused analyst time by the budget
}

func New(c Config) *Grouper { return &Grouper{c: c, open: map[string]*Incident{}} }

var rank = map[string]int{"low": 0, "normal": 1, "high": 2, "critical": 3}

func key(e *afp.Escalation) string {
	c := strings.TrimSuffix(e.Class, ".distributed")
	if c == "" {
		c = "unclassified"
	}
	return c
}

// Admit folds an escalation into its incident. It returns the escalation to
// record (stamped with the incident and a summary), or nil when it adds
// nothing new and is folded silently.
func (g *Grouper) Admit(e *afp.Escalation, novel bool, now time.Time) *afp.Escalation {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, inc := range g.open {
		if now.Sub(inc.Last) > g.c.Window {
			delete(g.open, k)
		}
	}
	if novel && rank[e.Priority] < rank["high"] {
		e.Priority = "high" // something this asset has never seen deserves a look first
	}
	k := key(e)
	inc, ok := g.open[k]
	emit := false
	if !ok {
		inc = &Incident{ID: "inc_" + strings.TrimPrefix(afp.NewID(afp.TypeEscalation), "esc_"), Class: k,
			Priority: e.Priority, First: now, subjects: map[string]bool{}}
		g.open[k] = inc
		emit = true
		inc.Analyst = g.ration(e, now)
	}
	inc.Last = now
	inc.Question = e.Question
	inc.Escalations++
	if !inc.subjects[e.Subject.Value] && len(inc.subjects) < 32 {
		inc.subjects[e.Subject.Value] = true
		inc.Subjects = append(inc.Subjects, e.Subject.Value)
	}
	if rank[e.Priority] > rank[inc.Priority] {
		inc.Priority = e.Priority
		emit = true
		if inc.Analyst != "queued" {
			inc.Analyst = g.ration(e, now)
		}
	}
	if novel || now.Sub(inc.lastEmit) >= g.c.Resummarise {
		emit = true
	}
	if !emit {
		g.Folded++
		return nil
	}
	inc.lastEmit = now
	e.Incident = inc.ID
	if e.Context == nil {
		e.Context = map[string]any{}
	}
	e.Context["incident_escalations"] = inc.Escalations
	e.Context["incident_subjects"] = append([]string(nil), inc.Subjects...)
	e.Context["incident_since"] = inc.First.UTC().Format(time.RFC3339)
	e.Context["analyst"] = inc.Analyst
	if inc.Escalations > 1 {
		e.Question = fmt.Sprintf("[%d escalations from %d+ subjects since %s] %s", inc.Escalations, len(inc.Subjects),
			inc.First.UTC().Format("15:04"), e.Question)
	}
	return e
}

// ration decides whether an incident gets model attention. Humans are
// never rationed: escalations targeted at a human always go through.
func (g *Grouper) ration(e *afp.Escalation, now time.Time) string {
	if e.Target == afp.TierHuman {
		return "human"
	}
	if h := now.Unix() / 3600; h != g.hour {
		g.hour, g.inHour = h, 0
	}
	if d := now.Unix() / 86400; d != g.day {
		g.day, g.inDay = d, 0
	}
	if g.inHour >= g.c.AnalystPerHour || g.inDay >= g.c.AnalystPerDay {
		g.Rationed++
		return "over-budget"
	}
	g.inHour++
	g.inDay++
	return "queued"
}

func (g *Grouper) Open() []Incident {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Incident, 0, len(g.open))
	for _, inc := range g.open {
		out = append(out, *inc)
	}
	return out
}

func (g *Grouper) Stats() map[string]uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]uint64{"open": uint64(len(g.open)), "folded": g.Folded, "rationed": g.Rationed,
		"analyst_this_hour": uint64(g.inHour), "analyst_today": uint64(g.inDay)}
}
