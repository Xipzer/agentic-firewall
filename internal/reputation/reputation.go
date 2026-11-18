// Package reputation fetches, sanitises and caches IP blocklists.
//
// Feeds are untrusted input. A broken or poisoned feed could otherwise block
// the LAN (FireHOL level1 ships RFC1918 as "bogons"), the resolver, or half
// the internet, so every entry passes the same checks before use.
package reputation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

const maxBody = 32 << 20

type Rejects struct {
	Unparsed, Reserved, Protected, TooWide int
}

// Parse extracts prefixes from plain lists ("1.2.3.4", "1.2.3.0/24 ; SBL1",
// "1.2.3.4<TAB>7", "# comment"), JSON-lines lists ({"cidr": "..."}) and JSON
// arrays ([{"ipv4": "..."}]). With minScore > 0 the second column must be an
// integer of at least minScore (IPsum style counts).
func Parse(r io.Reader, minScore int) ([]netip.Prefix, int) {
	br := bufio.NewReaderSize(r, 64<<10)
	if first, _ := br.Peek(64); len(bytes.TrimSpace(first)) > 0 && bytes.TrimSpace(first)[0] == '[' {
		return parseArray(br)
	}
	var out []netip.Prefix
	bad := 0
	s := bufio.NewScanner(br)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue
		}
		if line[0] == '{' {
			var obj map[string]any
			if json.Unmarshal([]byte(line), &obj) != nil {
				bad++
				continue
			}
			if line = addrField(obj); line == "" {
				continue // metadata line
			}
		}
		tok := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ';' || r == ',' || r == '#' })
		if len(tok) == 0 {
			continue
		}
		if minScore > 0 {
			n, err := strconv.Atoi(safeIndex(tok, 1))
			if err != nil || n < minScore {
				continue
			}
		}
		p, err := netx.ParsePrefixOrAddr(tok[0])
		if err != nil {
			bad++
			continue
		}
		out = append(out, p)
	}
	return out, bad
}

func safeIndex(ss []string, i int) string {
	if i < len(ss) {
		return ss[i]
	}
	return ""
}

func addrField(obj map[string]any) string {
	for _, k := range []string{"cidr", "ip", "ipv4", "ipv6", "address"} {
		if v, ok := obj[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func parseArray(r io.Reader) ([]netip.Prefix, int) {
	var arr []map[string]any
	if err := json.NewDecoder(r).Decode(&arr); err != nil {
		return nil, 1
	}
	var out []netip.Prefix
	bad := 0
	for _, obj := range arr {
		v := addrField(obj)
		if v == "" {
			continue
		}
		p, err := netx.ParsePrefixOrAddr(v)
		if err != nil {
			bad++
			continue
		}
		out = append(out, p)
	}
	return out, bad
}

// Sanitize drops entries that are reserved, protected or implausibly wide.
func Sanitize(in []netip.Prefix, protected []netip.Prefix, min4, min6 int) ([]netip.Prefix, Rejects) {
	var r Rejects
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		switch {
		case (p.Addr().Is4() && p.Bits() < min4) || (p.Addr().Is6() && p.Bits() < min6):
			r.TooWide++
		case netx.Reserved(p):
			r.Reserved++
		case netx.Overlaps(p, protected):
			r.Protected++
		default:
			out = append(out, p)
		}
	}
	return netx.Collapse(out), r
}

// Table is an immutable prefix lookup for observe-class feeds.
type Table struct {
	lens  []int
	nets  map[netip.Prefix]string
	feeds map[string]float64
}

func NewTable() *Table { return &Table{nets: map[netip.Prefix]string{}, feeds: map[string]float64{}} }

func (t *Table) add(feed string, w float64, ps []netip.Prefix) {
	t.feeds[feed] = w
	seen := map[int]bool{}
	for _, l := range t.lens {
		seen[l] = true
	}
	for _, p := range ps {
		t.nets[p] = feed
		if !seen[p.Bits()+boolInt(p.Addr().Is6())*1000] {
			seen[p.Bits()+boolInt(p.Addr().Is6())*1000] = true
			t.lens = append(t.lens, p.Bits()+boolInt(p.Addr().Is6())*1000)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(t.lens)))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (t *Table) Lookup(a netip.Addr) (string, float64, bool) {
	if t == nil {
		return "", 0, false
	}
	a = a.Unmap()
	for _, l := range t.lens {
		is6 := l >= 1000
		if is6 != a.Is6() {
			continue
		}
		p, err := a.Prefix(l % 1000)
		if err != nil {
			continue
		}
		if f, ok := t.nets[p]; ok {
			return f, t.feeds[f], true
		}
	}
	return "", 0, false
}

func (t *Table) Len() int { return len(t.nets) }

type FeedState struct {
	Name     string    `json:"name"`
	Action   string    `json:"action"`
	Entries  int       `json:"entries"`
	Updated  time.Time `json:"updated"`
	Error    string    `json:"error,omitempty"`
	Rejects  Rejects   `json:"rejects"`
	Unparsed int       `json:"unparsed"`
	Failures int       `json:"failures,omitempty"`
	NextTry  time.Time `json:"next_try,omitempty"`
}

// Manager owns all feeds. Lookup is safe to call concurrently with Refresh.
type Manager struct {
	feeds     []config.Feed
	dir       string
	client    *http.Client
	min4      int
	min6      int
	mu        sync.Mutex
	current   map[string][]netip.Prefix
	state     map[string]*FeedState
	table     atomic.Pointer[Table]
	benign    atomic.Pointer[Table]
	protected func() []netip.Prefix
}

func NewManager(feeds []config.Feed, stateDir string, min4, min6 int, protected func() []netip.Prefix) *Manager {
	m := &Manager{feeds: feeds, dir: filepath.Join(stateDir, "feeds"), client: &http.Client{Timeout: 45 * time.Second},
		min4: min4, min6: min6, current: map[string][]netip.Prefix{}, state: map[string]*FeedState{}, protected: protected}
	m.table.Store(NewTable())
	m.benign.Store(NewTable())
	return m
}

func (m *Manager) Lookup(a netip.Addr) (string, float64, bool) { return m.table.Load().Lookup(a) }

// Benign reports whether a is a known research scanner.
func (m *Manager) Benign(a netip.Addr) bool { _, _, ok := m.benign.Load().Lookup(a); return ok }

// Due reports which feeds should be refreshed now.
func (m *Manager) Due(now time.Time) []config.Feed {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []config.Feed
	for _, f := range m.feeds {
		st := m.state[f.Name]
		every := f.Refresh.D()
		if every < 15*time.Minute {
			every = time.Hour // be polite: most lists update hourly or slower
		}
		switch {
		case st == nil || st.Updated.IsZero():
			out = append(out, f)
		case st.Failures > 0:
			if !now.Before(st.NextTry) {
				out = append(out, f)
			}
		case now.Sub(st.Updated) >= every:
			out = append(out, f)
		}
	}
	return out
}

// LoadCache restores the last good copy of every feed, so protection is
// back before the network is (a Pi often boots without it).
func (m *Manager) LoadCache() {
	for _, f := range m.feeds {
		b, err := os.ReadFile(filepath.Join(m.dir, f.Name+".txt"))
		if err != nil {
			continue
		}
		ps, _ := Parse(strings.NewReader(string(b)), 0)
		ps, _ = Sanitize(ps, m.protected(), m.min4, m.min6)
		st, _ := os.Stat(filepath.Join(m.dir, f.Name+".txt"))
		m.mu.Lock()
		m.current[f.Name] = ps
		m.state[f.Name] = &FeedState{Name: f.Name, Action: f.Action, Entries: len(ps), Updated: st.ModTime()}
		m.mu.Unlock()
	}
	m.rebuild()
}

func (m *Manager) fetch(ctx context.Context, f config.Feed) ([]byte, error) {
	if path, ok := strings.CutPrefix(f.URL, "file://"); ok {
		return os.ReadFile(path)
	}
	if !strings.HasPrefix(f.URL, "https://") {
		return nil, errors.New("feeds must use https:// or file://")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "agentic-firewall/0.1 (+https://github.com/Xipzer/agentic-firewall)")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if len(b) > maxBody {
		return nil, errors.New("feed larger than 32 MiB")
	}
	return b, err
}

// Refresh fetches one feed. It keeps the previous copy when the new one is
// empty or changes too much at once.
func (m *Manager) Refresh(ctx context.Context, f config.Feed) error {
	body, err := m.fetch(ctx, f)
	m.mu.Lock()
	st := m.state[f.Name]
	if st == nil {
		st = &FeedState{Name: f.Name, Action: f.Action}
		m.state[f.Name] = st
	}
	m.mu.Unlock()
	fail := func(err error) error {
		m.mu.Lock()
		st.Error = err.Error()
		// Retry soon (a Pi often boots before its uplink), backing off to the refresh interval.
		st.Failures++
		backoff := time.Duration(1<<min(st.Failures-1, 6)) * 2 * time.Minute
		if r := f.Refresh.D(); r > 0 && backoff > r {
			backoff = r
		}
		if st.Updated.IsZero() {
			st.Updated = time.Now()
		}
		st.NextTry = time.Now().Add(backoff)
		m.mu.Unlock()
		return fmt.Errorf("feed %s: %w", f.Name, err)
	}
	if err != nil {
		return fail(err)
	}
	raw, bad := Parse(strings.NewReader(string(body)), f.MinScore)
	ps, rej := Sanitize(raw, m.protected(), m.min4, m.min6)
	m.mu.Lock()
	prev := m.current[f.Name]
	m.mu.Unlock()
	if len(ps) == 0 {
		return fail(fmt.Errorf("no usable entries (%d unparsed)", bad))
	}
	maxChange := f.MaxChange
	if maxChange == 0 {
		maxChange = 0.5
	}
	if len(prev) >= 100 {
		if c := changeRatio(prev, ps); c > maxChange {
			return fail(fmt.Errorf("refused: %.0f%% of entries changed at once (limit %.0f%%)", c*100, maxChange*100))
		}
	}
	if err := os.MkdirAll(m.dir, 0o750); err == nil {
		var b strings.Builder
		fmt.Fprintf(&b, "# %s fetched %s from %s\n", f.Name, time.Now().UTC().Format(time.RFC3339), f.URL)
		for _, p := range ps {
			b.WriteString(p.String() + "\n")
		}
		tmp := filepath.Join(m.dir, f.Name+".tmp")
		if os.WriteFile(tmp, []byte(b.String()), 0o640) == nil {
			_ = os.Rename(tmp, filepath.Join(m.dir, f.Name+".txt"))
		}
	}
	m.mu.Lock()
	m.current[f.Name] = ps
	*st = FeedState{Name: f.Name, Action: f.Action, Entries: len(ps), Updated: time.Now(), Rejects: rej, Unparsed: bad}
	m.mu.Unlock()
	m.rebuild()
	return nil
}

func changeRatio(a, b []netip.Prefix) float64 {
	in := make(map[netip.Prefix]bool, len(a))
	for _, p := range a {
		in[p] = true
	}
	same := 0
	for _, p := range b {
		if in[p] {
			same++
		}
	}
	diff := (len(a) - same) + (len(b) - same)
	return float64(diff) / float64(max(len(a), len(b)))
}

func (m *Manager) rebuild() {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, b := NewTable(), NewTable()
	for _, f := range m.feeds {
		switch f.Action {
		case "observe":
			w := f.Weight
			if w == 0 {
				w = 0.3
			}
			t.add(f.Name, w, m.current[f.Name])
		case "benign":
			b.add(f.Name, 0, m.current[f.Name])
		}
	}
	m.table.Store(t)
	m.benign.Store(b)
}

// Lists are the kernel-enforced reputation sets.
type Lists struct {
	DropIn, DropOut, ThrottleIn []netip.Prefix
}

func (l Lists) Len() int { return len(l.DropIn) + len(l.DropOut) + len(l.ThrottleIn) }

// Lists builds the kernel sets from drop- and throttle-class feeds, minus protected subjects.
func (m *Manager) Lists() Lists {
	m.mu.Lock()
	defer m.mu.Unlock()
	var l Lists
	for _, f := range m.feeds {
		ps := m.current[f.Name]
		switch {
		case f.Action == "throttle":
			l.ThrottleIn = append(l.ThrottleIn, ps...)
		case f.Action == "drop" && f.Direction == "in":
			l.DropIn = append(l.DropIn, ps...)
		case f.Action == "drop" && f.Direction == "out":
			l.DropOut = append(l.DropOut, ps...)
		case f.Action == "drop":
			l.DropIn = append(l.DropIn, ps...)
			l.DropOut = append(l.DropOut, ps...)
		}
	}
	prot := m.protected()
	clean := func(in []netip.Prefix) []netip.Prefix {
		out := make([]netip.Prefix, 0, len(in))
		for _, p := range in {
			if !netx.Overlaps(p, prot) {
				out = append(out, p)
			}
		}
		return netx.Collapse(out)
	}
	return Lists{DropIn: clean(l.DropIn), DropOut: clean(l.DropOut), ThrottleIn: clean(l.ThrottleIn)}
}

func (m *Manager) States() []FeedState {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FeedState
	for _, f := range m.feeds {
		if st := m.state[f.Name]; st != nil {
			out = append(out, *st)
		} else {
			out = append(out, FeedState{Name: f.Name, Action: f.Action, Error: "not loaded yet"})
		}
	}
	return out
}
