package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/netx"
)

// NFT drives nftables through `nft -f -`. Every change is one atomic
// transaction. All verdict entries carry kernel timeouts, so blocks lapse on
// their own even if afw dies: the system fails open.
type NFT struct {
	Binary       string
	Table        string
	LogGroup     uint16
	LogRate      int
	ThrottleRate string
	// SensitivePorts get a separate sampling budget.
	SensitivePorts []uint16
	Env            []string
	// Run executes an nft script; replaceable in tests.
	Run func(ctx context.Context, script string) ([]byte, error)
	// Query runs nft with args (JSON output); replaceable in tests.
	Query func(ctx context.Context, args ...string) ([]byte, error)

	mu     sync.Mutex
	mirror map[string]map[netip.Prefix]time.Time
}

func NewNFT(binary, table string, logGroup uint16, logRate int, throttleRate string) *NFT {
	n := &NFT{Binary: binary, Table: table, LogGroup: logGroup, LogRate: logRate, ThrottleRate: throttleRate,
		mirror: map[string]map[netip.Prefix]time.Time{}}
	n.Run = func(ctx context.Context, script string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, n.Binary, "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = n.Env
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("nft: %w: %s", err, bytes.TrimSpace(out))
		}
		return out, nil
	}
	n.Query = func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, n.Binary, append([]string{"-j"}, args...)...)
		cmd.Env = n.Env
		return cmd.Output()
	}
	return n
}

var verdictSets = []string{"drop4", "drop6", "thr4", "thr6"}

func setFor(a afp.Action, p netip.Prefix) string {
	fam := "4"
	if p.Addr().Is6() {
		fam = "6"
	}
	if a == afp.ActionDrop {
		return "drop" + fam
	}
	return "thr" + fam
}

var rulesetTmpl = template.Must(template.New("ruleset").Parse(`add table inet {{.T}}
delete table inet {{.T}}
table inet {{.T}} {
	comment "agentic-firewall: every verdict entry expires; delete this table to disable afw"
	set protect4 { type ipv4_addr; flags interval; {{.P4}}}
	set protect6 { type ipv6_addr; flags interval; {{.P6}}}
	set repin4 { type ipv4_addr; flags interval; }
	set repin6 { type ipv6_addr; flags interval; }
	set repout4 { type ipv4_addr; flags interval; }
	set repout6 { type ipv6_addr; flags interval; }
	set repthr4 { type ipv4_addr; flags interval; }
	set repthr6 { type ipv6_addr; flags interval; }
	set drop4 { type ipv4_addr; flags interval,timeout; }
	set drop6 { type ipv6_addr; flags interval,timeout; }
	set thr4 { type ipv4_addr; flags interval,timeout; }
	set thr6 { type ipv6_addr; flags interval,timeout; }
	set thrm4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }
	set thrm6 { type ipv6_addr; size 65535; flags dynamic,timeout; timeout 1m; }
	counter drop_verdict {}
	counter drop_reputation {}
	counter drop_egress {}
	counter throttled {}

	# Before conntrack: reputation drops (curated lists of hijacked or
	# criminal networks) so floods from them never create connection state.
	chain pre {
		type filter hook prerouting priority -300; policy accept;
		ip saddr @protect4 accept
		ip6 saddr @protect6 accept
{{- if not .ObserveOnly}}
		ip saddr @repin4 counter name drop_reputation drop
		ip6 saddr @repin6 counter name drop_reputation drop
		ip daddr @protect4 accept
		ip6 daddr @protect6 accept
		ip daddr @repout4 counter name drop_egress drop
		ip6 daddr @repout6 counter name drop_egress drop
{{- end}}
	}

	# After conntrack. Sampling first, so evidence keeps flowing while a
	# source is restricted. Logins and admin ports get their own sampling
	# budget, so a noise flood cannot blind afw to a brute force.
	#
	# Verdicts act only on connections the subject starts (ct direction
	# original). Replies to connections we start are never touched, so an
	# attacker who gets a shared or spoofed address blocked cannot cut us off
	# from a service we use: the worst outcome is that address cannot open
	# new connections to us.
	chain observe {
		type filter hook prerouting priority -150; policy accept;
{{- if .Sensitive}}
		ct state new tcp dport { {{.Sensitive}} } limit rate {{.SensRate}}/second burst {{.SensRate}} packets log group {{.LogGroup}} snaplen 96
		ct state new meta l4proto { tcp, udp } th dport != { {{.Sensitive}} } limit rate {{.LogRate}}/second burst {{.LogRate}} packets log group {{.LogGroup}} snaplen 96
{{- else}}
		ct state new meta l4proto { tcp, udp } limit rate {{.LogRate}}/second burst {{.LogRate}} packets log group {{.LogGroup}} snaplen 96
{{- end}}
{{- if not .ObserveOnly}}
		ip saddr @protect4 accept
		ip6 saddr @protect6 accept
		ip saddr @drop4 ct direction original counter name drop_verdict drop
		ip6 saddr @drop6 ct direction original counter name drop_verdict drop
		ct state new ip saddr @thr4 add @thrm4 { ip saddr limit rate over {{.Rate}} } counter name throttled drop
		ct state new ip6 saddr @thr6 add @thrm6 { ip6 saddr limit rate over {{.Rate}} } counter name throttled drop
		ct state new ip saddr @repthr4 add @thrm4 { ip saddr limit rate over {{.Rate}} } counter name throttled drop
		ct state new ip6 saddr @repthr6 add @thrm6 { ip6 saddr limit rate over {{.Rate}} } counter name throttled drop
{{- end}}
	}

	chain egress {
		type filter hook output priority -300; policy accept;
		ip daddr @protect4 accept
		ip6 daddr @protect6 accept
{{- if not .ObserveOnly}}
		ip daddr @repout4 counter name drop_egress drop
		ip6 daddr @repout6 counter name drop_egress drop
{{- end}}
	}
}
`))

func elements(ps []netip.Prefix) string {
	if len(ps) == 0 {
		return ""
	}
	ss := make([]string, len(ps))
	for i, p := range ps {
		ss[i] = elem(p)
	}
	return "elements = { " + strings.Join(ss, ", ") + " }; "
}

func elem(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

func split(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range netx.Collapse(ps) {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

// Ruleset renders the full table definition.
func (n *NFT) Ruleset(protected []netip.Prefix, observeOnly bool) string {
	p4, p6 := split(protected)
	rate := n.ThrottleRate
	if rate == "" {
		rate = "5/second"
	}
	var ports []string
	for _, p := range n.SensitivePorts {
		ports = append(ports, fmt.Sprint(p))
	}
	sensRate := max(n.LogRate/4, 50)
	var b strings.Builder
	_ = rulesetTmpl.Execute(&b, map[string]any{"T": n.Table, "P4": elements(p4), "P6": elements(p6),
		"ObserveOnly": observeOnly, "LogGroup": n.LogGroup, "LogRate": n.LogRate, "Rate": rate,
		"Sensitive": strings.Join(ports, ", "), "SensRate": sensRate})
	return b.String()
}

func (n *NFT) Setup(ctx context.Context, protected []netip.Prefix, observeOnly bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	keep, _ := n.readSets(ctx) // carry live verdicts across restarts
	var b strings.Builder
	b.WriteString(n.Ruleset(protected, observeOnly))
	now := time.Now()
	n.mirror = map[string]map[netip.Prefix]time.Time{}
	if !observeOnly {
		for set, m := range keep {
			for p, until := range m {
				if ttl := until.Sub(now); ttl >= time.Second && !netx.Overlaps(p, protected) {
					fmt.Fprintf(&b, "add element inet %s %s { %s timeout %ds }\n", n.Table, set, elem(p), int(ttl.Seconds()))
					n.track(set, p, until)
				}
			}
		}
	}
	_, err := n.Run(ctx, b.String())
	return err
}

func (n *NFT) track(set string, p netip.Prefix, until time.Time) {
	if n.mirror[set] == nil {
		n.mirror[set] = map[netip.Prefix]time.Time{}
	}
	n.mirror[set][p] = until
}

// plan writes the commands for entries against the mirror, resolving
// interval overlaps the kernel would otherwise reject.
func (n *NFT) plan(entries []Entry, now time.Time) (string, func()) {
	var b strings.Builder
	type change struct {
		set   string
		p     netip.Prefix
		until time.Time
		del   bool
	}
	var changes []change
	shadow := map[string]map[netip.Prefix]time.Time{}
	view := func(set string) map[netip.Prefix]time.Time {
		if m, ok := shadow[set]; ok {
			return m
		}
		m := map[netip.Prefix]time.Time{}
		for p, t := range n.mirror[set] {
			if now.Before(t) {
				m[p] = t
			}
		}
		shadow[set] = m
		return m
	}
	for _, e := range entries {
		if e.Action != afp.ActionDrop && e.Action != afp.ActionThrottle {
			continue
		}
		set := setFor(e.Action, e.Prefix)
		m := view(set)
		until := now.Add(e.TTL)
		covered := false
		for p, t := range m {
			switch {
			case p == e.Prefix:
				changes = append(changes, change{set, p, t, true})
				delete(m, p)
			case p.Bits() < e.Prefix.Bits() && p.Contains(e.Prefix.Addr()):
				// Already covered by a wider entry. The kernel rejects overlapping
				// intervals, and splitting the wider entry is not worth the risk.
				covered = true
			case e.Prefix.Bits() < p.Bits() && e.Prefix.Contains(p.Addr()):
				changes = append(changes, change{set, p, t, true})
				delete(m, p)
			}
		}
		if covered {
			continue
		}
		m[e.Prefix] = until
		changes = append(changes, change{set, e.Prefix, until, false})
	}
	for _, c := range changes {
		if c.del {
			fmt.Fprintf(&b, "delete element inet %s %s { %s }\n", n.Table, c.set, elem(c.p))
		} else {
			secs := int(c.until.Sub(now).Round(time.Second).Seconds())
			if secs < 1 {
				secs = 1
			}
			fmt.Fprintf(&b, "add element inet %s %s { %s timeout %ds }\n", n.Table, c.set, elem(c.p), secs)
		}
	}
	commit := func() {
		for set, m := range shadow {
			n.mirror[set] = m
		}
	}
	return b.String(), commit
}

func (n *NFT) Apply(ctx context.Context, entries []Entry) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	for attempt := 0; ; attempt++ {
		script, commit := n.plan(entries, time.Now())
		if script == "" {
			return nil
		}
		_, err := n.Run(ctx, script)
		if err == nil {
			commit()
			return nil
		}
		if attempt == 1 {
			return err
		}
		// Most likely an entry expired in the kernel between plan and run. Resync and retry once.
		if m, rerr := n.readSets(ctx); rerr == nil {
			n.mirror = m
		}
	}
}

func (n *NFT) Remove(ctx context.Context, ps []netip.Prefix) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if m, err := n.readSets(ctx); err == nil {
		n.mirror = m
	}
	var b strings.Builder
	for _, set := range verdictSets {
		for p := range n.mirror[set] {
			for _, q := range ps {
				if p.Overlaps(q) {
					fmt.Fprintf(&b, "delete element inet %s %s { %s }\n", n.Table, set, elem(p))
					delete(n.mirror[set], p)
					break
				}
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	_, err := n.Run(ctx, b.String())
	return err
}

func (n *NFT) replaceSets(ctx context.Context, name string, ps []netip.Prefix) error {
	_, err := n.Run(ctx, n.setScript(name, ps))
	return err
}

// setScript flushes and refills name4/name6 in one transaction.
func (n *NFT) setScript(name string, ps []netip.Prefix) string {
	v4, v6 := split(ps)
	var b strings.Builder
	for _, x := range []struct {
		set string
		ps  []netip.Prefix
	}{{name + "4", v4}, {name + "6", v6}} {
		fmt.Fprintf(&b, "flush set inet %s %s\n", n.Table, x.set)
		for i := 0; i < len(x.ps); i += 512 {
			chunk := x.ps[i:min(i+512, len(x.ps))]
			ss := make([]string, len(chunk))
			for j, p := range chunk {
				ss[j] = elem(p)
			}
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", n.Table, x.set, strings.Join(ss, ", "))
		}
	}
	return b.String()
}

func (n *NFT) ReplaceReputation(ctx context.Context, r Reputation) error {
	var b strings.Builder
	b.WriteString(n.setScript("repin", r.DropIn))
	b.WriteString(n.setScript("repout", r.DropOut))
	b.WriteString(n.setScript("repthr", r.ThrottleIn))
	_, err := n.Run(ctx, b.String())
	return err
}

func (n *NFT) SetProtected(ctx context.Context, ps []netip.Prefix) error {
	return n.replaceSets(ctx, "protect", ps)
}

func (n *NFT) Flush(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var b strings.Builder
	for _, set := range append(verdictSets, "repin4", "repin6", "repout4", "repout6", "repthr4", "repthr6", "thrm4", "thrm6") {
		fmt.Fprintf(&b, "flush set inet %s %s\n", n.Table, set)
	}
	n.mirror = map[string]map[netip.Prefix]time.Time{}
	_, err := n.Run(ctx, b.String())
	return err
}

func (n *NFT) Teardown(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mirror = map[string]map[netip.Prefix]time.Time{}
	_, err := n.Run(ctx, fmt.Sprintf("add table inet %s\ndelete table inet %s\n", n.Table, n.Table))
	return err
}

type nftJSON struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftSet struct {
	Name string            `json:"name"`
	Elem []json.RawMessage `json:"elem"`
}

type nftElem struct {
	Elem struct {
		Val     json.RawMessage `json:"val"`
		Expires float64         `json:"expires"`
	} `json:"elem"`
}

func parseVal(raw json.RawMessage) (netip.Prefix, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		p, err := netx.ParsePrefixOrAddr(s)
		return p, err == nil
	}
	var pv struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &pv) == nil && pv.Prefix.Addr != "" {
		p, err := netx.ParsePrefixOrAddr(fmt.Sprintf("%s/%d", pv.Prefix.Addr, pv.Prefix.Len))
		return p, err == nil
	}
	return netip.Prefix{}, false
}

// readSets loads live verdict entries and their remaining lifetime from the kernel.
func (n *NFT) readSets(ctx context.Context) (map[string]map[netip.Prefix]time.Time, error) {
	out, err := n.Query(ctx, "list", "table", "inet", n.Table)
	if err != nil {
		return nil, err
	}
	var doc nftJSON
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	now := time.Now()
	res := map[string]map[netip.Prefix]time.Time{}
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var s nftSet
		if json.Unmarshal(raw, &s) != nil || !strings.HasPrefix(s.Name, "drop") && !strings.HasPrefix(s.Name, "thr") || strings.HasPrefix(s.Name, "thrm") {
			continue
		}
		for _, e := range s.Elem {
			var el nftElem
			if json.Unmarshal(e, &el) != nil {
				continue
			}
			if p, ok := parseVal(el.Elem.Val); ok && el.Elem.Expires > 0 {
				if res[s.Name] == nil {
					res[s.Name] = map[netip.Prefix]time.Time{}
				}
				res[s.Name][p] = now.Add(time.Duration(el.Elem.Expires * float64(time.Second)))
			}
		}
	}
	return res, nil
}

func (n *NFT) Stats(ctx context.Context) (map[string]uint64, error) {
	out, err := n.Query(ctx, "list", "counters", "table", "inet", n.Table)
	if err != nil {
		return nil, err
	}
	var doc nftJSON
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	res := map[string]uint64{}
	for _, obj := range doc.Nftables {
		var c struct {
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
		}
		if raw, ok := obj["counter"]; ok && json.Unmarshal(raw, &c) == nil {
			res[c.Name+"_packets"] = c.Packets
		}
	}
	n.mu.Lock()
	now := time.Now()
	sets := make([]string, 0, len(n.mirror))
	for s := range n.mirror {
		sets = append(sets, s)
	}
	sort.Strings(sets)
	for _, s := range sets {
		for _, t := range n.mirror[s] {
			if now.Before(t) {
				res["active_"+s]++
			}
		}
	}
	n.mu.Unlock()
	return res, nil
}
