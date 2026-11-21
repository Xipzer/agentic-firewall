// Package config loads and validates the afw configuration.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Xipzer/agentic-firewall/internal/netx"
)

// Duration is a time.Duration that reads "10m"-style YAML values.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	Node string `yaml:"node"`
	// Role selects defaults. "host" protects this machine, "gateway" protects
	// everything routed through it. The engine, ruleset and protocol are the same.
	Role string `yaml:"role"`
	// Mode "shadow" logs what would happen and enforces nothing. "enforce" acts.
	Mode string `yaml:"mode"`
	// Probation disarms enforcement automatically unless `afw confirm` is run
	// within this window after start. 0 disables it.
	Probation Duration `yaml:"probation"`

	Protected      []string `yaml:"protected"`
	AutoProtect    *bool    `yaml:"auto_protect"`
	Internal       []string `yaml:"internal"`
	InternalMax    string   `yaml:"internal_max_action"`
	SensitivePorts []uint16 `yaml:"sensitive_ports"`
	ServicePorts   []uint16 `yaml:"service_ports"`
	MaxSubjects    int      `yaml:"max_subjects"`
	Heuristics     Heuristics
	Policy         Policy
	Budget         Budget
	BreakGlass     BreakGlass `yaml:"breakglass"`
	Analyst        Analyst
	Canary         Canary
	Feeds          []Feed
	Crosstalk      Crosstalk
	Log            Log
	NFT            NFT
	ControlSocket  string `yaml:"control_socket"`
	StateDir       string `yaml:"state_dir"`
	protected      []netip.Prefix
	internal       []netip.Prefix
}

type Heuristics struct {
	Window          Duration `yaml:"window"`
	LongWindow      Duration `yaml:"long_window"`
	HandshakeWait   Duration `yaml:"handshake_wait"`
	ShortSession    Duration `yaml:"short_session"`
	RateWarn        float64  `yaml:"rate_warn"`
	RateHigh        float64  `yaml:"rate_high"`
	PortsWarn       int      `yaml:"ports_warn"`
	PortsHigh       int      `yaml:"ports_high"`
	PortsLongHigh   int      `yaml:"ports_long_high"`
	HostsWarn       int      `yaml:"hosts_warn"`
	HostsHigh       int      `yaml:"hosts_high"`
	FailMin         int      `yaml:"handshake_fail_min"`
	ShortWarn       int      `yaml:"short_sessions_warn"`
	ShortHigh       int      `yaml:"short_sessions_high"`
	AggregateFactor float64  `yaml:"aggregate_factor"`
}

type Policy struct {
	Observe       float64  `yaml:"observe"`
	Throttle      float64  `yaml:"throttle"`
	Drop          float64  `yaml:"drop"`
	ThrottleRate  string   `yaml:"throttle_rate"`
	BaseTTL       Duration `yaml:"base_ttl"`
	MaxTTL        Duration `yaml:"max_ttl"`
	TTLMultiplier float64  `yaml:"ttl_multiplier"`
	MinPrefix4    int      `yaml:"min_prefix_v4"`
	MinPrefix6    int      `yaml:"min_prefix_v6"`
}

type Budget struct {
	PerMinute int `yaml:"per_minute"`
	MaxActive int `yaml:"max_active"`
}

// BreakGlass controls the emergency posture: under a flood that hurts the
// service, known-good sources keep full access and newcomers share a capped lane.
type BreakGlass struct {
	Auto          bool     `yaml:"auto"`
	MinRate       float64  `yaml:"min_rate"`
	Surge         float64  `yaml:"surge"`
	AbsRate       float64  `yaml:"abs_rate"`
	FailRatio     float64  `yaml:"fail_ratio"`
	Hold          Duration `yaml:"hold"`
	ManualHold    Duration `yaml:"manual_hold"`
	NewcomerRate  int      `yaml:"newcomer_rate"`
	PerSourceRate string   `yaml:"per_source_rate"`
	Sensitivity   float64  `yaml:"sensitivity"`
	BudgetFactor  float64  `yaml:"budget_factor"`
}

// Canary configures decoy ports: ports nothing on this machine serves. Any
// completed connection to one is proven evidence of probing, and the
// connection is tarpitted. Off unless ports are listed.
type Canary struct {
	Ports    []uint16 `yaml:"ports"`
	Listen   string   `yaml:"listen"`
	Hold     Duration `yaml:"hold"`
	MaxConns int      `yaml:"max_connections"`
}

// Analyst rations model attention (the slow tier) so that escalation floods
// cannot run up token costs. Humans are never rationed.
type Analyst struct {
	PerHour        int      `yaml:"per_hour"`
	PerDay         int      `yaml:"per_day"`
	IncidentWindow Duration `yaml:"incident_window"`
	// Socket is the adviser's only door into afw: it can read redacted
	// briefings and submit proposals, nothing else. Empty turns it off.
	Socket string `yaml:"socket"`
	// Provider labels whoever answers on that socket (a model, local or remote).
	Provider string `yaml:"provider"`
	// Trust scales the adviser's confidence. Its evidence always counts as
	// unproven, so whatever the value it can slow a source but never block one.
	Trust            float64 `yaml:"trust"`
	ProposalsPerHour int     `yaml:"proposals_per_hour"`
}

type Feed struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Format string `yaml:"format"`
	// Action is drop, throttle, observe (adds to the fast-tier score) or
	// benign (known research scanners: never escalated).
	Action string `yaml:"action"`
	// Direction is in (source of inbound traffic), out (destination of
	// outbound traffic) or both. Lists built from attack reports contain CDN
	// and cloud addresses, so they must stay inbound-only.
	Direction string   `yaml:"direction"`
	MinScore  int      `yaml:"min_score"`
	Refresh   Duration `yaml:"refresh"`
	Weight    float64  `yaml:"weight"`
	// MaxChange rejects a refresh that changes more than this fraction of
	// entries at once, a guard against a poisoned or broken upstream.
	MaxChange float64 `yaml:"max_change"`
}

type Crosstalk struct {
	Listen    string   `yaml:"listen"`
	Peers     []Peer   `yaml:"peers"`
	KeyFile   string   `yaml:"key_file"`
	MaxSkew   Duration `yaml:"max_skew"`
	MaxTTL    Duration `yaml:"max_ttl"`
	PerMinute int      `yaml:"per_minute"`
}

type Peer struct {
	Node  string  `yaml:"node"`
	URL   string  `yaml:"url"`
	Trust float64 `yaml:"trust"`
}

type Log struct {
	Path         string `yaml:"path"`
	MaxMB        int    `yaml:"max_mb"`
	Keep         int    `yaml:"keep"`
	Observations string `yaml:"observations"`
}

type NFT struct {
	Binary   string `yaml:"binary"`
	Table    string `yaml:"table"`
	LogGroup uint16 `yaml:"log_group"`
	LogRate  int    `yaml:"log_rate"`
	OnExit   string `yaml:"on_exit"`
}

func Default() Config {
	return Config{
		Node:           hostname(),
		Role:           "host",
		Mode:           "shadow",
		Probation:      Duration(15 * time.Minute),
		InternalMax:    "observe",
		SensitivePorts: []uint16{21, 22, 23, 445, 1433, 2323, 3306, 3389, 5432, 5900, 6379, 8291, 9200, 27017},
		MaxSubjects:    32768,
		Heuristics: Heuristics{
			Window: Duration(10 * time.Second), LongWindow: Duration(10 * time.Minute),
			HandshakeWait: Duration(3 * time.Second), ShortSession: Duration(5 * time.Second),
			RateWarn: 5, RateHigh: 50,
			PortsWarn: 8, PortsHigh: 64, PortsLongHigh: 128,
			HostsWarn: 8, HostsHigh: 64,
			FailMin: 10, ShortWarn: 6, ShortHigh: 40,
			AggregateFactor: 4,
		},
		Policy: Policy{
			Observe: 0.35, Throttle: 0.6, Drop: 0.85, ThrottleRate: "5/second",
			BaseTTL: Duration(10 * time.Minute), MaxTTL: Duration(24 * time.Hour), TTLMultiplier: 4,
			MinPrefix4: 16, MinPrefix6: 32,
		},
		Budget: Budget{PerMinute: 60, MaxActive: 4096},
		BreakGlass: BreakGlass{Auto: true, MinRate: 100, Surge: 5, AbsRate: 2000, FailRatio: 0.6,
			Hold: Duration(10 * time.Minute), ManualHold: Duration(time.Hour), NewcomerRate: 200,
			PerSourceRate: "2/second", Sensitivity: 2, BudgetFactor: 4},
		Analyst: Analyst{PerHour: 10, PerDay: 50, IncidentWindow: Duration(30 * time.Minute),
			Provider: "analyst", Trust: 0.6, ProposalsPerHour: 30},
		Crosstalk:     Crosstalk{MaxSkew: Duration(2 * time.Minute), MaxTTL: Duration(time.Hour), PerMinute: 120},
		Log:           Log{Path: "/var/log/afw/afw.jsonl", MaxMB: 50, Keep: 5, Observations: "evidence"},
		NFT:           NFT{Binary: "nft", Table: "afw", LogGroup: 7, LogRate: 1000, OnExit: "keep"},
		ControlSocket: "/run/afw/afw.sock",
		StateDir:      "/var/lib/afw",
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "afw"
	}
	return h
}

// Load reads a YAML file over the defaults. An empty path gives defaults.
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		dec := yaml.NewDecoder(bytesReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil && err.Error() != "EOF" {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	var errs []error
	if c.Role != "host" && c.Role != "gateway" {
		errs = append(errs, fmt.Errorf("role %q: want host or gateway", c.Role))
	}
	if c.Mode != "shadow" && c.Mode != "enforce" {
		errs = append(errs, fmt.Errorf("mode %q: want shadow or enforce", c.Mode))
	}
	switch c.InternalMax {
	case "observe", "throttle", "drop":
	default:
		errs = append(errs, fmt.Errorf("internal_max_action %q", c.InternalMax))
	}
	p := c.Policy
	if !(0 < p.Observe && p.Observe < p.Throttle && p.Throttle < p.Drop && p.Drop <= 1) {
		errs = append(errs, errors.New("policy thresholds must satisfy 0 < observe < throttle < drop <= 1"))
	}
	if p.BaseTTL <= 0 || p.MaxTTL < p.BaseTTL {
		errs = append(errs, errors.New("policy ttl: need 0 < base_ttl <= max_ttl"))
	}
	if p.MaxTTL.D() > 7*24*time.Hour {
		errs = append(errs, errors.New("policy max_ttl over 7d: long blocks belong to a reviewed policy, not an agent"))
	}
	if p.MinPrefix4 < 8 || p.MinPrefix6 < 16 {
		errs = append(errs, errors.New("min_prefix too wide"))
	}
	if c.Budget.PerMinute <= 0 || c.Budget.MaxActive <= 0 {
		errs = append(errs, errors.New("budget must be positive"))
	}
	if b := c.BreakGlass; b.MinRate <= 0 || b.Surge < 1.5 || b.AbsRate <= b.MinRate || b.FailRatio <= 0 || b.FailRatio > 1 ||
		b.Hold <= 0 || b.NewcomerRate <= 0 || b.Sensitivity < 1 || b.BudgetFactor < 1 || b.BudgetFactor > 20 {
		errs = append(errs, errors.New("breakglass: need min_rate > 0, surge >= 1.5, abs_rate > min_rate, 0 < fail_ratio <= 1, hold > 0, newcomer_rate > 0, sensitivity >= 1, 1 <= budget_factor <= 20"))
	}
	if c.Analyst.PerHour < 0 || c.Analyst.PerDay < c.Analyst.PerHour || c.Analyst.IncidentWindow <= 0 {
		errs = append(errs, errors.New("analyst: need 0 <= per_hour <= per_day and incident_window > 0"))
	}
	if a := c.Analyst; a.Trust < 0 || a.Trust > 1 || a.ProposalsPerHour < 0 || a.Provider == "" {
		errs = append(errs, errors.New("analyst: need 0 <= trust <= 1, proposals_per_hour >= 0 and a provider label"))
	}
	if c.Analyst.Socket != "" && c.Analyst.Socket == c.ControlSocket {
		errs = append(errs, errors.New("analyst: the adviser socket must not be the admin control socket"))
	}
	if c.Canary.Hold < 0 || c.Canary.Hold.D() > 5*time.Minute || c.Canary.MaxConns < 0 || c.Canary.MaxConns > 4096 {
		errs = append(errs, errors.New("canary: need 0 <= hold <= 5m and 0 <= max_connections <= 4096"))
	}
	for _, cp := range c.Canary.Ports {
		for _, sp := range c.ServicePorts {
			if cp == sp {
				errs = append(errs, fmt.Errorf("canary: port %d is listed as a service port; a decoy must be a port nothing uses", cp))
			}
		}
		if cp == 0 {
			errs = append(errs, errors.New("canary: port 0 is not valid"))
		}
	}
	if c.MaxSubjects < 128 {
		errs = append(errs, errors.New("max_subjects must be at least 128"))
	}
	for _, f := range c.Feeds {
		if f.Name == "" || f.URL == "" {
			errs = append(errs, errors.New("feed needs name and url"))
		}
		switch f.Action {
		case "drop", "throttle", "observe", "benign":
		default:
			errs = append(errs, fmt.Errorf("feed %s: action %q, want drop, throttle, observe or benign", f.Name, f.Action))
		}
		switch f.Direction {
		case "", "in", "out", "both":
		default:
			errs = append(errs, fmt.Errorf("feed %s: direction %q, want in, out or both", f.Name, f.Direction))
		}
		if f.Action == "throttle" && f.Direction != "" && f.Direction != "in" {
			errs = append(errs, fmt.Errorf("feed %s: throttle only applies inbound", f.Name))
		}
	}
	for _, peer := range c.Crosstalk.Peers {
		if peer.Trust < 0 || peer.Trust > 1 {
			errs = append(errs, fmt.Errorf("peer %s trust out of [0,1]", peer.Node))
		}
	}
	if len(c.Crosstalk.Peers) > 0 && c.Crosstalk.KeyFile == "" {
		errs = append(errs, errors.New("crosstalk peers need key_file"))
	}
	var err error
	if c.protected, err = parseList(c.Protected); err != nil {
		errs = append(errs, fmt.Errorf("protected: %w", err))
	}
	internal := c.Internal
	if len(internal) == 0 {
		for _, p := range netx.Private {
			internal = append(internal, p.String())
		}
	}
	if c.internal, err = parseList(internal); err != nil {
		errs = append(errs, fmt.Errorf("internal: %w", err))
	}
	return errors.Join(errs...)
}

func parseList(ss []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netx.ParsePrefixOrAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (c *Config) ProtectedPrefixes() []netip.Prefix { return c.protected }
func (c *Config) InternalPrefixes() []netip.Prefix  { return c.internal }

// AddProtected appends auto-detected protected subjects.
func (c *Config) AddProtected(ps ...netip.Prefix) { c.protected = append(c.protected, ps...) }

func (c *Config) AutoProtectEnabled() bool { return c.AutoProtect == nil || *c.AutoProtect }
