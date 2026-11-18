// Package afp implements the Agentic Firewall Protocol v0.1 message types.
// The JSON Schemas in spec/afp/0.1 are normative; these types mirror them.
package afp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1"

type Type string

const (
	TypeObservation Type = "observation"
	TypeVerdict     Type = "verdict"
	TypeEscalation  Type = "escalation"
	TypeRule        Type = "rule"
	TypeExplanation Type = "explanation"
)

type Tier string

const (
	TierDataplane Tier = "dataplane"
	TierFast      Tier = "fast"
	TierMedium    Tier = "medium"
	TierSlow      Tier = "slow"
	TierHuman     Tier = "human"
	TierPeer      Tier = "peer"
)

type Action string

const (
	ActionAllow      Action = "allow"
	ActionObserve    Action = "observe"
	ActionThrottle   Action = "throttle"
	ActionDrop       Action = "drop"
	ActionReroute    Action = "reroute"
	ActionQuarantine Action = "quarantine"
)

// Severity orders actions from least to most disruptive. Allow is special:
// it lifts other actions on the subject rather than ranking below them.
func (a Action) Severity() int {
	switch a {
	case ActionObserve:
		return 1
	case ActionThrottle:
		return 2
	case ActionReroute:
		return 3
	case ActionDrop:
		return 4
	case ActionQuarantine:
		return 5
	}
	return 0
}

func (a Action) Valid() bool { return a == ActionAllow || a.Severity() > 0 }

type Source struct {
	Tier  Tier   `json:"tier"`
	Agent string `json:"agent"`
	Node  string `json:"node,omitempty"`
}

// Envelope is shared by every AFP message.
type Envelope struct {
	AFP    string    `json:"afp"`
	Type   Type      `json:"type"`
	ID     string    `json:"id"`
	TS     time.Time `json:"ts"`
	Source Source    `json:"source"`
}

func NewEnvelope(t Type, src Source) Envelope {
	return Envelope{AFP: Version, Type: t, ID: NewID(t), TS: time.Now().UTC(), Source: src}
}

var idPrefix = map[Type]string{
	TypeObservation: "obs", TypeVerdict: "ver", TypeEscalation: "esc", TypeRule: "rule", TypeExplanation: "exp",
}

// NewID returns a prefixed, time-sortable random identifier.
func NewID(t Type) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s_%x%s", idPrefix[t], time.Now().UnixMilli(), hex.EncodeToString(b[:]))
}

type SubjectKind string

const (
	SubjectHost   SubjectKind = "host"
	SubjectPrefix SubjectKind = "prefix"
	SubjectFlow   SubjectKind = "flow"
)

type Subject struct {
	Kind  SubjectKind `json:"kind"`
	Value string      `json:"value"`
}

func HostSubject(a netip.Addr) Subject { return Subject{SubjectHost, a.Unmap().String()} }

// Prefix returns the subject as a prefix (a host is a /32 or /128).
func (s Subject) Prefix() (netip.Prefix, error) {
	switch s.Kind {
	case SubjectHost:
		a, err := netip.ParseAddr(s.Value)
		if err != nil {
			return netip.Prefix{}, err
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	case SubjectPrefix:
		p, err := netip.ParsePrefix(s.Value)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	return netip.Prefix{}, fmt.Errorf("subject kind %q has no prefix form", s.Kind)
}

type Flow struct {
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Proto     string `json:"proto"`
	Bytes     uint64 `json:"bytes,omitempty"`
	Packets   uint64 `json:"packets,omitempty"`
	State     string `json:"state,omitempty"`
	Direction string `json:"direction,omitempty"`
}

type Observation struct {
	Envelope
	Event   string         `json:"event,omitempty"`
	Flow    *Flow          `json:"flow,omitempty"`
	Context map[string]any `json:"context,omitempty"`
}

// Signal is one piece of evidence behind a verdict.
type Signal struct {
	Name      string  `json:"name"`
	Weight    float64 `json:"weight"`
	Spoofable bool    `json:"spoofable,omitempty"`
	Detail    string  `json:"detail,omitempty"`
}

type Verdict struct {
	Envelope
	Subject    Subject        `json:"subject"`
	Action     Action         `json:"action"`
	Params     map[string]any `json:"params,omitempty"`
	Confidence float64        `json:"confidence"`
	TTL        string         `json:"ttl,omitempty"`
	Reason     string         `json:"reason"`
	Escalate   bool           `json:"escalate,omitempty"`
	Mode       string         `json:"mode,omitempty"`
	Signals    []Signal       `json:"signals,omitempty"`
	Refs       []string       `json:"refs,omitempty"`
	// Class names the attack using the dotted taxonomy (e.g. "recon.scan.vertical").
	Class string `json:"class,omitempty"`
	// Posture is the node's defence posture when the verdict was made.
	Posture string `json:"posture,omitempty"`
	// Hops counts how many nodes relayed this verdict. Peers never relay a
	// verdict whose Hops is already non-zero, which bounds crosstalk loops.
	Hops int `json:"hops,omitempty"`
}

type Escalation struct {
	Envelope
	Subject  Subject        `json:"subject"`
	Refs     []string       `json:"refs"`
	Question string         `json:"question"`
	Priority string         `json:"priority"`
	Deadline string         `json:"deadline,omitempty"`
	Target   Tier           `json:"target,omitempty"`
	Class    string         `json:"class,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

type Provenance struct {
	Incident    string   `json:"incident,omitempty"`
	Explanation string   `json:"explanation,omitempty"`
	Verdicts    []string `json:"verdicts,omitempty"`
}

type Rule struct {
	Envelope
	Match      map[string]any `json:"match"`
	Action     Action         `json:"action"`
	Params     map[string]any `json:"params,omitempty"`
	TTL        string         `json:"ttl"`
	Priority   int            `json:"priority,omitempty"`
	Provenance Provenance     `json:"provenance"`
}

type Evidence struct {
	Ref  string `json:"ref,omitempty"`
	Note string `json:"note"`
}

type Explanation struct {
	Envelope
	About      string     `json:"about"`
	Summary    string     `json:"summary"`
	Evidence   []Evidence `json:"evidence,omitempty"`
	Confidence float64    `json:"confidence,omitempty"`
}

// ParseTTL accepts Go durations plus a "d" (day) suffix, e.g. "10m", "24h", "7d".
func ParseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty ttl")
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseFloat(n, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("bad ttl %q", s)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad ttl %q", s)
	}
	return d, nil
}

// FormatTTL renders a duration in the compact form ParseTTL accepts.
func FormatTTL(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

// Decode parses any AFP message and validates it.
func Decode(b []byte) (any, error) {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	var msg interface{ Validate() error }
	switch env.Type {
	case TypeObservation:
		msg = &Observation{}
	case TypeVerdict:
		msg = &Verdict{}
	case TypeEscalation:
		msg = &Escalation{}
	case TypeRule:
		msg = &Rule{}
	case TypeExplanation:
		msg = &Explanation{}
	default:
		return nil, fmt.Errorf("unknown afp type %q", env.Type)
	}
	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}
	return msg, msg.Validate()
}
