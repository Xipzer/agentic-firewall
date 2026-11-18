package fast

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
)

type Kind uint8

const (
	KindNew Kind = iota + 1
	KindEstablished
	KindEnd
)

func (k Kind) String() string {
	switch k {
	case KindNew:
		return "new"
	case KindEstablished:
		return "established"
	case KindEnd:
		return "destroy"
	}
	return "unknown"
}

const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

func protoName(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return fmt.Sprint(p)
}

func protoNum(s string) uint8 {
	switch strings.ToLower(s) {
	case "tcp":
		return ProtoTCP
	case "udp":
		return ProtoUDP
	case "icmp":
		return ProtoICMP
	case "icmpv6":
		return ProtoICMPv6
	}
	var n uint8
	_, _ = fmt.Sscan(s, &n)
	return n
}

// Event is one flow lifecycle step reported by a sensor. Src is always the
// initiator of the flow (conntrack's original direction).
type Event struct {
	Time    time.Time
	Kind    Kind
	Proto   uint8
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Bytes   uint64
	Packets uint64
	Sampled bool
	// Assured is set on End events when conntrack saw the handshake complete.
	Assured bool
}

type flowKey struct {
	proto    uint8
	src, dst netip.AddrPort
}

func (e Event) key() flowKey {
	return flowKey{e.Proto, unmapAP(e.Src), unmapAP(e.Dst)}
}

func unmapAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Observation converts an event to its AFP form.
func (e Event) Observation(src afp.Source, dir Direction) *afp.Observation {
	o := &afp.Observation{Envelope: afp.NewEnvelope(afp.TypeObservation, src), Event: e.Kind.String(),
		Flow: &afp.Flow{Src: unmapAP(e.Src).String(), Dst: unmapAP(e.Dst).String(), Proto: protoName(e.Proto),
			Bytes: e.Bytes, Packets: e.Packets, Direction: dir.String()}}
	o.TS = e.Time.UTC()
	if e.Sampled {
		o.Context = map[string]any{"sampled": true}
	}
	return o
}

// EventFromObservation is the inverse, used by replay.
func EventFromObservation(o *afp.Observation) (Event, error) {
	if o.Flow == nil {
		return Event{}, fmt.Errorf("%s: no flow", o.ID)
	}
	src, err := parseEndpoint(o.Flow.Src)
	if err != nil {
		return Event{}, err
	}
	dst, err := parseEndpoint(o.Flow.Dst)
	if err != nil {
		return Event{}, err
	}
	k := map[string]Kind{"new": KindNew, "established": KindEstablished, "destroy": KindEnd}[o.Event]
	if k == 0 {
		k = KindNew
	}
	return Event{Time: o.TS, Kind: k, Proto: protoNum(o.Flow.Proto), Src: src, Dst: dst,
		Bytes: o.Flow.Bytes, Packets: o.Flow.Packets}, nil
}

func parseEndpoint(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, 0), nil
}

type Direction uint8

const (
	DirUnknown Direction = iota
	DirInbound
	DirOutbound
	DirInternal
	DirLocal
	DirTransit
)

func (d Direction) String() string {
	return [...]string{"", "inbound", "outbound", "internal", "local", "transit"}[d]
}
