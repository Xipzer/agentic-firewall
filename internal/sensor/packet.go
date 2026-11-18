// Package sensor turns kernel signals into fast-tier events.
package sensor

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/fast"
)

var errShort = errors.New("short packet")

// ParsePacket reads the 5-tuple from a raw IPv4 or IPv6 packet, as delivered
// by NFLOG from the prerouting hook (payload starts at the network header).
func ParsePacket(b []byte, t time.Time) (fast.Event, error) {
	if len(b) < 1 {
		return fast.Event{}, errShort
	}
	var src, dst netip.Addr
	var proto uint8
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return fast.Event{}, errShort
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return fast.Event{}, errShort
		}
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return fast.Event{}, errors.New("non-first fragment")
		}
		proto = b[9]
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		l4 = b[ihl:]
	case 6:
		if len(b) < 40 {
			return fast.Event{}, errShort
		}
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		next, off := b[6], 40
		for i := 0; i < 8; i++ {
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(b) < off+2 {
					return fast.Event{}, errShort
				}
				next, off = b[off], off+(int(b[off+1])+1)*8
				continue
			case 44: // fragment
				if len(b) < off+8 {
					return fast.Event{}, errShort
				}
				if binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
					return fast.Event{}, errors.New("non-first fragment")
				}
				next, off = b[off], off+8
				continue
			}
			break
		}
		if off > len(b) {
			return fast.Event{}, errShort
		}
		proto, l4 = next, b[off:]
	default:
		return fast.Event{}, errors.New("not ip")
	}
	var sp, dp uint16
	if proto == fast.ProtoTCP || proto == fast.ProtoUDP {
		if len(l4) < 4 {
			return fast.Event{}, errShort
		}
		sp, dp = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	}
	return fast.Event{Time: t, Kind: fast.KindNew, Proto: proto, Src: netip.AddrPortFrom(src, sp),
		Dst: netip.AddrPortFrom(dst, dp), Sampled: true}, nil
}
