//go:build linux

package sensor

import (
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/ti-mo/conntrack"
)

// ConntrackFill reads how full the kernel connection table is (0..1).
func ConntrackFill() float64 {
	read := func(name string) float64 {
		b, err := os.ReadFile("/proc/sys/net/netfilter/" + name)
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		return v
	}
	if m := read("nf_conntrack_max"); m > 0 {
		return read("nf_conntrack_count") / m
	}
	return 0
}

// Reclaim frees connection-table slots held by sources that are not kept:
// TCP entries that are half-open or already closing. Live, established
// connections are never touched, so no genuine session is cut. Returns how
// many entries were removed.
func Reclaim(keep func(netip.Addr) bool, limit int) (int, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	flows, err := c.Dump(nil)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range flows {
		if n >= limit {
			break
		}
		if f.TupleOrig.Proto.Protocol != 6 || f.ProtoInfo.TCP == nil {
			continue
		}
		switch f.ProtoInfo.TCP.State {
		case 1, 2, 5, 6, 7, 8, 9: // SYN_SENT, SYN_RECV, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE, SYN_SENT2
		default:
			continue
		}
		if keep(f.TupleOrig.IP.SourceAddress.Unmap()) {
			continue
		}
		if c.Delete(f) == nil {
			n++
		}
	}
	return n, nil
}
