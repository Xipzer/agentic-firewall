// Package netx holds address helpers shared by the tiers and the enforcer.
package netx

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Special-purpose ranges (IANA registries) that must never appear in a
// reputation feed or be treated as an internet attacker.
var reserved = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

// Private holds the ranges a home network uses internally by default.
var Private = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10", "100.64.0.0/10")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Overlaps reports whether p overlaps any prefix in set.
func Overlaps(p netip.Prefix, set []netip.Prefix) bool {
	for _, q := range set {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}

// Contains reports whether a falls inside any prefix in set.
func Contains(set []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, q := range set {
		if q.Contains(a) {
			return true
		}
	}
	return false
}

// Reserved reports whether p touches special-purpose address space.
func Reserved(p netip.Prefix) bool { return Overlaps(p, reserved) }

// ParsePrefixOrAddr accepts "1.2.3.4", "1.2.3.0/24" or IPv6 forms and
// returns a masked prefix with any IPv4-in-IPv6 mapping removed.
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("mapped prefix %s too wide", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// HostKey is the subject key for a single source: the address itself for
// IPv4, the /64 for IPv6 (one end site rotates freely inside its /64).
func HostKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// AggKey is the coarser aggregate used to catch distributed sources:
// /24 for IPv4 and /48 for IPv6.
func AggKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// IsHost reports whether p is a single-address or single-/64 subject.
func IsHost(p netip.Prefix) bool {
	return (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() >= 64)
}

// Collapse sorts prefixes and removes any prefix covered by another.
// The result is safe to load into an nftables interval set.
func Collapse(in []netip.Prefix) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p.IsValid() {
			ps = append(ps, p.Masked())
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	out := ps[:0]
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].Addr().BitLen() == p.Addr().BitLen() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}
