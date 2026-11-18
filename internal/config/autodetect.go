package config

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Discovered lists subjects that must never be blocked, found on this machine:
// its own addresses, default gateways, DNS resolvers and the SSH client that
// started afw (so an operator cannot lock themselves out).
type Discovered struct {
	Self      []netip.Prefix
	Gateways  []netip.Prefix
	Resolvers []netip.Prefix
	Admin     []netip.Prefix
	OnLink    []netip.Prefix
}

func (d Discovered) All() []netip.Prefix {
	var out []netip.Prefix
	for _, l := range [][]netip.Prefix{d.Self, d.Gateways, d.Resolvers, d.Admin} {
		out = append(out, l...)
	}
	return out
}

func host(a netip.Addr) netip.Prefix { a = a.Unmap(); return netip.PrefixFrom(a, a.BitLen()) }

func Discover() Discovered {
	var d Discovered
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			d.Self = append(d.Self, host(ip))
			if !ip.IsLoopback() {
				d.OnLink = append(d.OnLink, netip.PrefixFrom(ip.Unmap(), ones).Masked())
			}
		}
	}
	d.Gateways = append(readRoute4("/proc/net/route"), readRoute6("/proc/net/ipv6_route")...)
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		d.Resolvers = append(d.Resolvers, readResolvers(f)...)
	}
	for _, env := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if f := strings.Fields(os.Getenv(env)); len(f) > 0 {
			if a, err := netip.ParseAddr(f[0]); err == nil {
				d.Admin = append(d.Admin, host(a))
				break
			}
		}
	}
	return d
}

func readRoute4(path string) []netip.Prefix {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Prefix
	s := bufio.NewScanner(f)
	for s.Scan() {
		fs := strings.Fields(s.Text())
		if len(fs) < 3 || fs[1] != "00000000" || fs[2] == "00000000" {
			continue
		}
		b, err := hex.DecodeString(fs[2])
		if err != nil || len(b) != 4 {
			continue
		}
		out = append(out, host(netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})))
	}
	return out
}

func readRoute6(path string) []netip.Prefix {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Prefix
	s := bufio.NewScanner(f)
	for s.Scan() {
		fs := strings.Fields(s.Text())
		if len(fs) < 5 || fs[1] != "00" || strings.Trim(fs[4], "0") == "" {
			continue
		}
		b, err := hex.DecodeString(fs[4])
		if err != nil || len(b) != 16 {
			continue
		}
		out = append(out, host(netip.AddrFrom16([16]byte(b))))
	}
	return out
}

func readResolvers(path string) []netip.Prefix {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, line := range strings.Split(string(b), "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 2 && fs[0] == "nameserver" {
			if a, err := netip.ParseAddr(strings.SplitN(fs[1], "%", 2)[0]); err == nil {
				out = append(out, host(a))
			}
		}
	}
	return out
}
