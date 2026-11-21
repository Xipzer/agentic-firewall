package graph

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/Xipzer/agentic-firewall/internal/netx"
)

// Redact replaces every address inside hide with a stable token (lan-xxxxxxxx)
// and drops node names, so a briefing sent to a model, local or remote, does
// not hand over a map of the network. Whoever answers the model's endpoint
// sees everything we send it; this bounds what that is. The same address
// always maps to the same token under one key, so the briefing still reads
// coherently, and the mapping never leaves this machine.
func Redact(text string, hide []netip.Prefix, key []byte) string {
	isAddrChar := func(r byte) bool {
		return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.'
	}
	var b strings.Builder
	lines := strings.Split(text, "\n")
	for li, line := range lines {
		if strings.HasPrefix(line, "nodes: ") {
			continue
		}
		for i := 0; i < len(line); {
			if !isAddrChar(line[i]) {
				b.WriteByte(line[i])
				i++
				continue
			}
			j := i
			for j < len(line) && isAddrChar(line[j]) {
				j++
			}
			b.WriteString(redactRun(line[i:j], hide, key))
			i = j
		}
		if li < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// Token is the pseudonym for one address under a key.
func Token(a netip.Addr, key []byte) string {
	m := hmac.New(sha256.New, key)
	raw := a.Unmap().As16()
	m.Write(raw[:])
	return "lan-" + hex.EncodeToString(m.Sum(nil))[:8]
}

func redactRun(run string, hide []netip.Prefix, key []byte) string {
	trimmed := strings.TrimRight(run, ".:")
	tail := run[len(trimmed):]
	if a, err := netip.ParseAddr(trimmed); err == nil {
		if netx.Contains(hide, a) {
			return Token(a, key) + tail
		}
		return run
	}
	// IPv4 with a port, e.g. 192.168.1.2:22
	if i := strings.LastIndexByte(trimmed, ':'); i > 0 && strings.Count(trimmed, ":") == 1 {
		if a, err := netip.ParseAddr(trimmed[:i]); err == nil && netx.Contains(hide, a) {
			return Token(a, key) + trimmed[i:] + tail
		}
	}
	return run
}
