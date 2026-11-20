// Package canary runs decoy listeners: ports that nothing legitimate uses.
//
// An automated intrusion tool probes everything it can reach, so it touches
// decoys that a real user never would. Because the listener only reports a
// source after the TCP handshake completes, the address is real: one touch is
// proven evidence, and the fast tier can block within a fraction of a second
// instead of waiting to count a pattern.
//
// Each connection is then held open and fed a slow trickle (a tarpit), which
// costs a machine-speed attacker the one thing it optimises for: time.
//
// Safety: a decoy binds its port directly, so it can never take over a port a
// real service already uses (the bind fails and that decoy is skipped). The
// listener never parses what it receives, holds a bounded number of
// connections with hard deadlines, and only ever sends on an established
// connection, so it cannot be used to reflect traffic at a forged address.
package canary

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Hit is one completed connection to a decoy port.
type Hit struct {
	Time    time.Time
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Payload []byte // first bytes the client sent, if any (attacker-written: data, never instructions)
	// Followup marks a second report for the same connection that only adds
	// the payload. The touch itself is reported the moment the handshake
	// completes, without waiting to see what the client sends.
	Followup bool
}

type Config struct {
	Ports    []uint16
	Listen   string        // address to bind, default all
	Hold     time.Duration // how long a connection is tarpitted
	MaxConns int           // concurrent tarpitted connections
}

const (
	maxPayload = 256
	perSource  = 2
	firstRead  = 1500 * time.Millisecond
	trickle    = 5 * time.Second
)

type Tarpit struct {
	c    Config
	log  *slog.Logger
	Hits chan Hit

	mu     sync.Mutex
	conns  int
	bySrc  map[netip.Addr]int
	bound  []uint16
	failed map[uint16]string

	Touches, Shed, DroppedHits atomic.Uint64
}

func New(c Config, log *slog.Logger) *Tarpit {
	if c.Hold <= 0 {
		c.Hold = 30 * time.Second
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 256
	}
	return &Tarpit{c: c, log: log, Hits: make(chan Hit, 1024), bySrc: map[netip.Addr]int{}, failed: map[uint16]string{}}
}

// Run binds every decoy port it can and serves until ctx ends. A port that
// cannot be bound (in use, or no permission) is logged and skipped.
func (t *Tarpit) Run(ctx context.Context) {
	var wg sync.WaitGroup
	var lc net.ListenConfig
	for _, port := range t.c.Ports {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(t.c.Listen, fmt.Sprint(port)))
		if err != nil {
			t.mu.Lock()
			t.failed[port] = err.Error()
			t.mu.Unlock()
			t.log.Warn("decoy port skipped", "port", port, "err", err)
			continue
		}
		t.mu.Lock()
		t.bound = append(t.bound, port)
		t.mu.Unlock()
		wg.Add(2)
		go func() { defer wg.Done(); <-ctx.Done(); ln.Close() }()
		go func() { defer wg.Done(); t.serve(ctx, ln) }()
	}
	t.mu.Lock()
	t.log.Info("decoys listening", "ports", t.bound)
	t.mu.Unlock()
	wg.Wait()
}

func (t *Tarpit) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // e.g. out of file descriptors: back off, keep serving
			continue
		}
		go t.handle(ctx, conn)
	}
}

func addrPort(a net.Addr) netip.AddrPort {
	if ta, ok := a.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func (t *Tarpit) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	t.Touches.Add(1)
	hit := Hit{Time: time.Now(), Src: addrPort(conn.RemoteAddr()), Dst: addrPort(conn.LocalAddr())}
	src := hit.Src.Addr()

	t.mu.Lock()
	hold := t.conns < t.c.MaxConns && t.bySrc[src] < perSource
	if hold {
		t.conns++
		t.bySrc[src]++
	}
	t.mu.Unlock()
	t.report(hit) // at once: the handshake is the evidence
	if !hold {
		t.Shed.Add(1) // over capacity: the touch is reported, the connection is not held
		return
	}
	defer func() {
		t.mu.Lock()
		t.conns--
		if t.bySrc[src]--; t.bySrc[src] <= 0 {
			delete(t.bySrc, src)
		}
		t.mu.Unlock()
	}()
	buf := make([]byte, maxPayload)
	_ = conn.SetReadDeadline(time.Now().Add(firstRead))
	if n, _ := conn.Read(buf); n > 0 {
		hit.Payload, hit.Followup = buf[:n], true
		t.report(hit)
	}
	// Tarpit: keep the connection open and send almost nothing.
	release := time.NewTimer(t.c.Hold)
	defer release.Stop()
	tick := time.NewTicker(trickle)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-release.C:
			return
		case <-tick.C:
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte{'\r', '\n'}); err != nil {
				return
			}
		}
	}
}

func (t *Tarpit) report(h Hit) {
	select {
	case t.Hits <- h:
	default:
		t.DroppedHits.Add(1)
	}
}

func (t *Tarpit) Snapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]any{"ports": append([]uint16(nil), t.bound...), "skipped": len(t.failed), "held_now": t.conns,
		"touches": t.Touches.Load(), "shed": t.Shed.Load(), "dropped_hits": t.DroppedHits.Load()}
}
