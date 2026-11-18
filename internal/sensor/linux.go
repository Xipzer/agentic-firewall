//go:build linux

package sensor

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/Xipzer/agentic-firewall/internal/fast"
)

// Counters are read by status; sensors never block on a slow consumer.
type Counters struct {
	Packets, Conntrack, Overflow, ParseErrors atomic.Uint64
}

// RunNFLOG streams sampled new flows from the observe chain's log group.
// NFLOG sees connection attempts even when a later rule drops them, which
// conntrack events alone would miss (unconfirmed entries emit nothing).
func RunNFLOG(ctx context.Context, group uint16, out chan<- fast.Event, c *Counters) error {
	nf, err := nflog.Open(&nflog.Config{Group: group, Copymode: nflog.CopyPacket, Bufsize: 96})
	if err != nil {
		return fmt.Errorf("nflog group %d: %w", group, err)
	}
	defer nf.Close()
	errs := make(chan error, 1)
	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		t := time.Now()
		if a.Timestamp != nil {
			t = *a.Timestamp
		}
		ev, err := ParsePacket(*a.Payload, t)
		if err != nil {
			c.ParseErrors.Add(1)
			return 0
		}
		c.Packets.Add(1)
		select {
		case out <- ev:
		default:
			c.Overflow.Add(1)
		}
		return 0
	}, func(e error) int {
		select {
		case errs <- e:
		default:
		}
		return 1
	})
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return fmt.Errorf("nflog: %w", err)
	}
}

const (
	tcpEstablished = 3
	tcpClose       = 8
)

// RunConntrack streams handshake completion and teardown from conntrack.
func RunConntrack(ctx context.Context, out chan<- fast.Event, c *Counters) error {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("conntrack: %w", err)
	}
	defer conn.Close()
	evs := make(chan conntrack.Event, 4096)
	errCh, err := conn.Listen(evs, 1, []netfilter.NetlinkGroup{netfilter.GroupCTUpdate, netfilter.GroupCTDestroy})
	if err != nil {
		return fmt.Errorf("conntrack listen: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return fmt.Errorf("conntrack events: %w", err)
		case e := <-evs:
			if e.Flow == nil {
				continue
			}
			ev, ok := convert(e)
			if !ok {
				continue
			}
			c.Conntrack.Add(1)
			select {
			case out <- ev:
			default:
				c.Overflow.Add(1)
			}
		}
	}
}

func convert(e conntrack.Event) (fast.Event, bool) {
	f := e.Flow
	t := f.TupleOrig
	ev := fast.Event{Time: time.Now(), Proto: t.Proto.Protocol,
		Src:     netip.AddrPortFrom(t.IP.SourceAddress, t.Proto.SourcePort),
		Dst:     netip.AddrPortFrom(t.IP.DestinationAddress, t.Proto.DestinationPort),
		Bytes:   f.CountersOrig.Bytes + f.CountersReply.Bytes,
		Packets: f.CountersOrig.Packets + f.CountersReply.Packets}
	switch e.Type {
	case conntrack.EventDestroy:
		// TCP teardown is reported from the first FIN/RST update below;
		// destroy arrives up to TIME_WAIT (2 min) later and only backs it up.
		ev.Kind, ev.Assured = fast.KindEnd, f.Status.Assured()
	case conntrack.EventUpdate:
		if t.Proto.Protocol != fast.ProtoTCP || f.ProtoInfo.TCP == nil {
			return ev, false
		}
		switch s := f.ProtoInfo.TCP.State; {
		case s == tcpEstablished:
			ev.Kind = fast.KindEstablished
		case s > tcpEstablished && s <= tcpClose:
			ev.Kind, ev.Assured = fast.KindEnd, f.Status.Assured()
		default:
			return ev, false
		}
	default:
		return ev, false
	}
	return ev, true
}
