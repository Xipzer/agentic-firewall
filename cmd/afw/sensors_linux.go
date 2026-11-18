//go:build linux

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/daemon"
	"github.com/Xipzer/agentic-firewall/internal/sensor"
)

// startSensors runs NFLOG and conntrack readers, restarting them with backoff.
// A dead sensor means afw sees less, never that traffic stops: it fails open.
func startSensors(ctx context.Context, d *daemon.Daemon, log *slog.Logger) func() {
	ctx, cancel := context.WithCancel(ctx)
	var c sensor.Counters
	daemon.SensorStats = func() map[string]uint64 {
		return map[string]uint64{"nflog_packets": c.Packets.Load(), "conntrack_events": c.Conntrack.Load(),
			"overflow": c.Overflow.Load(), "parse_errors": c.ParseErrors.Load()}
	}
	keep := func(name string, f func() error) {
		backoff := time.Second
		for ctx.Err() == nil {
			start := time.Now()
			if err := f(); err != nil && ctx.Err() == nil {
				log.Error("sensor stopped; restarting", "sensor", name, "err", err, "in", backoff)
			}
			if time.Since(start) > time.Minute {
				backoff = time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
		}
	}
	go keep("nflog", func() error { return sensor.RunNFLOG(ctx, d.Cfg.NFT.LogGroup, d.Events, &c) })
	go keep("conntrack", func() error { return sensor.RunConntrack(ctx, d.Events, &c) })
	return cancel
}
