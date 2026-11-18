//go:build !linux

package main

import (
	"context"
	"log/slog"

	"github.com/Xipzer/agentic-firewall/internal/daemon"
)

func startSensors(_ context.Context, _ *daemon.Daemon, log *slog.Logger) func() {
	log.Warn("live sensors need Linux (nflog and conntrack); only replay works on this platform")
	return func() {}
}
