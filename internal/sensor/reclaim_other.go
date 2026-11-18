//go:build !linux

package sensor

import (
	"errors"
	"net/netip"
)

func ConntrackFill() float64 { return 0 }

func Reclaim(func(netip.Addr) bool, int) (int, error) { return 0, errors.New("linux only") }
