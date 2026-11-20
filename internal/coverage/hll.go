package coverage

import (
	"encoding/binary"
	"hash/fnv"
	"math"
	"math/bits"
	"net/netip"
)

// hll is a small HyperLogLog (1 KiB, about 3% error). It keeps counting
// distinct sources after the exact set is full, so a capped set cannot make
// an ever-growing population look like it has hit a ceiling.
type hll struct{ reg [1 << hllP]uint8 }

const hllP = 10

func (h *hll) add(p netip.Prefix) {
	f := fnv.New64a()
	b := p.Addr().As16()
	f.Write(b[:])
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(p.Bits()))
	f.Write(l[:])
	x := f.Sum64()
	x ^= x >> 33 // fnv's high bits are weak for short inputs; mix before splitting
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	idx := x >> (64 - hllP)
	rank := uint8(bits.LeadingZeros64(x<<hllP|1<<(hllP-1))) + 1
	if rank > h.reg[idx] {
		h.reg[idx] = rank
	}
}

func (h *hll) estimate() float64 {
	m := float64(len(h.reg))
	sum, zeros := 0.0, 0
	for _, r := range h.reg {
		sum += math.Pow(2, -float64(r))
		if r == 0 {
			zeros++
		}
	}
	e := 0.7213 / (1 + 1.079/m) * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return e
}
