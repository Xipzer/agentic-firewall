package sensor

import (
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/fast"
)

func TestParseIPv4TCP(t *testing.T) {
	pkt := []byte{0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 45, 9, 20, 7, 192, 168, 1, 2,
		0xc3, 0x50, 0x00, 0x16, 0, 0, 0, 0}
	ev, err := ParsePacket(pkt, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Src.String() != "45.9.20.7:50000" || ev.Dst.String() != "192.168.1.2:22" || ev.Proto != fast.ProtoTCP || ev.Kind != fast.KindNew {
		t.Fatalf("%+v", ev)
	}
}

func TestParseIPv6WithExtensionHeader(t *testing.T) {
	pkt := make([]byte, 40+8+4)
	pkt[0] = 0x60
	pkt[6] = 0 // hop-by-hop
	copy(pkt[8:24], []byte{0x2a, 0x0e, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	pkt[40] = 17 // next: udp
	pkt[41] = 0  // length 8 bytes
	pkt[48], pkt[49], pkt[50], pkt[51] = 0x13, 0x88, 0x00, 0x35
	ev, err := ParsePacket(pkt, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Src.String() != "[2a0e:1:0:7::9]:5000" || ev.Dst.Port() != 53 || ev.Proto != fast.ProtoUDP {
		t.Fatalf("%+v", ev)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x45}, {0x60, 0}, {0x99, 1, 2, 3}, {0x4f, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}} {
		if _, err := ParsePacket(b, time.Now()); err == nil {
			t.Errorf("accepted %x", b)
		}
	}
	frag := []byte{0x45, 0, 0, 40, 0, 0, 0x00, 0x10, 64, 6, 0, 0, 45, 9, 20, 7, 192, 168, 1, 2, 0, 0, 0, 0}
	if _, err := ParsePacket(frag, time.Now()); err == nil {
		t.Error("accepted a non-first fragment")
	}
}
