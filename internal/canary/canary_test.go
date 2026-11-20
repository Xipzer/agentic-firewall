package canary

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func freePort(t *testing.T) uint16 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func start(t *testing.T, c Config) (*Tarpit, func()) {
	c.Listen = "127.0.0.1"
	tp := New(c, quiet)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tp.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(tp.Snapshot()["ports"].([]uint16))+tp.Snapshot()["skipped"].(int) == len(c.Ports) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return tp, func() { cancel(); <-done }
}

func TestTouchIsReportedWithPayloadAndHeld(t *testing.T) {
	port := freePort(t)
	tp, stop := start(t, Config{Ports: []uint16{port}, Hold: 400 * time.Millisecond})
	defer stop()
	began := time.Now()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("SSH-2.0-probe\r\n"))
	select {
	case h := <-tp.Hits:
		if h.Dst.Port() != port || h.Followup || !h.Src.Addr().IsLoopback() {
			t.Fatalf("hit %+v", h)
		}
		if since := time.Since(began); since > 500*time.Millisecond {
			t.Fatalf("touch reported after %v; it must not wait for the client to speak", since)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no hit")
	}
	select {
	case h := <-tp.Hits:
		if !h.Followup || string(h.Payload) != "SSH-2.0-probe\r\n" {
			t.Fatalf("followup %+v", h)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no payload followup")
	}
	// The connection is held, then closed by the hold deadline.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(conn)
	if held := time.Since(began); err != nil || held < 350*time.Millisecond {
		t.Fatalf("not tarpitted: held %v err %v", held, err)
	}
}

func TestSilentClientStillReported(t *testing.T) {
	port := freePort(t)
	tp, stop := start(t, Config{Ports: []uint16{port}, Hold: 200 * time.Millisecond})
	defer stop()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case h := <-tp.Hits:
		if len(h.Payload) != 0 {
			t.Fatalf("payload %q", h.Payload)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("a client that sends nothing must still be reported")
	}
}

// A flood of connections cannot exhaust the listener: beyond the caps,
// touches are still reported but not held.
func TestCapsBoundResources(t *testing.T) {
	port := freePort(t)
	tp, stop := start(t, Config{Ports: []uint16{port}, Hold: 2 * time.Second, MaxConns: 8})
	defer stop()
	var conns []net.Conn
	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 20; i++ {
		select {
		case <-tp.Hits:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 20 touches reported", i)
		}
	}
	snap := tp.Snapshot()
	if held := snap["held_now"].(int); held > perSource {
		t.Fatalf("one source holds %d connections, cap is %d", held, perSource)
	}
	if tp.Shed.Load() != 20-perSource {
		t.Fatalf("shed %d", tp.Shed.Load())
	}
}

// A decoy can never take over a port that a real service is using.
func TestPortInUseIsSkippedNotStolen(t *testing.T) {
	real, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	inUse := uint16(real.Addr().(*net.TCPAddr).Port)
	free := freePort(t)
	tp, stop := start(t, Config{Ports: []uint16{inUse, free}})
	defer stop()
	snap := tp.Snapshot()
	if ports := snap["ports"].([]uint16); len(ports) != 1 || ports[0] != free || snap["skipped"].(int) != 1 {
		t.Fatalf("snapshot %+v", snap)
	}
	go func() {
		if c, err := real.Accept(); err == nil {
			_, _ = c.Write([]byte("real"))
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", real.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	if string(b) != "real" {
		t.Fatalf("real service was displaced: %q", b)
	}
	select {
	case h := <-tp.Hits:
		t.Fatalf("traffic to a real service reported as a decoy touch: %+v", h)
	case <-time.After(200 * time.Millisecond):
	}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }
