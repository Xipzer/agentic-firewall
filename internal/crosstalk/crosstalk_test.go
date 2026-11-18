package crosstalk

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
)

var key = []byte("0123456789abcdef0123456789abcdef")

func bus(now time.Time) *Bus {
	b := New("gw", key, config.Crosstalk{MaxSkew: config.Duration(2 * time.Minute), PerMinute: 3,
		Peers: []config.Peer{{Node: "pc", URL: "http://pc", Trust: 0.8}}})
	b.now = func() time.Time { return now }
	return b
}

func signed(t *testing.T, node string, k []byte, v *afp.Verdict) *http.Request {
	body, _ := json.Marshal(v)
	r := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(body))
	r.Header.Set("X-AFP-Node", node)
	r.Header.Set("X-AFP-Signature", Sign(k, node, body))
	return r
}

func verdict(node string, ts time.Time) *afp.Verdict {
	v := &afp.Verdict{Envelope: afp.NewEnvelope(afp.TypeVerdict, afp.Source{Tier: afp.TierFast, Agent: "h", Node: node}),
		Subject: afp.Subject{Kind: afp.SubjectHost, Value: "45.9.20.7"}, Action: afp.ActionDrop, Confidence: 0.9, TTL: "10m", Reason: "x"}
	v.TS = ts
	return v
}

func TestReceiveRules(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		req  func() *http.Request
		code int
	}{
		{"valid", func() *http.Request { return signed(t, "pc", key, verdict("pc", now)) }, http.StatusAccepted},
		{"unknown peer", func() *http.Request { return signed(t, "evil", key, verdict("evil", now)) }, http.StatusForbidden},
		{"wrong key", func() *http.Request {
			return signed(t, "pc", []byte("ffffffffffffffffffffffffffffffff"), verdict("pc", now))
		}, http.StatusUnauthorized},
		{"node mismatch", func() *http.Request { return signed(t, "pc", key, verdict("gw", now)) }, http.StatusBadRequest},
		{"stale", func() *http.Request { return signed(t, "pc", key, verdict("pc", now.Add(-10*time.Minute))) }, http.StatusBadRequest},
		{"relayed", func() *http.Request {
			v := verdict("pc", now)
			v.Hops = 1
			return signed(t, "pc", key, v)
		}, http.StatusBadRequest},
		{"invalid verdict", func() *http.Request {
			v := verdict("pc", now)
			v.TTL = ""
			return signed(t, "pc", key, v)
		}, http.StatusBadRequest},
	}
	for _, c := range cases {
		b := bus(now)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, c.req())
		if w.Code != c.code {
			t.Errorf("%s: code %d, want %d (%s)", c.name, w.Code, c.code, w.Body)
		}
	}
}

func TestReplayAndRateLimit(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	b := bus(now)
	v := verdict("pc", now)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, signed(t, "pc", key, v))
	w = httptest.NewRecorder()
	b.ServeHTTP(w, signed(t, "pc", key, v))
	if w.Code != http.StatusConflict {
		t.Fatalf("replay: %d", w.Code)
	}
	for i := 0; i < 3; i++ {
		w = httptest.NewRecorder()
		b.ServeHTTP(w, signed(t, "pc", key, verdict("pc", now)))
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", w.Code)
	}
	r := <-b.Inbox
	if r.Verdict.Hops != 1 || r.Peer.Trust != 0.8 {
		t.Fatalf("received verdict not stamped: %+v", r)
	}
}

func TestUnsetClockSkipsFreshness(t *testing.T) {
	b := bus(time.Unix(0, 0)) // a Pi before NTP
	w := httptest.NewRecorder()
	b.ServeHTTP(w, signed(t, "pc", key, verdict("pc", time.Now())))
	if w.Code != http.StatusAccepted {
		t.Fatalf("code %d", w.Code)
	}
}

func TestPublishNeverRelays(t *testing.T) {
	b := bus(time.Now())
	v := verdict("gw", time.Now())
	v.Hops = 1
	b.Publish(v)
	if len(b.outbox) != 0 {
		t.Fatal("relayed a received verdict")
	}
	v.Hops = 0
	b.Publish(v)
	if len(b.outbox) != 1 {
		t.Fatal("did not queue local verdict")
	}
}

func TestEndToEnd(t *testing.T) {
	now := time.Now()
	recv := New("pc", key, config.Crosstalk{MaxSkew: config.Duration(time.Minute), Peers: []config.Peer{{Node: "gw", Trust: 0.7}}})
	srv := httptest.NewServer(recv)
	defer srv.Close()
	send := New("gw", key, config.Crosstalk{Peers: []config.Peer{{Node: "pc", URL: srv.URL}}})
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()
	go send.Run(ctx)
	send.Publish(verdict("gw", now))
	select {
	case r := <-recv.Inbox:
		if r.Peer.Node != "gw" || r.Verdict.Subject.Value != "45.9.20.7" {
			t.Fatalf("%+v", r)
		}
	case <-ctx.Done():
		t.Fatal("verdict never arrived")
	}
}
