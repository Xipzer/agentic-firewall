// Package crosstalk lets independent afw nodes (a gateway and the hosts behind
// it, or two sites) share verdicts. It is advisory: a peer's verdict becomes
// evidence for the receiving node's own fast tier, never a direct command, so
// a broken or compromised peer cannot take another node down.
//
// Loop and cascade control: only verdicts a node reached from its own
// evidence are published (hops 0); received verdicts are stamped hops 1 and
// are never relayed. Messages are HMAC-signed, time-bounded and de-duplicated.
package crosstalk

import (
	"bytes"
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
)

const Path = "/afp/0.1/verdict"

type Received struct {
	Verdict *afp.Verdict
	Peer    config.Peer
}

type Bus struct {
	node    string
	key     []byte
	peers   map[string]config.Peer
	maxSkew time.Duration
	limit   int
	client  *http.Client
	now     func() time.Time

	mu     sync.Mutex
	seen   map[string]*list.Element
	order  *list.List
	counts map[string]int
	minute int64
	Inbox  chan Received
	outbox chan []byte
	Stats  struct{ Accepted, Rejected, Sent, SendErrors, Dropped uint64 }
}

func LoadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k := bytes.TrimSpace(b)
	if len(k) < 32 {
		return nil, errors.New("crosstalk key must be at least 32 bytes (try: openssl rand -hex 32)")
	}
	return k, nil
}

func New(node string, key []byte, c config.Crosstalk) *Bus {
	b := &Bus{node: node, key: key, peers: map[string]config.Peer{}, maxSkew: c.MaxSkew.D(), limit: c.PerMinute,
		client: &http.Client{Timeout: 3 * time.Second}, now: time.Now,
		seen: map[string]*list.Element{}, order: list.New(), counts: map[string]int{},
		Inbox: make(chan Received, 256), outbox: make(chan []byte, 256)}
	for _, p := range c.Peers {
		b.peers[p.Node] = p
	}
	return b
}

func Sign(key []byte, node string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(node))
	m.Write([]byte{'\n'})
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (b *Bus) reject(w http.ResponseWriter, code int, why string) {
	b.mu.Lock()
	b.Stats.Rejected++
	b.mu.Unlock()
	http.Error(w, why, code)
}

// ServeHTTP receives a signed verdict from a peer.
func (b *Bus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	node := r.Header.Get("X-AFP-Node")
	peer, ok := b.peers[node]
	if !ok {
		b.reject(w, http.StatusForbidden, "unknown peer")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		b.reject(w, http.StatusBadRequest, "read")
		return
	}
	if !hmac.Equal([]byte(r.Header.Get("X-AFP-Signature")), []byte(Sign(b.key, node, body))) {
		b.reject(w, http.StatusUnauthorized, "bad signature")
		return
	}
	v := &afp.Verdict{}
	if err := json.Unmarshal(body, v); err != nil || v.Validate() != nil {
		b.reject(w, http.StatusBadRequest, "invalid verdict")
		return
	}
	if v.Source.Node != node {
		b.reject(w, http.StatusBadRequest, "source node mismatch")
		return
	}
	if v.Hops != 0 {
		b.reject(w, http.StatusBadRequest, "relayed verdicts are not accepted")
		return
	}
	now := b.now()
	// A Pi has no battery clock: until NTP syncs it can think it is 1970.
	// Skip the freshness check while our own clock is clearly unset; the
	// id cache still stops replays within this run.
	if clockSane(now) && b.maxSkew > 0 {
		if d := now.Sub(v.TS); d > b.maxSkew || d < -b.maxSkew {
			b.reject(w, http.StatusBadRequest, "stale or future timestamp")
			return
		}
	}
	b.mu.Lock()
	if _, dup := b.seen[v.ID]; dup {
		b.mu.Unlock()
		b.reject(w, http.StatusConflict, "replay")
		return
	}
	if m := now.Unix() / 60; m != b.minute {
		b.minute = m
		clear(b.counts)
	}
	if b.counts[node]++; b.limit > 0 && b.counts[node] > b.limit {
		b.mu.Unlock()
		b.reject(w, http.StatusTooManyRequests, "peer rate limit")
		return
	}
	b.seen[v.ID] = b.order.PushBack(v.ID)
	for b.order.Len() > 8192 {
		old := b.order.Front()
		delete(b.seen, old.Value.(string))
		b.order.Remove(old)
	}
	b.Stats.Accepted++
	b.mu.Unlock()
	v.Hops = 1
	select {
	case b.Inbox <- Received{Verdict: v, Peer: peer}:
		w.WriteHeader(http.StatusAccepted)
	default:
		b.mu.Lock()
		b.Stats.Dropped++
		b.mu.Unlock()
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}
}

func clockSane(t time.Time) bool { return t.Year() >= 2025 }

// Publish queues a locally reached verdict for every peer. It never blocks.
func (b *Bus) Publish(v *afp.Verdict) {
	if v.Hops != 0 || len(b.peers) == 0 {
		return
	}
	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case b.outbox <- body:
	default:
		b.mu.Lock()
		b.Stats.Dropped++
		b.mu.Unlock()
	}
}

// Run sends queued verdicts until ctx ends. Peer failures are counted and
// ignored: every node stays fully functional on its own.
func (b *Bus) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case body := <-b.outbox:
			sig := Sign(b.key, b.node, body)
			var wg sync.WaitGroup
			for _, p := range b.peers {
				wg.Add(1)
				go func(p config.Peer) {
					defer wg.Done()
					err := b.send(ctx, p, body, sig)
					b.mu.Lock()
					if err != nil {
						b.Stats.SendErrors++
					} else {
						b.Stats.Sent++
					}
					b.mu.Unlock()
				}(p)
			}
			wg.Wait()
		}
	}
}

func (b *Bus) send(ctx context.Context, p config.Peer, body []byte, sig string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.URL, "/")+Path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AFP-Node", b.node)
	req.Header.Set("X-AFP-Signature", sig)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("peer %s: http %d", p.Node, resp.StatusCode)
	}
	return nil
}

func (b *Bus) Snapshot() map[string]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return map[string]uint64{"accepted": b.Stats.Accepted, "rejected": b.Stats.Rejected, "sent": b.Stats.Sent,
		"send_errors": b.Stats.SendErrors, "dropped": b.Stats.Dropped}
}
