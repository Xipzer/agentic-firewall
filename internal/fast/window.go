package fast

import "time"

const buckets = 10

// counter counts events in a sliding window using fixed buckets. It is O(1)
// in memory and time, which keeps per-subject state small on a Pi.
type counter struct {
	width time.Duration // bucket width = window / buckets
	last  int64         // index of the newest bucket
	b     [buckets]uint32
}

func newCounter(window time.Duration) counter {
	w := window / buckets
	if w <= 0 {
		w = time.Millisecond
	}
	return counter{width: w}
}

func (c *counter) advance(t time.Time) {
	idx := t.UnixNano() / int64(c.width)
	if idx <= c.last {
		return
	}
	if idx-c.last >= buckets {
		c.b = [buckets]uint32{}
	} else {
		for i := c.last + 1; i <= idx; i++ {
			c.b[i%buckets] = 0
		}
	}
	c.last = idx
}

func (c *counter) add(t time.Time, n uint32) {
	c.advance(t)
	idx := t.UnixNano() / int64(c.width)
	if c.last-idx >= buckets {
		return // older than the window
	}
	c.b[idx%buckets] += n
}

func (c *counter) sum(now time.Time) uint32 {
	c.advance(now)
	var s uint32
	for _, v := range c.b {
		s += v
	}
	return s
}

// distinct tracks distinct keys with their last-seen time, bounded in size.
// When full it reports saturation instead of growing.
type distinct[K comparable] struct {
	m         map[K]time.Time
	cap       int
	saturated bool
}

func newDistinct[K comparable](cap int) distinct[K] { return distinct[K]{cap: cap} }

func (d *distinct[K]) add(k K, t time.Time, keep time.Duration) {
	if d.m == nil {
		d.m = make(map[K]time.Time, 4)
	}
	if _, ok := d.m[k]; !ok && len(d.m) >= d.cap {
		d.prune(t.Add(-keep))
		if len(d.m) >= d.cap {
			d.saturated = true
			return
		}
	}
	d.m[k] = t
}

func (d *distinct[K]) prune(before time.Time) {
	for k, t := range d.m {
		if t.Before(before) {
			delete(d.m, k)
		}
	}
	if len(d.m) < d.cap {
		d.saturated = false
	}
}

// count returns how many keys were seen since the given time.
func (d *distinct[K]) count(since time.Time) int {
	if d.saturated {
		return d.cap
	}
	n := 0
	for _, t := range d.m {
		if !t.Before(since) {
			n++
		}
	}
	return n
}
