// Package saturation decides, from a discovery curve, whether more effort
// will keep finding new things or has hit a ceiling.
//
// It fits the cumulative discoveries y against effort x two ways:
//
//	Hill (saturating):   y = Nmax * x / (K + x)
//	power law (scaling): y = a * x^b
//
// and compares them with AIC. A clearly better Hill fit means a ceiling
// exists, estimated as Nmax, and Reached = y/Nmax says how close we are.
// The method follows Cantina's analysis of 1,610 agentic pentest runs, where
// the same test separated saturating runs (24%) from still-scaling ones (74%)
// and stopping at 95% of the estimated ceiling matched human pentest results.
// One caveat carries over: a flat curve means either "nothing left" or "hit a
// wall"; the counts, not the shape, tell those apart.
package saturation

import (
	"math"
	"sort"
)

type Point struct{ X, Y float64 }

type Result struct {
	State    string  `json:"state"` // "saturating", "scaling", "unclear" or "too-few-points"
	Ceiling  float64 `json:"ceiling,omitempty"`
	HalfAt   float64 `json:"half_effort,omitempty"`
	Exponent float64 `json:"exponent,omitempty"`
	DeltaAIC float64 `json:"delta_aic"`
	Reached  float64 `json:"reached,omitempty"` // share of the estimated ceiling already found
	// StopNow is true once a saturating curve has reached StopAt of its ceiling.
	StopNow bool `json:"stop_now"`
}

// StopAt is the share of the estimated ceiling at which extra effort stops paying.
const StopAt = 0.95

// MinPoints is the fewest points worth fitting.
const MinPoints = 6

// Fit classifies a discovery curve. Points need not be sorted.
func Fit(pts []Point) Result {
	var ps []Point
	for _, p := range pts {
		if p.X > 0 && p.Y > 0 && !math.IsNaN(p.X) && !math.IsNaN(p.Y) {
			ps = append(ps, p)
		}
	}
	if len(ps) < MinPoints {
		return Result{State: "too-few-points"}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].X < ps[j].X })
	n := float64(len(ps))
	hK, hN, hSSE := fitHill(ps)
	pA, pB, pSSE := fitPower(ps)
	aic := func(sse float64) float64 { return n*math.Log(math.Max(sse, 1e-12)/n) + 2*2 }
	r := Result{DeltaAIC: round(aic(hSSE)-aic(pSSE), 2), Exponent: round(pB, 3)}
	_ = pA
	last := ps[len(ps)-1].Y
	switch {
	case r.DeltaAIC < -4 && hN > 0:
		r.State = "saturating"
		r.Ceiling, r.HalfAt = round(hN, 1), round(hK, 1)
		r.Reached = round(math.Min(1, last/hN), 3)
		r.StopNow = r.Reached >= StopAt
	case r.DeltaAIC > 4:
		r.State = "scaling"
	default:
		r.State = "unclear"
	}
	return r
}

// fitHill grid-searches K on a log scale; for a fixed K the model is linear
// in Nmax, so Nmax has a closed form. Deterministic and allocation-light.
func fitHill(ps []Point) (bestK, bestN, bestSSE float64) {
	xmin, xmax := ps[0].X, ps[len(ps)-1].X
	bestSSE = math.Inf(1)
	lo, hi := math.Log(xmin/100), math.Log(xmax*100)
	for i := 0; i <= 400; i++ {
		k := math.Exp(lo + (hi-lo)*float64(i)/400)
		var sfy, sff float64
		for _, p := range ps {
			f := p.X / (k + p.X)
			sfy += f * p.Y
			sff += f * f
		}
		if sff == 0 {
			continue
		}
		nmax := sfy / sff
		var sse float64
		for _, p := range ps {
			d := p.Y - nmax*p.X/(k+p.X)
			sse += d * d
		}
		if sse < bestSSE {
			bestK, bestN, bestSSE = k, nmax, sse
		}
	}
	return
}

// fitPower grid-searches the exponent; for a fixed b, a has a closed form.
// Error is measured in y, like the Hill fit, so the AICs are comparable.
func fitPower(ps []Point) (bestA, bestB, bestSSE float64) {
	bestSSE = math.Inf(1)
	for i := 0; i <= 300; i++ {
		b := 0.01 + 1.49*float64(i)/300
		var sgy, sgg float64
		for _, p := range ps {
			g := math.Pow(p.X, b)
			sgy += g * p.Y
			sgg += g * g
		}
		if sgg == 0 {
			continue
		}
		a := sgy / sgg
		var sse float64
		for _, p := range ps {
			d := p.Y - a*math.Pow(p.X, b)
			sse += d * d
		}
		if sse < bestSSE {
			bestA, bestB, bestSSE = a, b, sse
		}
	}
	return
}

func round(f float64, places int) float64 {
	m := math.Pow(10, float64(places))
	return math.Round(f*m) / m
}

// Curve records a discovery trajectory with bounded memory: it keeps a point
// each time effort doubles, plus evenly spaced points in between, at most Max.
type Curve struct {
	Points []Point
	Max    int
	next   float64
}

func (c *Curve) Add(x, y float64) {
	if c.Max == 0 {
		c.Max = 48
	}
	if x < c.next {
		return
	}
	c.Points = append(c.Points, Point{x, y})
	c.next = x * 1.15 // geometric sampling: dense early, sparse late, like the curve itself
	if len(c.Points) > c.Max {
		// drop every other interior point, keep first and last
		kept := c.Points[:1]
		for i := 1; i < len(c.Points)-1; i += 2 {
			kept = append(kept, c.Points[i])
		}
		c.Points = append(kept, c.Points[len(c.Points)-1])
	}
}
