package saturation

import (
	"math"
	"testing"
)

func curve(f func(x float64) float64, noise float64) []Point {
	var ps []Point
	for i := 1; i <= 50; i++ {
		x := math.Pow(1.25, float64(i))
		// deterministic pseudo-noise
		y := f(x) * (1 + noise*math.Sin(float64(i)*2.3))
		ps = append(ps, Point{x, y})
	}
	return ps
}

func TestSaturatingCurveFindsCeiling(t *testing.T) {
	r := Fit(curve(func(x float64) float64 { return 120 * x / (300 + x) }, 0.02))
	if r.State != "saturating" {
		t.Fatalf("want saturating, got %+v", r)
	}
	if math.Abs(r.Ceiling-120)/120 > 0.1 {
		t.Fatalf("ceiling %v, want about 120", r.Ceiling)
	}
	if !r.StopNow || r.Reached < StopAt {
		t.Fatalf("a curve this far along should stop: %+v", r)
	}
}

func TestScalingCurveKeepsGoing(t *testing.T) {
	// Cantina's cohort law: findings proportional to compute^0.54.
	r := Fit(curve(func(x float64) float64 { return 3 * math.Pow(x, 0.54) }, 0.02))
	if r.State != "scaling" || r.StopNow {
		t.Fatalf("want scaling, got %+v", r)
	}
	if math.Abs(r.Exponent-0.54) > 0.05 {
		t.Fatalf("exponent %v, want about 0.54", r.Exponent)
	}
}

func TestEarlyHillIsNotStoppedPrematurely(t *testing.T) {
	// Only the first part of a saturating curve: the ceiling is far away.
	var ps []Point
	for i := 1; i <= 12; i++ {
		x := float64(i * 10)
		ps = append(ps, Point{x, 500 * x / (5000 + x)})
	}
	if r := Fit(ps); r.StopNow {
		t.Fatalf("stopped long before the ceiling: %+v", r)
	}
}

func TestTooFewPoints(t *testing.T) {
	if r := Fit([]Point{{1, 1}, {2, 2}}); r.State != "too-few-points" || r.StopNow {
		t.Fatal(r)
	}
}

func TestCurveIsBounded(t *testing.T) {
	var c Curve
	for i := 1; i <= 1_000_000; i++ {
		c.Add(float64(i), math.Sqrt(float64(i)))
	}
	if len(c.Points) > 48 || c.Points[0].X != 1 {
		t.Fatalf("points %d first %v", len(c.Points), c.Points[0])
	}
}
