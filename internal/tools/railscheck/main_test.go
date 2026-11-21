package main

import (
	"bufio"
	"strings"
	"testing"
)

func run(required []string, lines ...string) ([]string, int) {
	return check(required, bufio.NewScanner(strings.NewReader(strings.Join(lines, "\n"))))
}

func ev(action, test string) string {
	return `{"Action":"` + action + `","Package":"p","Test":"` + test + `"}`
}

func TestRailscheckCatchesEveryWayToFakeGreen(t *testing.T) {
	req := []string{"TestA", "TestB"}
	if p, n := run(req, ev("run", "TestA"), ev("pass", "TestA"), ev("pass", "TestB"), ev("pass", "TestC"), ev("pass", "TestC/sub")); len(p) != 0 || n != 3 {
		t.Fatalf("clean run: %v %d", p, n)
	}
	cases := map[string][]string{
		"did not run":  {ev("pass", "TestA")},                                           // TestB deleted or renamed
		"was skipped":  {ev("pass", "TestA"), ev("skip", "TestB")},                      // skipped rail
		"TestC was sk": {ev("pass", "TestA"), ev("pass", "TestB"), ev("skip", "TestC")}, // any skip at all
		"failed":       {ev("pass", "TestA"), ev("fail", "TestB")},
		"package p":    {ev("pass", "TestA"), ev("pass", "TestB"), `{"Action":"fail","Package":"p"}`}, // build failure or panic
	}
	for want, lines := range cases {
		p, _ := run(req, lines...)
		if len(p) == 0 || !strings.Contains(strings.Join(p, "; "), want) {
			t.Errorf("%q not caught: %v", want, p)
		}
	}
	// A pass in one run cannot hide a skip or failure of the same test in another.
	if p, _ := run(req, ev("pass", "TestA"), ev("pass", "TestB"), ev("skip", "TestB")); len(p) == 0 {
		t.Error("a later skip was hidden by an earlier pass")
	}
}
