package main

import (
	"bufio"
	"os"
	"path/filepath"
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

func TestLockCatchesAnyEditToASafetyTestOrItsHelpers(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("guard/guard_test.go", "package guard\nfunc TestRails(t *testing.T) { if blocked(protected) { t.Fatal() } }\n")
	write("guard/helpers_test.go", "package guard\nfunc blocked(x int) bool { return real(x) }\n")
	write("other/other_test.go", "package other\nfunc TestUnrelated(t *testing.T) {}\n")
	for _, f := range gateFiles {
		write(f, "gate\n")
	}
	write("internal/tools/railscheck/main.go", "package main\n")
	req := []string{"TestRails"}
	base, err := computeLock(root, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base["other/other_test.go"]; ok {
		t.Error("packages without safety tests should stay free to change")
	}
	if len(diffLock(parseLock(formatLock(base)), base)) != 0 {
		t.Fatal("a lock must match the tree it was made from")
	}
	edits := map[string]func(){
		"guard/guard_test.go changed":   func() { write("guard/guard_test.go", "package guard\nfunc TestRails(t *testing.T) { }\n") },            // assertion removed
		"guard/helpers_test.go changed": func() { write("guard/helpers_test.go", "package guard\nfunc blocked(x int) bool { return false }\n") }, // helper neutered
		"rails.txt changed":             func() { write("rails.txt", "gate\n# TestRails removed\n") },                                            // manifest edited
		"lab/rails.sh changed":          func() { write("lab/rails.sh", "exit 0\n") },                                                            // gate bypassed
		"main.go changed":               func() { write("internal/tools/railscheck/main.go", "package main\nfunc main() {}\n") },                 // checker neutered
		"extra_test.go is new":          func() { write("guard/extra_test.go", "package guard\nfunc init() { protected = 0 }\n") },               // new file altering a helper
	}
	for want, edit := range edits {
		edit() // edits pile up; each must still be reported by name
		cur, err := computeLock(root, req)
		if err != nil {
			t.Fatal(err)
		}
		d := strings.Join(diffLock(base, cur), "; ")
		if !strings.Contains(d, want) {
			t.Errorf("%q not caught: %s", want, d)
		}
	}
	// Renaming a safety test away is an error, not a silent pass.
	write("guard/guard_test.go", "package guard\nfunc TestRailsDisabled(t *testing.T) {}\n")
	if _, err := computeLock(root, req); err == nil {
		t.Error("a safety test missing from the source must be an error")
	}
	// Line endings do not change a hash.
	write("a_test.go", "x\r\ny\r\n")
	h1, _ := hashFile(filepath.Join(root, "a_test.go"))
	write("a_test.go", "x\ny\n")
	if h2, _ := hashFile(filepath.Join(root, "a_test.go")); h1 != h2 {
		t.Error("line endings changed the hash")
	}
}
