// Command railscheck is the gate on the test suite itself.
//
// A green run proves nothing if a safety test was skipped, renamed away or
// deleted. railscheck reads `go test -json` output (several runs may be
// concatenated) and fails unless:
//
//   - no test failed,
//   - no test was skipped (a skipped test proves nothing),
//   - every test named in the manifest ran and passed.
//
// It also keeps a lock of hashes over the safety tests and the gate (lock.go),
// so a test cannot be loosened without the change showing up on its own.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type event struct {
	Action  string
	Package string
	Test    string
}

const usage = `usage:
  railscheck results <manifest> < go-test-json   every safety test ran and passed, none skipped
  railscheck verify  <manifest> <lock>           no safety test, helper or gate file changed since locked
  railscheck lock    <manifest> <lock>           record the current files as the approved ones
`

func main() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	required, err := manifest(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "railscheck:", err)
		os.Exit(2)
	}
	switch {
	case os.Args[1] == "results":
		problems, passed := check(required, bufio.NewScanner(os.Stdin))
		for _, p := range problems {
			fmt.Println("RAIL BROKEN:", p)
		}
		if len(problems) > 0 {
			fmt.Printf("railscheck: %d problem(s). A safety test that does not run and pass is treated as a failure.\n", len(problems))
			os.Exit(1)
		}
		fmt.Printf("railscheck: %d tests passed, none skipped, all %d safety rails ran and passed\n", passed, len(required))
	case len(os.Args) == 4 && (os.Args[1] == "verify" || os.Args[1] == "lock"):
		current, err := computeLock(".", required)
		if err != nil {
			fmt.Fprintln(os.Stderr, "railscheck:", err)
			os.Exit(1)
		}
		if os.Args[1] == "lock" {
			if err := os.WriteFile(os.Args[3], []byte(formatLock(current)), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "railscheck:", err)
				os.Exit(1)
			}
			fmt.Printf("railscheck: locked %d files\n", len(current))
			return
		}
		b, err := os.ReadFile(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "railscheck:", err)
			os.Exit(1)
		}
		diff := diffLock(parseLock(string(b)), current)
		for _, d := range diff {
			fmt.Println("RAIL CHANGED:", d)
		}
		if len(diff) > 0 {
			fmt.Printf("railscheck: %d locked file(s) differ. If the change is intended, run `go run ./internal/tools/railscheck lock %s %s` and commit the lock with an explanation.\n", len(diff), os.Args[2], os.Args[3])
			os.Exit(1)
		}
		fmt.Printf("railscheck: all %d locked files match\n", len(current))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func manifest(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if seen[line] {
			return nil, fmt.Errorf("%s listed twice", line)
		}
		seen[line] = true
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no tests", path)
	}
	return out, nil
}

func check(required []string, s *bufio.Scanner) (problems []string, passed int) {
	s.Buffer(make([]byte, 1<<20), 16<<20)
	result := map[string]string{} // top-level test name -> worst outcome seen
	rank := map[string]int{"pass": 1, "skip": 2, "fail": 3}
	for s.Scan() {
		var e event
		if json.Unmarshal(s.Bytes(), &e) != nil || e.Test == "" || strings.Contains(e.Test, "/") {
			if e.Test == "" && e.Action == "fail" && e.Package != "" {
				problems = append(problems, "package "+e.Package+" failed")
			}
			continue
		}
		if rank[e.Action] > rank[result[e.Test]] {
			result[e.Test] = e.Action
		}
	}
	names := make([]string, 0, len(result))
	for n := range result {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		switch result[n] {
		case "pass":
			passed++
		case "skip":
			problems = append(problems, n+" was skipped")
		case "fail":
			problems = append(problems, n+" failed")
		}
	}
	for _, n := range required {
		if _, ok := result[n]; !ok {
			problems = append(problems, n+" did not run (deleted, renamed, or left out of the run)")
		}
	}
	return problems, passed
}
