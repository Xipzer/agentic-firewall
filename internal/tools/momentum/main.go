// Command momentum shows how the safety tests have moved, version by version.
//
// Nothing is stored: every number is recomputed from git history, so there
// is no record to overwrite. For each commit it measures each safety test
// (the names in rails.txt) and reports whether it is new, grew, shrank,
// changed without changing size, or disappeared. A healthy codebase's safety
// tests grow or hold steady; a test that shrinks or vanishes is the thing a
// supervisor, human or agent, should look at.
//
// Usage: momentum [-n 30] [-chart file.mmd] [-warn]
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"strings"
)

// measure is one test function at one version.
type measure struct {
	hash   [32]byte
	size   int // syntax nodes in the body: shrinks when a case or a check is removed
	checks int // assertion calls plus table rows: the human-readable strength
}

type snapshot struct {
	commit, date, subject string
	tests                 map[string]measure
	testLines             int
}

var assertNames = map[string]bool{"Fatal": true, "Fatalf": true, "Error": true, "Errorf": true, "Fail": true, "FailNow": true}

// measureFile parses one Go test file and measures every top-level test in it.
func measureFile(src []byte, out map[string]measure) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x_test.go", src, parser.SkipObjectResolution)
	if err != nil {
		return
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		var m measure
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			m.size++
			switch x := n.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && assertNames[sel.Sel.Name] {
					m.checks++
				}
			case *ast.CompositeLit:
				switch x.Type.(type) {
				case *ast.ArrayType, *ast.MapType:
					if len(x.Elts) >= 2 {
						m.checks += len(x.Elts) // rows of a table-driven test
					}
				}
			}
			return true
		})
		var buf bytes.Buffer
		_ = printer.Fprint(&buf, token.NewFileSet(), fn.Body) // formatting-independent
		m.hash = sha256.Sum256(buf.Bytes())
		out[fn.Name.Name] = m
	}
}

func git(args ...string) ([]byte, error) {
	return exec.Command("git", args...).Output()
}

func snapshotAt(commit, date, subject string) snapshot {
	s := snapshot{commit: commit, date: date, subject: subject, tests: map[string]measure{}}
	files, _ := git("ls-tree", "-r", "--name-only", commit)
	for _, path := range strings.Split(string(files), "\n") {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := git("show", commit+":"+path)
		if err != nil {
			continue
		}
		s.testLines += bytes.Count(src, []byte("\n"))
		measureFile(src, s.tests)
	}
	return s
}

func manifest() []string {
	b, err := os.ReadFile("rails.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "momentum: run from the repository root:", err)
		os.Exit(2)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0]); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// move is how one safety test changed between two versions.
type move struct {
	name, kind    string
	before, after int
}

func compare(rails []string, prev, cur snapshot) (moves []move) {
	for _, n := range rails {
		a, hadA := prev.tests[n]
		b, hasB := cur.tests[n]
		switch {
		case !hadA && hasB:
			moves = append(moves, move{n, "new", 0, b.checks})
		case hadA && !hasB:
			moves = append(moves, move{n, "removed", a.checks, 0})
		case hadA && hasB && a.hash != b.hash:
			kind := "reworded"
			switch {
			case b.size < a.size || b.checks < a.checks:
				kind = "shrank"
			case b.size > a.size:
				kind = "grew"
			}
			moves = append(moves, move{n, kind, a.checks, b.checks})
		}
	}
	return moves
}

func totals(rails []string, s snapshot) (present, railChecks, allTests, allChecks int) {
	for _, n := range rails {
		if m, ok := s.tests[n]; ok {
			present++
			railChecks += m.checks
		}
	}
	for _, m := range s.tests {
		allTests++
		allChecks += m.checks
	}
	return
}

func main() {
	n := flag.Int("n", 30, "how many of the latest versions to show")
	chart := flag.String("chart", "", "also write a Mermaid chart to this file")
	warn := flag.Bool("warn", false, "print GitHub warning annotations for the newest version")
	flag.Parse()
	rails := manifest()

	log, err := git("log", "--first-parent", "--reverse", "--format=%h%x09%cs%x09%s")
	if err != nil {
		fmt.Fprintln(os.Stderr, "momentum: git log failed (a full clone is needed):", err)
		os.Exit(2)
	}
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	if len(lines) > *n+1 {
		lines = lines[len(lines)-*n-1:]
	}
	var snaps []snapshot
	for _, l := range lines {
		if f := strings.SplitN(l, "\t", 3); len(f) == 3 {
			snaps = append(snaps, snapshotAt(f[0], f[1], f[2]))
		}
	}
	if len(snaps) == 0 {
		return
	}

	fmt.Println("| Version | Date | Safety tests | Checks in them | All tests | All checks | What moved |")
	fmt.Println("|---|---|---|---|---|---|---|")
	var flags []string
	var xs []string
	var railSeries, allSeries []int
	for i, s := range snaps {
		present, railChecks, allTests, allChecks := totals(rails, s)
		summary := "first version shown"
		if i > 0 {
			moves := compare(rails, snaps[i-1], s)
			count := map[string]int{}
			for _, m := range moves {
				count[m.kind]++
				if m.kind == "shrank" || m.kind == "removed" {
					flags = append(flags, fmt.Sprintf("%s (%s): **%s %s**, checks %d → %d. %s", s.commit, s.date, m.name, m.kind, m.before, m.after, s.subject))
					if *warn && i == len(snaps)-1 {
						fmt.Fprintf(os.Stderr, "::warning::safety test %s %s in this change (checks %d -> %d)\n", m.name, m.kind, m.before, m.after)
					}
				}
			}
			var parts []string
			for _, k := range []string{"new", "grew", "reworded", "shrank", "removed"} {
				if count[k] > 0 {
					label := k
					if k == "shrank" || k == "removed" {
						label = "**" + k + "**"
					}
					parts = append(parts, fmt.Sprintf("%d %s", count[k], label))
				}
			}
			summary = strings.Join(parts, ", ")
			if summary == "" {
				summary = "no safety test touched"
			}
		}
		if i == 0 && len(snaps) > 1 {
			continue // only a baseline for the first comparison
		}
		fmt.Printf("| %s | %s | %d | %d | %d | %d | %s |\n", s.commit, s.date, present, railChecks, allTests, allChecks, summary)
		xs = append(xs, fmt.Sprint(len(xs)+1))
		railSeries = append(railSeries, railChecks)
		allSeries = append(allSeries, allChecks)
	}
	fmt.Println()
	if len(flags) == 0 {
		fmt.Println("No safety test shrank or disappeared in these versions.")
	} else {
		fmt.Println("Worth a look (a safety test lost checks or disappeared):")
		for _, f := range flags {
			fmt.Println("- " + f)
		}
	}
	if *chart != "" {
		top := 10
		for _, v := range allSeries {
			if v > top {
				top = v
			}
		}
		join := func(v []int) string {
			ss := make([]string, len(v))
			for i, x := range v {
				ss[i] = fmt.Sprint(x)
			}
			return strings.Join(ss, ", ")
		}
		mmd := fmt.Sprintf("xychart-beta\n  title \"Checks per version\"\n  x-axis \"version\" [%s]\n  y-axis \"checks\" 0 --> %d\n  line [%s]\n  line [%s]\n",
			strings.Join(xs, ", "), top+top/10, join(allSeries), join(railSeries))
		_ = os.WriteFile(*chart, []byte(mmd), 0o644)
	}
}
