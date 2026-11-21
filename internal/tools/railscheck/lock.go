package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The lock pins the exact content of every file a safety test depends on:
// all test files in any package that holds a safety test (so shared helpers
// are covered), the manifest, and the gate itself. Editing any of them makes
// the build fail until the lock is rewritten, so loosening a test can never
// be a quiet side effect of another change: it shows up as its own line in
// the lock's diff.

var gateFiles = []string{"rails.txt", "lab/rails.sh", "lab/run.sh", ".github/workflows/ci.yml"}

var testFunc = regexp.MustCompile(`(?m)^func (Test\w+)\(`)

// lockedFiles lists every file the lock covers, relative to root.
func lockedFiles(root string, required []string) ([]string, error) {
	want := map[string]bool{}
	for _, n := range required {
		want[n] = true
	}
	byDir := map[string][]string{}
	railDirs := map[string]bool{}
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n != "." && strings.HasPrefix(n, ".") && n != ".github" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		dir := filepath.ToSlash(filepath.Dir(rel))
		byDir[dir] = append(byDir[dir], rel)
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range testFunc.FindAllSubmatch(b, -1) {
			if want[string(m[1])] {
				railDirs[dir] = true
				found[string(m[1])] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, n := range required {
		if !found[n] {
			return nil, fmt.Errorf("safety test %s is in the manifest but not in the source", n)
		}
	}
	var out []string
	for dir := range railDirs {
		out = append(out, byDir[dir]...)
	}
	tool, _ := filepath.Glob(filepath.Join(root, "internal/tools/railscheck/*.go"))
	for _, f := range tool {
		rel, _ := filepath.Rel(root, f)
		out = append(out, filepath.ToSlash(rel))
	}
	out = append(out, gateFiles...)
	sort.Strings(out)
	uniq := out[:0]
	for i, f := range out {
		if i == 0 || f != out[i-1] {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Line endings are normalised so the same content hashes the same on every checkout.
	sum := sha256.Sum256([]byte(strings.ReplaceAll(string(b), "\r\n", "\n")))
	return hex.EncodeToString(sum[:]), nil
}

func computeLock(root string, required []string) (map[string]string, error) {
	files, err := lockedFiles(root, required)
	if err != nil {
		return nil, err
	}
	lock := map[string]string{}
	for _, f := range files {
		h, err := hashFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		lock[f] = h
	}
	return lock, nil
}

func formatLock(lock map[string]string) string {
	names := make([]string, 0, len(lock))
	for n := range lock {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Hashes of every file the safety tests depend on. Do not edit by hand.\n")
	b.WriteString("# Rewritten by: go run ./internal/tools/railscheck lock\n")
	b.WriteString("# A change here means a safety test, its helpers, the manifest or the gate changed.\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", lock[n], n)
	}
	return b.String()
}

func parseLock(text string) map[string]string {
	lock := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if f := strings.Fields(line); len(f) == 2 {
			lock[f[1]] = f[0]
		}
	}
	return lock
}

// diffLock describes how the tree differs from the recorded lock.
func diffLock(recorded, current map[string]string) []string {
	var out []string
	for f, h := range current {
		switch old, ok := recorded[f]; {
		case !ok:
			out = append(out, f+" is new and not in the lock")
		case old != h:
			out = append(out, f+" changed since it was locked")
		}
	}
	for f := range recorded {
		if _, ok := current[f]; !ok {
			out = append(out, f+" is in the lock but gone or no longer covered")
		}
	}
	sort.Strings(out)
	return out
}
