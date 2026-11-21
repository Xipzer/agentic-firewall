package main

import "testing"

func at(src string) snapshot {
	s := snapshot{tests: map[string]measure{}}
	measureFile([]byte("package p\nimport \"testing\"\n"+src), s.tests)
	return s
}

const strong = `func TestRails(t *testing.T) {
	cases := []struct{ ip string; want int }{{"1.1.1.1", 1}, {"10.0.0.1", 1}, {"45.9.20.7", 4}}
	for _, c := range cases {
		if got := decide(c.ip); got != c.want {
			t.Errorf("%s: %d", c.ip, got)
		}
	}
	if !protected("1.1.1.1") {
		t.Fatal("unprotected")
	}
}`

func TestMomentumNamesEveryKindOfMove(t *testing.T) {
	rails := []string{"TestRails"}
	base := at(strong)
	cases := map[string]string{
		// formatting and comments are not a change
		"": "func TestRails(t *testing.T) {\n\n\t// note\n\tcases := []struct{ ip string; want int }{{\"1.1.1.1\", 1}, {\"10.0.0.1\", 1}, {\"45.9.20.7\", 4}}\n\tfor _, c := range cases {\n\t\tif got := decide(c.ip); got != c.want {\n\t\t\tt.Errorf(\"%s: %d\", c.ip, got)\n\t\t}\n\t}\n\tif !protected(\"1.1.1.1\") {\n\t\tt.Fatal(\"unprotected\")\n\t}\n}",
		// a table row dropped
		"shrank": `func TestRails(t *testing.T) {
	cases := []struct{ ip string; want int }{{"10.0.0.1", 1}, {"45.9.20.7", 4}}
	for _, c := range cases {
		if got := decide(c.ip); got != c.want {
			t.Errorf("%s: %d", c.ip, got)
		}
	}
	if !protected("1.1.1.1") {
		t.Fatal("unprotected")
	}
}`,
		// an expected value quietly changed: same size, so it is named as reworded
		"reworded": `func TestRails(t *testing.T) {
	cases := []struct{ ip string; want int }{{"1.1.1.1", 4}, {"10.0.0.1", 1}, {"45.9.20.7", 4}}
	for _, c := range cases {
		if got := decide(c.ip); got != c.want {
			t.Errorf("%s: %d", c.ip, got)
		}
	}
	if !protected("1.1.1.1") {
		t.Fatal("unprotected")
	}
}`,
		"removed": `func TestSomethingElse(t *testing.T) {}`,
		"grew": `func TestRails(t *testing.T) {
	cases := []struct{ ip string; want int }{{"1.1.1.1", 1}, {"10.0.0.1", 1}, {"45.9.20.7", 4}, {"::1", 1}}
	for _, c := range cases {
		if got := decide(c.ip); got != c.want {
			t.Errorf("%s: %d", c.ip, got)
		}
	}
	if !protected("1.1.1.1") {
		t.Fatal("unprotected")
	}
}`,
	}
	for want, src := range cases {
		moves := compare(rails, base, at(src))
		got := ""
		if len(moves) == 1 {
			got = moves[0].kind
		}
		if got != want {
			t.Errorf("want %q, got %q (%+v)", want, got, moves)
		}
	}
	if m := compare(rails, at(""), base); len(m) != 1 || m[0].kind != "new" || m[0].after != 5 {
		t.Errorf("new test: %+v", m)
	}
	// An emptied body is the clearest shrink of all.
	if m := compare(rails, base, at("func TestRails(t *testing.T) {}")); m[0].kind != "shrank" || m[0].after != 0 {
		t.Errorf("gutted test: %+v", m)
	}
}
