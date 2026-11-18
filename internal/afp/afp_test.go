package afp

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const specDir = "../../spec/afp/0.1"

func compileSchemas(t *testing.T) map[Type]*jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	files, _ := filepath.Glob(filepath.Join(specDir, "*.schema.json"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := c.AddResource("https://agentic-firewall.dev/afp/0.1/"+filepath.Base(f), doc); err != nil {
			t.Fatal(err)
		}
	}
	out := map[Type]*jsonschema.Schema{}
	for _, ty := range []Type{TypeObservation, TypeVerdict, TypeEscalation, TypeRule, TypeExplanation} {
		s, err := c.Compile("https://agentic-firewall.dev/afp/0.1/" + string(ty) + ".schema.json")
		if err != nil {
			t.Fatalf("compile %s: %v", ty, err)
		}
		out[ty] = s
	}
	return out
}

func schemaCheck(t *testing.T, s *jsonschema.Schema, b []byte) error {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(doc)
}

// Examples must pass both the normative schema and the Go validator, and
// survive a round trip, so the spec and the implementation cannot drift.
func TestExamplesMatchSchemaAndGo(t *testing.T) {
	schemas := compileSchemas(t)
	for ty, s := range schemas {
		raw, err := os.ReadFile(filepath.Join(specDir, "examples", string(ty)+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := schemaCheck(t, s, raw); err != nil {
			t.Errorf("%s example fails schema: %v", ty, err)
		}
		msg, err := Decode(raw)
		if err != nil {
			t.Errorf("%s example fails Go validation: %v", ty, err)
			continue
		}
		again, _ := json.Marshal(msg)
		if err := schemaCheck(t, s, again); err != nil {
			t.Errorf("%s round trip fails schema: %v\n%s", ty, err, again)
		}
	}
}

func TestGeneratedMessagesMatchSchema(t *testing.T) {
	schemas := compileSchemas(t)
	src := Source{Tier: TierFast, Agent: "test"}
	v := &Verdict{Envelope: NewEnvelope(TypeVerdict, src), Subject: HostSubject(netip.MustParseAddr("::ffff:198.51.100.4")),
		Action: ActionDrop, Confidence: 0.9, TTL: FormatTTL(90 * time.Minute), Reason: "test"}
	if v.Subject.Value != "198.51.100.4" {
		t.Fatalf("4in6 not unmapped: %s", v.Subject.Value)
	}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if err := schemaCheck(t, schemas[TypeVerdict], b); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
}

func TestVerdictRules(t *testing.T) {
	schemas := compileSchemas(t)
	base := func() Verdict {
		return Verdict{Envelope: NewEnvelope(TypeVerdict, Source{Tier: TierFast, Agent: "t"}),
			Subject: Subject{SubjectHost, "203.0.113.9"}, Action: ActionDrop, Confidence: 0.5, TTL: "10m", Reason: "x"}
	}
	cases := map[string]func(*Verdict){
		"drop without ttl":   func(v *Verdict) { v.TTL = "" },
		"bad action":         func(v *Verdict) { v.Action = "nuke" },
		"confidence > 1":     func(v *Verdict) { v.Confidence = 1.5 },
		"bad subject":        func(v *Verdict) { v.Subject.Value = "not-an-ip" },
		"missing reason":     func(v *Verdict) { v.Reason = " " },
		"wrong afp version":  func(v *Verdict) { v.AFP = "9" },
		"negative ttl value": func(v *Verdict) { v.TTL = "-5m" },
	}
	for name, mut := range cases {
		v := base()
		mut(&v)
		if v.Validate() == nil {
			t.Errorf("%s: Go validator accepted", name)
		}
		b, _ := json.Marshal(&v)
		if name != "bad subject" && name != "missing reason" && schemaCheck(t, schemas[TypeVerdict], b) == nil {
			t.Errorf("%s: schema accepted", name)
		}
	}
	allow := base()
	allow.Action, allow.TTL = ActionAllow, ""
	if err := allow.Validate(); err != nil {
		t.Errorf("allow without ttl should be valid: %v", err)
	}
}

func TestTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"10m": 10 * time.Minute, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "1.5h": 90 * time.Minute} {
		got, err := ParseTTL(in)
		if err != nil || got != want {
			t.Errorf("ParseTTL(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0s", "-1m", "forever", "d"} {
		if _, err := ParseTTL(bad); err == nil {
			t.Errorf("ParseTTL(%q) accepted", bad)
		}
	}
	if FormatTTL(48*time.Hour) != "2d" || FormatTTL(90*time.Second) != "90s" {
		t.Error("FormatTTL")
	}
}

func TestSubjectPrefix(t *testing.T) {
	p, err := Subject{SubjectPrefix, "203.0.113.77/24"}.Prefix()
	if err != nil || p.String() != "203.0.113.0/24" {
		t.Errorf("prefix not masked: %v %v", p, err)
	}
	p, _ = Subject{SubjectPrefix, "::ffff:203.0.113.0/120"}.Prefix()
	if p.String() != "203.0.113.0/24" {
		t.Errorf("4in6 prefix: %v", p)
	}
}
