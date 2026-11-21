package daemon

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Xipzer/agentic-firewall/internal/afp"
	"github.com/Xipzer/agentic-firewall/internal/config"
	"github.com/Xipzer/agentic-firewall/internal/ui"
)

const uiTok = "0123456789abcdef0123456789abcdef0123456789abcdef"

func uiReq(h http.Handler, method, path, host, token, body string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The interface sits on a firewall, so who may ask it for what is a safety rail.
func TestInterfaceAccessRules(t *testing.T) {
	r, _ := newRig(t)
	r.bruteForce("103.77.1.9")
	const host = "127.0.0.1:7844"
	h := r.d.UIHandler(host, uiTok, false)

	// The page itself needs no token, but carries a strict policy.
	w := uiReq(h, "GET", "/", host, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "app.js") {
		t.Fatalf("page: %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") {
		t.Errorf("policy allows unsafe sources: %s", csp)
	}
	cases := []struct {
		name               string
		method, path, host string
		token, body        string
		hdr                []string
		code               int
	}{
		{"data without a token", "GET", "/api/state", host, "", "", nil, 401},
		{"data with a wrong token", "GET", "/api/state", host, strings.Repeat("f", 48), "", nil, 401},
		{"data with the token", "GET", "/api/state", host, uiTok, "", nil, 200},
		{"localhost name is the same machine", "GET", "/api/state", "localhost:7844", uiTok, "", nil, 200},
		{"another site's name pointed at us (DNS rebinding)", "GET", "/api/state", "evil.example:7844", uiTok, "", nil, 403},
		{"the page under a foreign name", "GET", "/", "evil.example", "", "", nil, 403},
		{"a cross-site request", "POST", "/api/do", host, uiTok, `{"action":"confirm"}`, []string{"Origin", "http://evil.example"}, 403},
		{"action without a token", "POST", "/api/do", host, "", `{"action":"panic"}`, nil, 401},
		{"unknown action", "POST", "/api/do", host, uiTok, `{"action":"format-disk"}`, nil, 400},
		{"writing to a page path", "POST", "/", host, "", "", nil, 405},
		{"path traversal", "GET", "/../../etc/passwd", host, "", "", nil, 404},
	}
	for _, c := range cases {
		if w := uiReq(h, c.method, c.path, c.host, c.token, c.body, c.hdr...); w.Code != c.code {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.code)
		}
	}

	// An action through the interface does what the command line does.
	if r.action("103.77.1.9") != afp.ActionDrop {
		t.Fatal("setup")
	}
	if w := uiReq(h, "POST", "/api/do", host, uiTok, `{"action":"unblock","subject":"103.77.1.9"}`); w.Code != 200 {
		t.Fatalf("unblock: %d %s", w.Code, w.Body)
	}
	if r.action("103.77.1.9") != "" {
		t.Fatal("unblock through the interface did not lift the block")
	}

	// Read-only: everything can be seen, nothing can be done.
	ro := r.d.UIHandler(host, uiTok, true)
	if w := uiReq(ro, "GET", "/api/state", host, uiTok, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"read_only":true`) {
		t.Fatalf("read-only state: %d", w.Code)
	}
	if w := uiReq(ro, "POST", "/api/do", host, uiTok, `{"action":"panic"}`); w.Code != 403 {
		t.Fatalf("read-only allowed an action: %d", w.Code)
	}
	// A LAN address is read-only whatever the caller asked for.
	lan := r.d.UIHandler("192.168.1.5:7844", uiTok, false)
	if w := uiReq(lan, "POST", "/api/do", "192.168.1.5:7844", uiTok, `{"action":"mode","value":"shadow"}`); w.Code != 403 {
		t.Fatalf("actions offered over the LAN: %d", w.Code)
	}
	if r.d.Guard.Mode() != "enforce" {
		t.Fatal("mode changed")
	}
	// And the config refuses that combination up front.
	cfg := config.Default()
	cfg.UI.Listen = "192.168.1.5:7844"
	if cfg.Validate() == nil {
		t.Error("a LAN listener with actions passed validation")
	}
	cfg.UI.ReadOnly = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("read-only LAN listener refused: %v", err)
	}
}

// Much of what the page shows was written by attackers. The script may only
// ever set text; one innerHTML would turn a probe's payload into code.
func TestInterfaceNeverWritesHTML(t *testing.T) {
	banned := regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setAttribute\('(on|href|src)|javascript:`)
	n := 0
	_ = fs.WalkDir(ui.Files, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(ui.Files, path)
		n++
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "no innerHTML anywhere") {
				continue // the comment that states the rule
			}
			if m := banned.FindString(line); m != "" {
				t.Errorf("%s:%d uses %q", path, i+1, m)
			}
		}
		if strings.Contains(string(b), "http://") || strings.Contains(string(b), "https://") || strings.Contains(string(b), "//cdn") {
			t.Errorf("%s refers to something outside this machine", path)
		}
		return nil
	})
	if n < 3 {
		t.Fatalf("only %d interface files found", n)
	}
}

// What the interface says matches what afw did, and hostile text arrives as data.
func TestInterfaceReportsTruthfully(t *testing.T) {
	r, _ := newRig(t)
	r.smallScan("45.9.20.7")
	r.bruteForce("103.77.1.9")
	r.propose("45.9.20.7", "drop", 1.0, `<img src=x onerror=alert(1)>`)
	const host = "127.0.0.1:7844"
	h := r.d.UIHandler(host, uiTok, false)
	get := func(path string, into any) string {
		w := uiReq(h, "GET", path, host, uiTok, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		b, _ := io.ReadAll(w.Body)
		if into != nil {
			if err := json.Unmarshal(b, into); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return string(b)
	}
	var st uiState
	get("/api/state", &st)
	got := map[string]afp.Action{}
	for _, x := range st.Restricted {
		got[x.Subject] = x.Action
	}
	if got["103.77.1.9"] != afp.ActionDrop || got["45.9.20.7"] != afp.ActionThrottle || len(got) != 2 {
		t.Fatalf("restricted list %v does not match what afw is doing", got)
	}
	if st.Day.Blocked < 1 || st.Mode != "enforce" {
		t.Fatalf("state: %+v", st)
	}
	var page struct {
		Items []Decision
		More  bool
	}
	get("/api/activity?show=drop", &page)
	if len(page.Items) == 0 || page.Items[0].Subject != "103.77.1.9" || page.Items[0].Summary == "" || page.Items[0].Class != "access.bruteforce" {
		t.Fatalf("activity: %+v", page.Items)
	}
	get("/api/activity?q=45.9", &page)
	for _, d := range page.Items {
		if d.Subject != "45.9.20.7" {
			t.Fatalf("search returned %s", d.Subject)
		}
	}
	var src SourceView
	body := get("/api/source?q=103.77.1.9", &src)
	if !src.Known || src.Restricted == nil || src.Latest == nil || len(src.Timeline) == 0 || len(src.Classes) == 0 {
		t.Fatalf("source view incomplete: %s", body)
	}
	get("/api/source?q=1.1.1.1", &src)
	if !src.Protected {
		t.Error("protected address not marked")
	}
	// The adviser's hostile text never reaches any view.
	for _, path := range []string{"/api/state", "/api/activity", "/api/source?q=45.9.20.7", "/api/coverage", "/api/system"} {
		if b := get(path, nil); strings.Contains(b, "onerror") {
			t.Errorf("%s carries the adviser's text", path)
		}
	}
	if w := uiReq(h, "GET", "/api/source?q=not-an-address", host, uiTok, ""); w.Code != 400 {
		t.Errorf("bad address: %d", w.Code)
	}
}
