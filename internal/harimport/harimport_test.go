package harimport

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// realisticHAR is a HAR fixture modelled on a Shape-protected POST.
const realisticHAR = `{
  "log": {
    "version": "1.2",
    "creator": {"name": "WebInspector", "version": "537.36"},
    "entries": [
      {
        "startedDateTime": "2026-04-28T07:30:00.000Z",
        "request": {
          "method": "GET",
          "url": "https://www.uniqlo.com/us/auth/v1/login",
          "httpVersion": "h2",
          "headers": [
            {"name": ":method", "value": "GET"},
            {"name": ":authority", "value": "www.uniqlo.com"},
            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0) Chrome/147"},
            {"name": "Host", "value": "www.uniqlo.com"}
          ],
          "cookies": []
        }
      },
      {
        "startedDateTime": "2026-04-28T07:30:05.000Z",
        "request": {
          "method": "POST",
          "url": "https://www.uniqlo.com/us/api/auth/v1/login",
          "httpVersion": "h2",
          "headers": [
            {"name": ":method", "value": "POST"},
            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"},
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Origin", "value": "https://www.uniqlo.com"},
            {"name": "X-I1ysm4mm-A", "value": "3GboyrkJOZtyGtQ69q9URPx4OZU=="},
            {"name": "X-I1ysm4mm-B", "value": "tb6zsr"},
            {"name": "X-I1ysm4mm-C", "value": "AMCl_c-dAQAALZvvPF4ydMOjBhYW"},
            {"name": "X-I1ysm4mm-D", "value": "ABaAhIDBCKGFgQGAAYIQgISigaIA"},
            {"name": "X-I1ysm4mm-F", "value": "Ay-BF9CdAQAAQhpBnq3SpKCNgm8c"},
            {"name": "X-I1ysm4mm-Z", "value": "q"},
            {"name": "Cookie", "value": "session=abc123; csrf=xyz789"}
          ],
          "cookies": [
            {"name": "session", "value": "abc123"},
            {"name": "csrf", "value": "xyz789"}
          ],
          "postData": {
            "mimeType": "application/json",
            "text": "{\"username\":\"x\",\"password\":\"y\"}"
          }
        }
      }
    ]
  }
}`

func writeFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.har")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParse_BasicShape(t *testing.T) {
	path := writeFixture(t, realisticHAR)
	h, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(h.Log.Entries) != 2 {
		t.Errorf("entries=%d want 2", len(h.Log.Entries))
	}
	if h.Log.Version != "1.2" {
		t.Errorf("version=%q want 1.2", h.Log.Version)
	}
}

func TestParse_FileNotFound(t *testing.T) {
	_, err := Parse(filepath.Join(t.TempDir(), "nonexistent.har"))
	if err == nil {
		t.Fatal("expected err for missing file")
	}
}

func TestParse_BadJSON(t *testing.T) {
	path := writeFixture(t, "not valid json")
	_, err := Parse(path)
	if err == nil {
		t.Fatal("expected err for invalid JSON")
	}
}

func TestParse_NoEntries(t *testing.T) {
	path := writeFixture(t, `{"log":{"version":"1.2","entries":[]}}`)
	_, err := Parse(path)
	if err == nil {
		t.Fatal("expected err for empty entries")
	}
}

func TestPick_FilterFindsLastMatch(t *testing.T) {
	path := writeFixture(t, realisticHAR)
	h, _ := Parse(path)

	// "uniqlo" matches both entries; Pick should return the last one (POST).
	e, err := h.Pick("uniqlo")
	if err != nil {
		t.Fatal(err)
	}
	if e.Request.Method != "POST" {
		t.Errorf("expected POST (last match), got %s", e.Request.Method)
	}

	e, err = h.Pick("auth/v1/login")
	if err != nil {
		t.Fatal(err)
	}
	if e.Request.Method != "POST" {
		t.Errorf("expected POST, got %s", e.Request.Method)
	}

	e, err = h.Pick("api/auth")
	if err != nil {
		t.Fatal(err)
	}
	if e.Request.Method != "POST" {
		t.Errorf("expected POST, got %s", e.Request.Method)
	}
}

func TestPick_NoMatch(t *testing.T) {
	path := writeFixture(t, realisticHAR)
	h, _ := Parse(path)
	_, err := h.Pick("does-not-exist")
	if err == nil {
		t.Fatal("expected err for no match")
	}
}

func TestPick_EmptyFilter_PicksFirst(t *testing.T) {
	path := writeFixture(t, realisticHAR)
	h, _ := Parse(path)
	e, err := h.Pick("")
	if err != nil {
		t.Fatal(err)
	}
	if e.Request.Method != "GET" {
		t.Errorf("empty filter should pick first entry (GET), got %s", e.Request.Method)
	}
}

// Shape's X-<id>-<letter> headers must survive conversion.
func TestToCaptured_PreservesShapeHeaders(t *testing.T) {
	path := writeFixture(t, realisticHAR)
	h, _ := Parse(path)
	e, _ := h.Pick("api/auth")
	c := e.ToCaptured("captured:test", "test capture")

	val := func(name string) (string, bool) {
		for _, h := range c.Headers {
			if strings.EqualFold(h.Name, name) {
				return h.Value, true
			}
		}
		return "", false
	}

	// UA hoisted out of Headers.
	if c.UserAgent == "" {
		t.Error("UserAgent should be set")
	}
	if _, ok := val("User-Agent"); ok {
		t.Error("User-Agent should NOT remain in Headers")
	}

	if c.Cookie == "" {
		t.Error("Cookie should be set")
	}

	// Pseudo-headers stripped.
	for _, h := range c.Headers {
		if strings.HasPrefix(h.Name, ":") {
			t.Errorf("pseudo-header %q leaked into Headers", h.Name)
		}
	}

	if _, ok := val("Host"); ok {
		t.Error("Host should be stripped")
	}

	// Shape header family preserved.
	want := []string{"X-I1ysm4mm-A", "X-I1ysm4mm-B", "X-I1ysm4mm-C", "X-I1ysm4mm-D", "X-I1ysm4mm-F", "X-I1ysm4mm-Z"}
	for _, h := range want {
		if _, ok := val(h); !ok {
			t.Errorf("captured persona missing critical Shape header %q", h)
		}
	}

	if v, _ := val("Origin"); v != "https://www.uniqlo.com" {
		t.Errorf("Origin header lost: %q", v)
	}
	if v, _ := val("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type header lost: %q", v)
	}

	// Body round-trips via base64.
	body, err := c.Body()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"username":"x","password":"y"}` {
		t.Errorf("body mismatch: %q", string(body))
	}
}

func TestToCaptured_ReconstructsCookieFromArray(t *testing.T) {
	// no Cookie header, only the cookies array
	har := `{
  "log": {"version":"1.2","entries":[{"startedDateTime":"x","request":{
    "method":"GET","url":"https://x.com/","httpVersion":"h2",
    "headers":[],
    "cookies":[{"name":"a","value":"1"},{"name":"b","value":"2"}]
  }}]}}`
	path := writeFixture(t, har)
	h, _ := Parse(path)
	e, _ := h.Pick("")
	c := e.ToCaptured("t", "t")
	if c.Cookie != "a=1; b=2" {
		t.Errorf("cookie reconstruction failed: %q", c.Cookie)
	}
}

func TestSaveAndLoadCaptured_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cap.json")
	in := &Captured{
		Schema:    SchemaTag,
		ID:        "cap1",
		Name:      "test",
		URL:       "https://x.com/login",
		Method:    "POST",
		UserAgent: "TestUA/1.0",
		Cookie:    "a=b",
		Headers:   []persona.HeaderField{{Name: "X-Test", Value: "1"}, {Name: "Origin", Value: "https://x.com"}},
		BodyB64:   base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	if err := SaveCaptured(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadCaptured(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != in.ID || out.UserAgent != in.UserAgent || out.Cookie != in.Cookie {
		t.Errorf("roundtrip mismatch: %+v vs %+v", in, out)
	}
	body, _ := out.Body()
	if string(body) != "hello" {
		t.Errorf("body mismatch: %q", string(body))
	}
	if len(out.Headers) != len(in.Headers) {
		t.Errorf("headers lost: %d vs %d", len(out.Headers), len(in.Headers))
	}
}

func TestLoadCaptured_RejectsWrongSchema(t *testing.T) {
	path := writeFixture(t, `{"schema":"old-format/v0","id":"x"}`)
	_, err := LoadCaptured(path)
	if err == nil || !strings.Contains(err.Error(), "not a wafprobe captured persona") {
		t.Errorf("non-wafprobe schema should be rejected clearly: %v", err)
	}
}

// a v1 file (headers as an object) gets the "re-run import-har" message
func TestLoadCaptured_OldVersionFriendlyError(t *testing.T) {
	v1 := `{"schema":"wafprobe-captured-persona/v1","id":"x","headers":{"X-A":"1"}}`
	path := writeFixture(t, v1)
	_, err := LoadCaptured(path)
	if err == nil {
		t.Fatal("expected an error for an old-schema file")
	}
	if !strings.Contains(err.Error(), "older wafprobe") || !strings.Contains(err.Error(), "import-har") {
		t.Errorf("old-schema error should tell the user to re-run import-har: %v", err)
	}
}

func TestSummarize_HumanReadable(t *testing.T) {
	c := &Captured{
		Method:    "POST",
		URL:       "https://x.com/login",
		UserAgent: "TestUA/1.0",
		Cookie:    "a=b; c=d",
		Headers:   []persona.HeaderField{{Name: "X-A", Value: "1"}, {Name: "X-B", Value: "2"}},
		BodyB64:   base64.StdEncoding.EncodeToString([]byte("hello world")),
	}
	out := c.Summarize()
	for _, want := range []string{"POST", "https://x.com/login", "TestUA", "Cookie:", "Headers: 2", "Body: 11"} {
		if !strings.Contains(out, want) {
			t.Errorf("Summarize() missing %q in: %s", want, out)
		}
	}
}
