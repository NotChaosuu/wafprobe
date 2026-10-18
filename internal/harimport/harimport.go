// Package harimport turns a request from a HAR 1.2 file into a Captured
// persona that hunt can replay via --persona-file. That's the only way to test
// sites whose JS-injected headers (Shape, Akamai _abck, Kasada x-kpsdk-*)
// can't be synthesized.
package harimport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// Captured is the persona file written to disk. Flat JSON, hand-editable.
type Captured struct {
	Schema    string `json:"schema"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	UserAgent string `json:"user_agent,omitempty"`
	Cookie    string `json:"cookie,omitempty"`
	// Headers keeps browser order; UA, Cookie, Host and pseudo-headers are excluded.
	Headers []persona.HeaderField `json:"headers,omitempty"`
	BodyB64 string                `json:"body_b64,omitempty"`
	Notes   string                `json:"notes,omitempty"`
}

// SchemaTag identifies files this tool writes. Bumped on breaking changes.
const SchemaTag = "wafprobe-captured-persona/v2"

// HAR is the subset of HAR 1.2 we read.
type HAR struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []Entry `json:"entries"`
	} `json:"log"`
}

type Entry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Request         Request `json:"request"`
}

type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	Cookies     []NameValue `json:"cookies"`
	PostData    *PostData   `json:"postData,omitempty"`
}

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PostData struct {
	MimeType string      `json:"mimeType"`
	Text     string      `json:"text"`
	Params   []NameValue `json:"params,omitempty"`
}

// Parse reads a HAR file from disk.
func Parse(path string) (*HAR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read HAR: %w", err)
	}
	var h HAR
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse HAR JSON: %w", err)
	}
	if len(h.Log.Entries) == 0 {
		return nil, errors.New("HAR contains no entries")
	}
	return &h, nil
}

// Pick returns the last entry whose URL contains filter (case-insensitive),
// usually the latest POST. Empty filter returns the first entry.
func (h *HAR) Pick(filter string) (*Entry, error) {
	if filter == "" {
		return &h.Log.Entries[0], nil
	}
	needle := strings.ToLower(filter)
	var matches []int
	for i, e := range h.Log.Entries {
		if strings.Contains(strings.ToLower(e.Request.URL), needle) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no HAR entry matches filter %q", filter)
	}
	idx := matches[len(matches)-1]
	return &h.Log.Entries[idx], nil
}

// PickAll returns every entry matching filter (case-insensitive substring on URL).
func (h *HAR) PickAll(filter string) []*Entry {
	if filter == "" {
		out := make([]*Entry, len(h.Log.Entries))
		for i := range h.Log.Entries {
			out[i] = &h.Log.Entries[i]
		}
		return out
	}
	needle := strings.ToLower(filter)
	var matches []*Entry
	for i, e := range h.Log.Entries {
		if strings.Contains(strings.ToLower(e.Request.URL), needle) {
			matches = append(matches, &h.Log.Entries[i])
		}
	}
	return matches
}

// ToCaptured converts a HAR entry into a Captured persona. Host,
// Content-Length and pseudo-headers are dropped; the body is base64'd.
func (e *Entry) ToCaptured(id, name string) *Captured {
	c := &Captured{
		Schema: SchemaTag,
		ID:     id,
		Name:   name,
		URL:    e.Request.URL,
		Method: e.Request.Method,
	}

	for _, h := range e.Request.Headers {
		lname := strings.ToLower(h.Name)
		switch {
		case lname == "user-agent":
			c.UserAgent = h.Value
		case lname == "cookie":
			c.Cookie = h.Value
		case lname == "host", lname == "content-length":
		case strings.HasPrefix(lname, ":"):
		default:
			c.Headers = append(c.Headers, persona.HeaderField{Name: h.Name, Value: h.Value})
		}
	}

	// some exporters only fill the cookies array
	if c.Cookie == "" && len(e.Request.Cookies) > 0 {
		var parts []string
		for _, ck := range e.Request.Cookies {
			parts = append(parts, ck.Name+"="+ck.Value)
		}
		c.Cookie = strings.Join(parts, "; ")
	}

	if pd := e.Request.PostData; pd != nil {
		switch {
		case pd.Text != "":
			c.BodyB64 = base64.StdEncoding.EncodeToString([]byte(pd.Text))
		case len(pd.Params) > 0 && strings.Contains(strings.ToLower(pd.MimeType), "x-www-form-urlencoded"):
			// params instead of text: rebuild in HAR order, not url.Values.Encode
			// (which sorts). Shape and Kasada look at body field order.
			var b strings.Builder
			for i, p := range pd.Params {
				if i > 0 {
					b.WriteByte('&')
				}
				b.WriteString(url.QueryEscape(p.Name))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(p.Value))
			}
			c.BodyB64 = base64.StdEncoding.EncodeToString([]byte(b.String()))
		}
	}

	return c
}

// LoadCaptured reads a Captured JSON file and validates its schema tag.
func LoadCaptured(path string) (*Captured, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read captured persona: %w", err)
	}
	// check the tag first so old v1 files get a clear error, not a json type error
	var tag struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return nil, fmt.Errorf("parse captured persona JSON: %w", err)
	}
	if tag.Schema != SchemaTag {
		if strings.HasPrefix(tag.Schema, "wafprobe-captured-persona/") {
			return nil, fmt.Errorf("captured persona was written by an older wafprobe (schema %q, want %q) — re-run `wafprobe import-har` to regenerate it", tag.Schema, SchemaTag)
		}
		return nil, fmt.Errorf("not a wafprobe captured persona (schema %q, want %q)", tag.Schema, SchemaTag)
	}
	var c Captured
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse captured persona JSON: %w", err)
	}
	return &c, nil
}

// SaveCaptured writes a Captured persona as JSON.
func SaveCaptured(path string, c *Captured) error {
	if c.Schema == "" {
		c.Schema = SchemaTag
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// holds session cookies and auth headers, so owner-only
	return os.WriteFile(path, data, 0o600)
}

// Body returns the decoded body bytes, or nil if there's no body.
func (c *Captured) Body() ([]byte, error) {
	if c.BodyB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(c.BodyB64)
}

// Summarize returns a short human-readable description.
func (c *Captured) Summarize() string {
	var parts []string
	if c.UserAgent != "" {
		ua := c.UserAgent
		if len(ua) > 60 {
			ua = ua[:60] + "..."
		}
		parts = append(parts, fmt.Sprintf("UA: %s", ua))
	}
	if c.Cookie != "" {
		parts = append(parts, fmt.Sprintf("Cookie: %d bytes", len(c.Cookie)))
	}
	if len(c.Headers) > 0 {
		parts = append(parts, fmt.Sprintf("Headers: %d", len(c.Headers)))
	}
	if c.BodyB64 != "" {
		body, _ := c.Body()
		parts = append(parts, fmt.Sprintf("Body: %d bytes", len(body)))
	}
	return fmt.Sprintf("[%s %s] %s", c.Method, c.URL, strings.Join(parts, ", "))
}
