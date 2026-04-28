// Package harimport reads HAR 1.2 files (Chrome/Firefox DevTools, Charles,
// Fiddler, mitmproxy) and converts a chosen request into a Captured persona
// JSON — a frozen snapshot of the User-Agent, headers, cookies, body, method.
//
// hunt loads these via --persona-file and replays them as the baseline,
// which is how we test sites whose JS-injected request headers (Shape,
// Akamai _abck, Kasada x-kpsdk-*) can only be observed, not synthesized.
package harimport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Captured is the persona file written to disk. Flat JSON, hand-editable.
type Captured struct {
	Schema    string            `json:"schema"`
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	UserAgent string            `json:"user_agent,omitempty"`
	Cookie    string            `json:"cookie,omitempty"`
	// Headers excludes User-Agent, Cookie, Host, and HTTP/2 pseudo-headers
	// (those are either hoisted to top-level fields or set by the transport).
	Headers map[string]string `json:"headers,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
	Notes   string            `json:"notes,omitempty"`
}

// SchemaTag identifies files this tool writes. Bumped on breaking changes.
const SchemaTag = "wafprobe-captured-persona/v1"

// HAR is the subset of HAR 1.2 we read. Hand-parsed to keep deps minimal.
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
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
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

// Pick returns one entry matching filter (case-insensitive substring on URL).
// Empty filter returns the first entry. If multiple match, the LAST one wins
// — usually the most-recent POST in a session is what you want.
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

// ToCaptured converts a HAR entry into a Captured persona. UA and Cookie
// are hoisted to top-level fields; Host, Content-Length, and HTTP/2 pseudo-
// headers (':method' etc) are dropped because the transport sets them.
// Body is base64-encoded so binary payloads survive the JSON round-trip.
func (e *Entry) ToCaptured(id, name string) *Captured {
	c := &Captured{
		Schema:  SchemaTag,
		ID:      id,
		Name:    name,
		URL:     e.Request.URL,
		Method:  e.Request.Method,
		Headers: map[string]string{},
	}

	for _, h := range e.Request.Headers {
		lname := strings.ToLower(h.Name)
		switch {
		case lname == "user-agent":
			c.UserAgent = h.Value
		case lname == "cookie":
			c.Cookie = h.Value
		case lname == "host", lname == "content-length":
			// transport sets these; ignore
		case strings.HasPrefix(lname, ":"):
			// HTTP/2 pseudo-header
		default:
			c.Headers[h.Name] = h.Value
		}
	}

	// Some HAR exporters split cookies into the Cookies array instead of
	// a single Cookie header — reconstruct it.
	if c.Cookie == "" && len(e.Request.Cookies) > 0 {
		var parts []string
		for _, ck := range e.Request.Cookies {
			parts = append(parts, ck.Name+"="+ck.Value)
		}
		c.Cookie = strings.Join(parts, "; ")
	}

	if e.Request.PostData != nil && e.Request.PostData.Text != "" {
		c.BodyB64 = base64.StdEncoding.EncodeToString([]byte(e.Request.PostData.Text))
	}

	return c
}

// LoadCaptured reads a Captured JSON file and validates its schema tag.
func LoadCaptured(path string) (*Captured, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read captured persona: %w", err)
	}
	var c Captured
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse captured persona JSON: %w", err)
	}
	if c.Schema != SchemaTag {
		return nil, fmt.Errorf("captured persona schema mismatch: got %q, want %q", c.Schema, SchemaTag)
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
	return os.WriteFile(path, data, 0644)
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
