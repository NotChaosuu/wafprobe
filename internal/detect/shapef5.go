package detect

import "regexp"

// Shape Security / F5 XC Bot Defense.
//
// Shape's JS sensor injects a family of request headers on every protected
// XHR with the pattern X-<8-char-id>-<letter>[<digit>]. The 8-char id is
// randomized per deployment but stable per site, and the Z header is
// always literal "q". The sensor JS bundle in the page references those
// header NAMES as string literals, so a body regex on the names is enough
// to identify Shape without seeing outgoing browser traffic.
//
// We claim "high" confidence only when 2+ matches share the same id —
// random co-occurrence of e.g. X-Foo-A and X-Foo-Z in unrelated content
// is implausible.

type shapef5 struct{}

func (shapef5) Vendor() string { return "shape-f5" }

// X-<id>-<letter>[<digit>] header family.
var shapeHeaderPattern = regexp.MustCompile(`X-[A-Za-z0-9]{6,12}-[A-Z][0-9]?\b`)

// Captures the id portion so we can group matches.
var shapeIDPattern = regexp.MustCompile(`X-([A-Za-z0-9]{6,12})-[A-Z][0-9]?\b`)

func (shapef5) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var (
		signals    []string
		hasTS      bool
		hasBodySig bool
		hasShapeHeaders bool
	)

	// Match the header NAMES as string literals in the page's JS bundle.
	if len(resp.Body) > 0 {
		matches := shapeHeaderPattern.FindAll(resp.Body, -1)
		if len(matches) >= 2 {
			ids := map[string]int{}
			for _, m := range matches {
				if id := shapeIDPattern.FindSubmatch(m); len(id) > 1 {
					ids[string(id[1])]++
				}
			}
			for id, count := range ids {
				if count >= 2 {
					signals = append(signals, "body:shape-headers id="+id+" count="+itoa(count))
					hasShapeHeaders = true
					break
				}
			}
		}
	}

	for _, c := range resp.Cookies {
		if hasPrefixFold(c.Name, "TS") && len(c.Name) >= 4 && len(c.Name) <= 24 {
			if looksLikeTSCookie(c.Name) {
				signals = append(signals, "cookie:"+c.Name)
				hasTS = true
			}
		}
	}

	if bodyContains(resp.Body, "pardon our interruption") ||
		bodyContains(resp.Body, "we've seen some unusual activity") ||
		bodyContains(resp.Body, "we apologize for the inconvenience") {
		signals = append(signals, "body:shape-interruption-page")
		hasBodySig = true
	}
	if bodyContains(resp.Body, "_shape_") || bodyContains(resp.Body, "f5-cc") {
		signals = append(signals, "body:shape-script-ref")
		hasBodySig = true
	}

	if server, ok := hasHeader(resp.Header, "Server"); ok &&
		(hasPrefixFold(server, "BigIP") || hasPrefixFold(server, "BIG-IP") || hasPrefixFold(server, "F5")) {
		signals = append(signals, "header:server="+server)
	}
	if _, ok := hasHeader(resp.Header, "X-Cnection"); ok {
		signals = append(signals, "header:x-cnection (F5 classic)")
	}

	if len(signals) == 0 {
		return nil
	}

	confidence := "medium"
	switch {
	case hasShapeHeaders, hasBodySig:
		confidence = "high"
	case hasTS:
		// TS cookie alone could be vanilla BIG-IP without Shape.
		confidence = "medium"
	}

	det := &Detection{
		Vendor:     "shape-f5",
		Confidence: confidence,
		Signals:    signals,
	}

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case resp.StatusCode == 403 || hasBodySig:
		det.Layer = LayerChallenge
		det.Blocked = true
	case resp.StatusCode >= 500:
		det.Layer = LayerHTTP
		det.Blocked = true
	case hasShapeHeaders && resp.StatusCode == 200:
		// Shape sensor is deployed on this page but didn't block — but the
		// next protected POST will require the headers. Tag as sensor.
		det.Layer = LayerSensor
		det.Blocked = false
	default:
		det.Layer = LayerPass
		det.Blocked = false
	}

	return det
}

func init() { Register(shapef5{}) }

// looksLikeTSCookie matches F5's TS<hex> session cookie pattern. We need
// this strict form to avoid matching TSESSIONID / TSTOKEN / TSToken etc.
func looksLikeTSCookie(name string) bool {
	if len(name) < 3 {
		return false
	}
	if !hasPrefixFold(name[:2], "TS") {
		return false
	}
	rest := name[2:]
	for _, r := range rest {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// itoa avoids importing strconv just for a small helper.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
