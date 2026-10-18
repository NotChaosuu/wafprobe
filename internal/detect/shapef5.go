package detect

import (
	"regexp"
	"strconv"
)

// Shape / F5 XC Bot Defense. The sensor adds X-<8-char-id>-<letter>[<digit>]
// headers (Z is always "q"), and the JS bundle has those names as literals,
// so a body regex is enough. High confidence needs 2+ matches on the same id.

type shapef5 struct{}

func (shapef5) Vendor() string { return "shape-f5" }

// X-<id>-<letter>[<digit>] header family.
var shapeHeaderPattern = regexp.MustCompile(`X-[A-Za-z0-9]{6,12}-[A-Z][0-9]?\b`)

var shapeIDPattern = regexp.MustCompile(`X-([A-Za-z0-9]{6,12})-[A-Z][0-9]?\b`)

// shapeScriptRef only matches anchored refs like src="/_shape_/..." or "f5-cc".
var shapeScriptRef = regexp.MustCompile(`(?i)(?:[/"'\s]_shape_|_shape_[/"'\s]|[/"'\s]f5-cc[/"'.\- ])`)

func (shapef5) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var (
		signals         []string
		hasInterruption bool // Shape/F5 block interstitial ("pardon our interruption")
		hasScriptRef    bool // anchored Shape/F5 sensor script reference
		hasShapeHeaders bool
	)

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
					signals = append(signals, "body:shape-headers id="+id+" count="+strconv.Itoa(count))
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
			}
		}
	}

	if resp.bodyHas("pardon our interruption") ||
		resp.bodyHas("we've seen some unusual activity") ||
		resp.bodyHas("we apologize for the inconvenience") {
		signals = append(signals, "body:shape-interruption-page")
		hasInterruption = true
	}
	if len(resp.Body) > 0 && shapeScriptRef.Match(resp.Body) {
		signals = append(signals, "body:shape-script-ref")
		hasScriptRef = true
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

	// a lone TS cookie or F5 server header is just BIG-IP, not Shape.
	shapeSpecific := hasShapeHeaders || hasInterruption || hasScriptRef
	det := &Detection{}
	if shapeSpecific {
		det.Vendor = "shape-f5"
		if hasShapeHeaders || hasInterruption {
			det.Confidence = "high"
		} else {
			det.Confidence = "medium" // script-ref alone
		}
	} else {
		det.Vendor = "f5-bigip"
		det.Confidence = "medium"
	}
	det.Signals = signals

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case hasInterruption:
		det.Layer = LayerChallenge
		det.Blocked = true
	case resp.StatusCode == 403:
		det.Layer = LayerHTTP
		det.Blocked = true
	case resp.StatusCode >= 500:
		det.Layer = LayerHTTP
		det.Blocked = true
	case shapeSpecific && resp.StatusCode < 400:
		// sensor on a passing page; the next protected POST needs the headers
		det.Layer = LayerSensor
		det.Blocked = false
	default:
		det.Layer, det.Blocked = statusLayer(resp)
	}

	return det
}

func init() { Register(shapef5{}) }

// looksLikeTSCookie matches TS<hex> strictly so TSESSIONID/TSTOKEN don't.
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
