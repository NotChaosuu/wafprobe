package detect

import (
	"net/http"
	"strings"
	"testing"
)

// Fixture builders.

func mkResp(status int, headers map[string]string, cookies []*http.Cookie, body string) *Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &Response{
		StatusCode: status,
		Header:     h,
		Cookies:    cookies,
		Body:       []byte(body),
	}
}

func ck(name, value string) *http.Cookie { return &http.Cookie{Name: name, Value: value} }

// Cloudflare

func TestCloudflare(t *testing.T) {
	tests := []struct {
		name     string
		resp     *Response
		wantHit  bool
		wantLayer Layer
		wantBlocked bool
	}{
		{
			"pass: 200 with cf-ray",
			mkResp(200, map[string]string{"CF-Ray": "1234abc", "Server": "cloudflare"}, nil, ""),
			true, LayerPass, false,
		},
		{
			"block: 403 with cf-ray + cf-mitigated challenge",
			mkResp(403, map[string]string{"CF-Ray": "1234abc", "CF-Mitigated": "challenge"}, nil, ""),
			true, LayerChallenge, true,
		},
		{
			"block: 403 with cf-ray only",
			mkResp(403, map[string]string{"CF-Ray": "99zz", "Server": "cloudflare"}, nil, ""),
			true, LayerHTTP, true,
		},
		{
			"rate-limit: 429 with cf-ray",
			mkResp(429, map[string]string{"CF-Ray": "xyz"}, nil, ""),
			true, LayerRateLimit, true,
		},
		{
			"managed challenge: legacy IUAM body",
			mkResp(503, map[string]string{"Server": "cloudflare"}, nil,
				"<html><title>Just a moment...</title>Please enable cookies. Cloudflare Ray ID: 123"),
			true, LayerChallenge, true,
		},
		{
			"turnstile widget: 200 OK with turnstile form gate",
			mkResp(200,
				map[string]string{"CF-Ray": "abc", "Server": "cloudflare"},
				nil,
				`<html><div class="cf-turnstile" data-sitekey="123"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></html>`),
			true, LayerSensor, false,
		},
		{
			"no match: clean origin",
			mkResp(200, map[string]string{"Server": "nginx"}, nil, "hello"),
			false, "", false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudflare{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v (got=%+v)", got != nil, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer {
				t.Errorf("layer=%q want=%q", got.Layer, tc.wantLayer)
			}
			if got.Blocked != tc.wantBlocked {
				t.Errorf("blocked=%v want=%v", got.Blocked, tc.wantBlocked)
			}
			if got.Confidence != "high" {
				t.Errorf("cloudflare should be high-confidence, got %q", got.Confidence)
			}
			if len(got.Signals) == 0 {
				t.Error("expected at least one signal")
			}
		})
	}
}

// Akamai

func TestAkamai(t *testing.T) {
	tests := []struct {
		name           string
		resp           *Response
		wantHit        bool
		wantVendor     string
		wantLayer      Layer
		wantBlocked    bool
		wantConfidence string
	}{
		{
			"BM: 200 with _abck sensor seed",
			mkResp(200, nil, []*http.Cookie{ck("_abck", "XYZ~abc~||0||~123")}, ""),
			true, "akamai", LayerSensor, false, "high",
		},
		{
			"BM: 403 + _abck blocking value",
			mkResp(403, nil, []*http.Cookie{ck("_abck", "XYZ~abc~||1||~bot")}, ""),
			true, "akamai", LayerHTTP, true, "high",
		},
		{
			"BM: sensor_data challenge page",
			mkResp(200, nil, []*http.Cookie{ck("_abck", "seed~||0||~")},
				"function sensor_data(){...}"),
			true, "akamai", LayerChallenge, true, "high",
		},
		{
			"BM: 429 with ak_bmsc",
			mkResp(429, nil, []*http.Cookie{ck("ak_bmsc", "ak-value")}, ""),
			true, "akamai", LayerRateLimit, true, "high",
		},
		{
			"CDN-only: AkamaiGHost server header does NOT claim bot manager",
			mkResp(200, map[string]string{"Server": "AkamaiGHost"}, nil, ""),
			true, "akamai-cdn", LayerPass, false, "low",
		},
		{
			"CDN-only: X-Akamai-Transformed is NOT proof of bot manager (Nike pattern)",
			mkResp(200, map[string]string{"X-Akamai-Transformed": "9 1234 0 pmb=mRUM"}, nil, ""),
			true, "akamai-cdn", LayerPass, false, "low",
		},
		{
			"no match: plain origin",
			mkResp(200, map[string]string{"Server": "nginx"}, nil, "{}"),
			false, "", "", false, "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := akamai{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v (got=%+v)", got != nil, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Vendor != tc.wantVendor {
				t.Errorf("vendor=%q want=%q", got.Vendor, tc.wantVendor)
			}
			if got.Layer != tc.wantLayer {
				t.Errorf("layer=%q want=%q", got.Layer, tc.wantLayer)
			}
			if got.Blocked != tc.wantBlocked {
				t.Errorf("blocked=%v want=%v", got.Blocked, tc.wantBlocked)
			}
			if got.Confidence != tc.wantConfidence {
				t.Errorf("confidence=%q want=%q", got.Confidence, tc.wantConfidence)
			}
		})
	}
}

// Kasada

func TestKasada(t *testing.T) {
	tests := []struct {
		name        string
		resp        *Response
		wantHit     bool
		wantLayer   Layer
		wantBlocked bool
	}{
		{
			"block: 429 with X-KPSDK-CT",
			mkResp(429, map[string]string{"X-KPSDK-CT": "token"}, nil, ""),
			true, LayerHTTP, true,
		},
		{
			"block: 429 with X-KPSDK-H version",
			mkResp(429, map[string]string{"X-KPSDK-H": "1.2.3"}, nil, ""),
			true, LayerHTTP, true,
		},
		{
			"sensor: 200 with /ips.js injected",
			mkResp(200, nil, nil, "<html><script src='/ips.js'></script></html>"),
			true, LayerSensor, false,
		},
		{
			"pass: KP_UIDz cookie on 200",
			mkResp(200, nil, []*http.Cookie{ck("KP_UIDz", "abc123")}, ""),
			true, LayerPass, false,
		},
		{
			"block: 403 with kpsdk body",
			mkResp(403, nil, nil, "kpsdk verification required"),
			true, LayerHTTP, true,
		},
		{
			"no match: plain origin (Nike CDN pattern without Kasada signals)",
			mkResp(200, map[string]string{"X-Akamai-Transformed": "9 1 0 pmb="}, nil, ""),
			false, "", false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kasada{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v (got=%+v)", got != nil, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer {
				t.Errorf("layer=%q want=%q", got.Layer, tc.wantLayer)
			}
			if got.Blocked != tc.wantBlocked {
				t.Errorf("blocked=%v want=%v", got.Blocked, tc.wantBlocked)
			}
			if got.Confidence != "high" {
				t.Errorf("confidence=%q want high", got.Confidence)
			}
		})
	}
}

// Shape / F5

func TestShapeF5(t *testing.T) {
	tests := []struct {
		name           string
		resp           *Response
		wantHit        bool
		wantLayer      Layer
		wantBlocked    bool
		wantConfidence string
	}{
		{
			"high: interruption page + TS cookie",
			mkResp(200, nil, []*http.Cookie{ck("TS012abc34", "val")},
				"<html>Pardon Our Interruption</html>"),
			true, LayerChallenge, true, "high",
		},
		{
			"high: X-<id>-<letter> family in body (Uniqlo-style sensor)",
			mkResp(200,
				map[string]string{"Server": "nginx"}, nil,
				`<script>var headers = {"X-I1ysm4mm-A":t,"X-I1ysm4mm-B":t2,"X-I1ysm4mm-C":t3,"X-I1ysm4mm-Z":"q"};</script>`),
			true, LayerSensor, false, "high",
		},
		{
			"high: Shape sensor on a 403 (challenge layer)",
			mkResp(403, nil, []*http.Cookie{ck("TSabcdef12", "x")},
				`<html><head><script>"X-Sjkdh3lf-A":x,"X-Sjkdh3lf-B":y,"X-Sjkdh3lf-Z":"q"</script>Pardon Our Interruption</html>`),
			true, LayerChallenge, true, "high",
		},
		{
			"no match: bare X-Foo-A header pattern (only one occurrence)",
			mkResp(200, nil, nil,
				`<html>some text X-Random-A nothing else</html>`),
			false, "", false, "",
		},
		{
			"high: we've seen unusual activity body",
			mkResp(403, nil, nil, "we've seen some unusual activity from your IP"),
			true, LayerChallenge, true, "high",
		},
		{
			"medium: TS cookie alone (could be vanilla BIG-IP)",
			mkResp(200, nil, []*http.Cookie{ck("TSabcd1234", "v")}, ""),
			true, LayerPass, false, "medium",
		},
		{
			"medium: BigIP server header",
			mkResp(200, map[string]string{"Server": "BigIP"}, nil, ""),
			true, LayerPass, false, "medium",
		},
		{
			"no match: vanilla TSESSIONID (not the TS-hex pattern)",
			mkResp(200, nil, []*http.Cookie{ck("TSESSIONID", "xyz")}, ""),
			false, "", false, "",
		},
		{
			"no match: clean origin",
			mkResp(200, map[string]string{"Server": "nginx"}, nil, "{}"),
			false, "", false, "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shapef5{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v (got=%+v)", got != nil, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer {
				t.Errorf("layer=%q want=%q", got.Layer, tc.wantLayer)
			}
			if got.Blocked != tc.wantBlocked {
				t.Errorf("blocked=%v want=%v", got.Blocked, tc.wantBlocked)
			}
			if got.Confidence != tc.wantConfidence {
				t.Errorf("confidence=%q want=%q", got.Confidence, tc.wantConfidence)
			}
		})
	}
}

// TestShape_RealWorldUniqloHeaders: regression test using header names
// observed on a real Uniqlo login POST. The page-side JS bundle includes
// these names as string literals, which the body scanner picks up.
func TestShape_RealWorldUniqloHeaders(t *testing.T) {
	bodyJS := `<script>
		var SHAPE_HEADERS = {
			"X-I1ysm4mm-A": null,
			"X-I1ysm4mm-B": null,
			"X-I1ysm4mm-C": null,
			"X-I1ysm4mm-D": null,
			"X-I1ysm4mm-F": null,
			"X-I1ysm4mm-A0": null,
			"X-I1ysm4mm-Z": "q"
		};
	</script>`
	resp := mkResp(200, map[string]string{"Server": "AkamaiGHost"}, nil, bodyJS)
	det := shapef5{}.Detect(resp)
	if det == nil {
		t.Fatal("expected Shape detection on body containing X-I1ysm4mm-* headers")
	}
	if det.Confidence != "high" {
		t.Errorf("confidence=%q want high", det.Confidence)
	}
	hasShapeSig := false
	for _, s := range det.Signals {
		if strings.HasPrefix(s, "body:shape-headers") {
			hasShapeSig = true
			break
		}
	}
	if !hasShapeSig {
		t.Errorf("expected 'body:shape-headers' signal, got %v", det.Signals)
	}
}

// TestShape_RegexExtractsIdentifier: id capture across known patterns.
func TestShape_RegexExtractsIdentifier(t *testing.T) {
	cases := []struct {
		input     string
		wantMatch bool
		wantID    string
	}{
		{"X-I1ysm4mm-A", true, "I1ysm4mm"},
		{"X-AbCdEf01-Z", true, "AbCdEf01"},
		{"X-Sjkdh3lf-A0", true, "Sjkdh3lf"},
		{"X-Foo-A", false, ""}, // identifier too short (3 chars)
		{"X-Forwarded-For", false, ""},
		{"X-Real-IP", false, ""},
		{"X-Frame-Options", false, ""}, // legit common header
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			match := shapeHeaderPattern.FindString(c.input)
			matched := match != ""
			if matched != c.wantMatch {
				t.Errorf("FindString(%q) matched=%v want %v", c.input, matched, c.wantMatch)
			}
			if c.wantMatch {
				sub := shapeIDPattern.FindStringSubmatch(c.input)
				if len(sub) < 2 || sub[1] != c.wantID {
					t.Errorf("ID extracted=%q want %q", sub, c.wantID)
				}
			}
		})
	}
}

func TestLooksLikeTSCookie(t *testing.T) {
	cases := map[string]bool{
		"TS012abc":    true,
		"TSabcd1234":  true,
		"TSESSIONID":  false,
		"TSTOKEN":     false,
		"TS":          false,
		"tsabc":       true, // case-insensitive prefix, hex suffix
		"TS01z":       false, // z is not hex
		"TS123-xyz":   false, // dash not hex
	}
	for name, want := range cases {
		if got := looksLikeTSCookie(name); got != want {
			t.Errorf("looksLikeTSCookie(%q) = %v, want %v", name, got, want)
		}
	}
}

// DataDome

func TestDataDome(t *testing.T) {
	tests := []struct {
		name        string
		resp        *Response
		wantHit     bool
		wantLayer   Layer
		wantBlocked bool
	}{
		{
			"pass: 200 with datadome cookie",
			mkResp(200, nil, []*http.Cookie{ck("datadome", "abc123")}, ""),
			true, LayerPass, false,
		},
		{
			"block: 403 with datadome cookie",
			mkResp(403, nil, []*http.Cookie{ck("datadome", "abc123")}, ""),
			true, LayerHTTP, true,
		},
		{
			"challenge: captcha interstitial",
			mkResp(403, map[string]string{"X-DataDome": "block"}, nil,
				"<html>https://geo.captcha-delivery.com/..."),
			true, LayerChallenge, true,
		},
		{
			"no match",
			mkResp(200, map[string]string{"Server": "nginx"}, nil, "{}"),
			false, "", false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := datadome{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v (got=%+v)", got != nil, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer || got.Blocked != tc.wantBlocked {
				t.Errorf("layer=%q blocked=%v  want layer=%q blocked=%v", got.Layer, got.Blocked, tc.wantLayer, tc.wantBlocked)
			}
		})
	}
}

// PerimeterX

func TestPerimeterX(t *testing.T) {
	tests := []struct {
		name        string
		resp        *Response
		wantHit     bool
		wantLayer   Layer
		wantBlocked bool
	}{
		{
			"pass: _pxvid cookie set",
			mkResp(200, nil, []*http.Cookie{ck("_pxvid", "abc")}, ""),
			true, LayerPass, false,
		},
		{
			"block: 403 + _px cookie",
			mkResp(403, nil, []*http.Cookie{ck("_px", "blocked")}, ""),
			true, LayerHTTP, true,
		},
		{
			"challenge: human verification page",
			mkResp(403, nil, []*http.Cookie{ck("_pxCaptcha", "x")},
				"<html>Please verify you are a human</html>"),
			true, LayerChallenge, true,
		},
		{
			"no match",
			mkResp(200, nil, nil, "{}"),
			false, "", false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := perimeterx{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v (got=%+v)", got != nil, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer || got.Blocked != tc.wantBlocked {
				t.Errorf("layer=%q blocked=%v  want layer=%q blocked=%v", got.Layer, got.Blocked, tc.wantLayer, tc.wantBlocked)
			}
		})
	}
}

// AWS WAF

func TestAWSWAF(t *testing.T) {
	tests := []struct {
		name           string
		resp           *Response
		wantHit        bool
		wantLayer      Layer
		wantBlocked    bool
		wantConfidence string
	}{
		{
			"high: WAFBlockException errortype",
			mkResp(403, map[string]string{"X-Amzn-ErrorType": "WAFBlockException"}, nil, ""),
			true, LayerHTTP, true, "high",
		},
		{
			"high: x-amzn-waf custom header",
			mkResp(403, map[string]string{"X-Amzn-Waf-Token": "xyz"}, nil, ""),
			true, LayerHTTP, true, "high",
		},
		{
			"low: cloudfront 403 without AWS WAF specific header",
			mkResp(403, map[string]string{"X-Amz-Cf-Id": "abc"}, nil, ""),
			true, LayerHTTP, true, "low",
		},
		{
			"no match",
			mkResp(200, map[string]string{"Server": "nginx"}, nil, "{}"),
			false, "", false, "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := awsWAF{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v", got != nil, tc.wantHit)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer || got.Blocked != tc.wantBlocked {
				t.Errorf("layer=%q blocked=%v  want layer=%q blocked=%v", got.Layer, got.Blocked, tc.wantLayer, tc.wantBlocked)
			}
			if got.Confidence != tc.wantConfidence {
				t.Errorf("confidence=%q want=%q", got.Confidence, tc.wantConfidence)
			}
		})
	}
}

// Imperva

func TestImperva(t *testing.T) {
	tests := []struct {
		name        string
		resp        *Response
		wantHit     bool
		wantLayer   Layer
		wantBlocked bool
	}{
		{
			"pass: x-iinfo present 200",
			mkResp(200, map[string]string{"X-Iinfo": "abc-def"}, nil, ""),
			true, LayerPass, false,
		},
		{
			"block: 403 + incapsula incident body",
			mkResp(403, nil, nil, "<html>Incapsula incident ID: 123</html>"),
			true, LayerHTTP, true,
		},
		{
			"no match",
			mkResp(200, nil, nil, "{}"),
			false, "", false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := imperva{}.Detect(tc.resp)
			if (got != nil) != tc.wantHit {
				t.Fatalf("hit=%v want=%v", got != nil, tc.wantHit)
			}
			if !tc.wantHit {
				return
			}
			if got.Layer != tc.wantLayer || got.Blocked != tc.wantBlocked {
				t.Errorf("layer=%q blocked=%v  want layer=%q blocked=%v", got.Layer, got.Blocked, tc.wantLayer, tc.wantBlocked)
			}
		})
	}
}

// Analyze orchestrator.

func TestAnalyzePrecedence(t *testing.T) {
	// If BOTH Cloudflare and Akamai signals fire (rare in practice — usually
	// means Akamai in front of CF or vice versa), Analyze should prefer the
	// high-confidence blocker.
	resp := mkResp(403,
		map[string]string{"CF-Ray": "xyz", "CF-Mitigated": "challenge", "Server": "AkamaiGHost"},
		[]*http.Cookie{ck("_abck", "pass~||0||~")},
		"Just a moment",
	)
	det := Analyze(resp)
	if !det.Blocked {
		t.Fatalf("expected Blocked=true, got %+v", det)
	}
	if det.Vendor != "cloudflare" && det.Vendor != "akamai" {
		t.Errorf("vendor should be cloudflare or akamai, got %q", det.Vendor)
	}
}

func TestAnalyzePassThrough(t *testing.T) {
	// Clean origin with no vendor signals → pass-through detection.
	resp := mkResp(200, map[string]string{"Server": "nginx"}, nil, "hello world")
	det := Analyze(resp)
	if det.Vendor != "" {
		t.Errorf("no vendor expected, got %q (%+v)", det.Vendor, det)
	}
	if det.Blocked {
		t.Errorf("pass-through should not be Blocked, got %+v", det)
	}
}

func TestAnalyzeNilResponse(t *testing.T) {
	det := Analyze(nil)
	if det.Blocked {
		t.Error("nil response should not be blocked")
	}
}

func TestAnalyzeStatusOnly403(t *testing.T) {
	// Unknown vendor, 403 → HTTP block.
	resp := mkResp(403, map[string]string{"Server": "unknown"}, nil, "")
	det := Analyze(resp)
	if !det.Blocked {
		t.Errorf("403 without vendor signal should still be Blocked=true, got %+v", det)
	}
	if det.Layer != LayerHTTP {
		t.Errorf("layer should be http, got %q", det.Layer)
	}
}

func TestDetectorsListIsSorted(t *testing.T) {
	ds := Detectors()
	prev := ""
	for _, d := range ds {
		if d.Vendor() < prev {
			t.Errorf("Detectors() not sorted: %q < %q", d.Vendor(), prev)
		}
		prev = d.Vendor()
	}
}

func TestFromHTTPResponseIsNilSafe(t *testing.T) {
	if r := FromHTTPResponse(nil, nil); r != nil {
		t.Errorf("expected nil, got %+v", r)
	}
	// no Header map → should still return a Response, with empty slices.
	hr := &http.Response{StatusCode: 200}
	r := FromHTTPResponse(hr, nil)
	if r == nil || r.StatusCode != 200 {
		t.Errorf("expected populated Response, got %+v", r)
	}
}

func TestAllSignalsStringer(t *testing.T) {
	// Smoke test for human-readable signal output.
	resp := mkResp(403,
		map[string]string{"CF-Ray": "abcdef", "CF-Mitigated": "challenge"},
		[]*http.Cookie{ck("__cf_bm", "v")}, "Just a moment")
	det := Analyze(resp)
	joined := strings.Join(det.Signals, "|")
	if !strings.Contains(joined, "cf-ray") {
		t.Errorf("expected cf-ray signal in %q", joined)
	}
}
