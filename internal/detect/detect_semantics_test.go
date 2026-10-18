package detect

import (
	"net/http"
	"testing"
)

// youtube's "web_badge_shape_defrag" flag must not trigger Shape.
func TestShapeScriptRefNeedsAnchor(t *testing.T) {
	body := `{"web_badge_shape_defrag":true,"mweb_badge_shape_defrag":true}`
	if got := (shapef5{}).Detect(mkResp(200, nil, nil, body)); got != nil {
		t.Fatalf("unanchored _shape_ must not match, got %+v", got)
	}
	// real script path still matches, as a sensor on 200
	anchored := `<script src="https://x/_shape_/v/1"></script>`
	got := (shapef5{}).Detect(mkResp(200, nil, nil, anchored))
	if got == nil || got.Vendor != "shape-f5" {
		t.Fatalf("anchored /_shape_/ must match shape-f5, got %+v", got)
	}
	if got.Blocked || got.Layer != LayerSensor {
		t.Errorf("script-ref on a 200 is a sensor, not a block: %+v", got)
	}
}

// lone TS<hex> cookie is f5-bigip, not Shape, and not blocked on 200.
func TestLoneTSCookieIsF5BigIP(t *testing.T) {
	got := (shapef5{}).Detect(mkResp(200, nil, []*http.Cookie{ck("TS011d4936", "x")}, ""))
	if got == nil {
		t.Fatal("TS cookie should still be detected")
	}
	if got.Vendor != "f5-bigip" {
		t.Errorf("lone TS cookie must be f5-bigip, got %q", got.Vendor)
	}
	if got.Blocked {
		t.Errorf("a TS cookie on a 200 is not a block: %+v", got)
	}
}

// captcha on a block page is Blocked (so --exit-code fails); on 2xx it's a sensor.
func TestCaptchaWidgetBlockedFromStatus(t *testing.T) {
	blockBody := `<div class="g-recaptcha" data-sitekey="x"></div>`
	for _, status := range []int{403, 429} {
		got := Analyze(mkResp(status, nil, nil, blockBody))
		if !got.Blocked {
			t.Errorf("captcha on a %d must be Blocked, got %+v", status, got)
		}
	}
	pass := Analyze(mkResp(200, nil, nil, blockBody))
	if pass.Blocked || pass.Layer != LayerSensor {
		t.Errorf("captcha on a 200 is a sensor, not a block: %+v", pass)
	}
}

func TestBenignStatusNotBlocked(t *testing.T) {
	for _, status := range []int{404, 405, 410, 401, 501} {
		got := Analyze(mkResp(status, nil, nil, "not found"))
		if got.Blocked {
			t.Errorf("bare %d must not be Blocked, got %+v", status, got)
		}
	}
	auth := Analyze(mkResp(403, map[string]string{"WWW-Authenticate": "Basic realm=x"}, nil, ""))
	if auth.Blocked {
		t.Errorf("403 + WWW-Authenticate is auth, not a block: %+v", auth)
	}
	if !Analyze(mkResp(403, nil, nil, "forbidden")).Blocked {
		t.Errorf("bare 403 should still be Blocked")
	}
}

func TestCDNNonBlockOnBenignStatus(t *testing.T) {
	got := Analyze(mkResp(404, map[string]string{"X-Amz-Cf-Id": "abc"}, nil, "not found"))
	if got.Blocked {
		t.Errorf("404 behind CloudFront must not be Blocked: %+v", got)
	}
}

// second vendor ends up in Also
func TestMultiVendorAlso(t *testing.T) {
	resp := mkResp(200,
		map[string]string{"CF-Ray": "abc-DFW", "Server": "cloudflare"},
		nil,
		`<script src="https://client-api.arkoselabs.com/x"></script>`)
	got := Analyze(resp)
	if len(got.Also) == 0 {
		t.Fatalf("a stacked deployment must record other vendors in Also, got %+v", got)
	}
}
