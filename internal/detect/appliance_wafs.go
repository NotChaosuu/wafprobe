package detect

// Appliance WAFs rarely set a signature header, so these lean on block-page
// strings and vendor cookies.

type sucuri struct{}

func (sucuri) Vendor() string { return "sucuri" }

func (sucuri) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	if v, ok := hasHeader(resp.Header, "X-Sucuri-ID"); ok {
		signals = append(signals, "header:x-sucuri-id="+short(v, 24))
	}
	if _, ok := hasHeader(resp.Header, "X-Sucuri-Cache"); ok {
		signals = append(signals, "header:x-sucuri-cache")
	}
	if _, ok := hasHeader(resp.Header, "X-Sucuri-Block"); ok {
		signals = append(signals, "header:x-sucuri-block")
	}
	if s, ok := hasHeader(resp.Header, "Server"); ok && hasPrefixFold(s, "sucuri") {
		signals = append(signals, "header:server=sucuri")
	}
	if resp.bodyHas("sucuri website firewall") || resp.bodyHas("cdn.sucuri.net/sucuri-firewall-block") {
		signals = append(signals, "body:sucuri-block")
	}
	if len(signals) == 0 {
		return nil
	}
	return blockOr(resp, "sucuri", signals, resp.StatusCode == 403)
}

type fortiweb struct{}

func (fortiweb) Vendor() string { return "fortiweb" }

func (fortiweb) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	if _, ok := hasCookie(resp.Cookies, "FORTIWAFSID"); ok {
		signals = append(signals, "cookie:FORTIWAFSID")
	}
	blocked := false
	if resp.bodyHas("fgd_icon") {
		signals = append(signals, "body:fgd_icon")
		blocked = true
	}
	if resp.bodyHas("web.page.blocked") && resp.bodyHas("attack.id") {
		signals = append(signals, "body:fortiweb-block-fields")
		blocked = true
	}
	if len(signals) == 0 {
		return nil
	}
	return blockOr(resp, "fortiweb", signals, blocked || resp.StatusCode == 403)
}

// NetScaler rewrites Connection to the mangled "Cneonction"/"nnCoection" headers.
type netscaler struct{}

func (netscaler) Vendor() string { return "citrix-netscaler" }

func (netscaler) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	for _, name := range []string{"ns_af", "citrix_ns_id"} {
		if _, ok := hasCookie(resp.Cookies, name); ok {
			signals = append(signals, "cookie:"+name)
		}
	}
	for _, c := range resp.Cookies {
		if hasPrefixFold(c.Name, "NSC_") {
			signals = append(signals, "cookie:NSC_*")
			break
		}
	}
	if _, ok := hasHeader(resp.Header, "Cneonction"); ok {
		signals = append(signals, "header:Cneonction")
	}
	if _, ok := hasHeader(resp.Header, "nnCoection"); ok {
		signals = append(signals, "header:nnCoection")
	}
	blocked := false
	if resp.bodyHas("APPFW_") || (resp.bodyHas("violation category") && resp.bodyHas("netscaler")) {
		signals = append(signals, "body:appfw-block")
		blocked = true
	}
	if len(signals) == 0 {
		return nil
	}
	return blockOr(resp, "citrix-netscaler", signals, blocked)
}

type radware struct{}

func (radware) Vendor() string { return "radware" }

func (radware) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	if _, ok := hasHeader(resp.Header, "X-SL-CompState"); ok {
		signals = append(signals, "header:x-sl-compstate")
	}
	blocked := false
	if resp.bodyHas("cloudwebsec.radware.com") ||
		(resp.bodyHas("unauthorized request blocked") && resp.bodyHas("unauthorized activity")) {
		signals = append(signals, "body:radware-block")
		blocked = true
	}
	if len(signals) == 0 {
		return nil
	}
	return blockOr(resp, "radware", signals, blocked || resp.StatusCode == 403)
}

type barracuda struct{}

func (barracuda) Vendor() string { return "barracuda" }

func (barracuda) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	for _, c := range resp.Cookies {
		if hasPrefixFold(c.Name, "barra_counter_session") || hasPrefixFold(c.Name, "BNI_") || hasPrefixFold(c.Name, "BNES_") {
			signals = append(signals, "cookie:"+c.Name)
		}
	}
	if resp.bodyHas("barracuda.networks") {
		signals = append(signals, "body:barracuda")
	}
	if len(signals) == 0 {
		return nil
	}
	return blockOr(resp, "barracuda", signals, resp.StatusCode == 403)
}

// A bare BIGipServer* cookie only means an F5 LB is in the path, so low
// confidence; the ASM "requested URL was rejected" page is the real signal.
type f5bigip struct{}

func (f5bigip) Vendor() string { return "f5-bigip-asm" }

func (f5bigip) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	blocked := false
	if resp.bodyHas("the requested url was rejected") && resp.bodyHas("consult with your administrator") {
		signals = append(signals, "body:asm-request-rejected")
		blocked = true
	}
	for _, c := range resp.Cookies {
		if hasPrefixFold(c.Name, "BIGipServer") {
			signals = append(signals, "cookie:BIGipServer* (LB in path)")
			break
		}
	}
	if len(signals) == 0 {
		return nil
	}
	conf := "high"
	if !blocked {
		conf = "low"
	}
	det := &Detection{Vendor: "f5-bigip-asm", Confidence: conf, Signals: signals}
	if blocked {
		det.Layer = LayerHTTP
		det.Blocked = true
	} else {
		det.Layer = LayerPass
	}
	return det
}

// Wordfence answers 429 from its rate limiter, not as a hard block.
type wordfence struct{}

func (wordfence) Vendor() string { return "wordfence" }

func (wordfence) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	blocked := false
	if resp.bodyHas("generated by wordfence") ||
		resp.bodyHas("your access to this site has been limited by the site owner") ||
		resp.bodyHas("access from your area has been temporarily limited for security reasons") {
		signals = append(signals, "body:wordfence-block")
		blocked = true
	}
	if len(signals) == 0 {
		return nil
	}
	det := &Detection{Vendor: "wordfence", Confidence: "high", Signals: signals}
	if resp.StatusCode == 429 {
		det.Layer = LayerRateLimit
	} else {
		det.Layer = LayerHTTP
	}
	det.Blocked = blocked
	return det
}

func blockOr(resp *Response, vendor string, signals []string, blocked bool) *Detection {
	det := &Detection{Vendor: vendor, Confidence: "high", Signals: signals}
	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case blocked:
		det.Layer = LayerHTTP
		det.Blocked = true
	default:
		det.Layer = LayerPass
	}
	return det
}

func init() {
	Register(sucuri{})
	Register(fortiweb{})
	Register(netscaler{})
	Register(radware{})
	Register(barracuda{})
	Register(f5bigip{})
	Register(wordfence{})
}
