package persona

import (
	"fmt"
	"strings"
)

// AkamaiH2 returns the Akamai-format HTTP/2 fingerprint
// (SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER), or "" with no h2 profile.
func AkamaiH2(p Persona) string {
	prof := p.Profile
	settings := prof.GetSettings()
	order := prof.GetSettingsOrder()
	if len(order) == 0 {
		return ""
	}

	sParts := make([]string, 0, len(order))
	for _, id := range order {
		sParts = append(sParts, fmt.Sprintf("%d:%d", uint16(id), settings[id]))
	}

	prio := "0"
	if ps := prof.GetPriorities(); len(ps) > 0 {
		pParts := make([]string, 0, len(ps))
		for _, pr := range ps {
			ex := 0
			if pr.PriorityParam.Exclusive {
				ex = 1
			}
			// wire weight is 0-indexed, the fingerprint uses 1-indexed
			pParts = append(pParts, fmt.Sprintf("%d:%d:%d:%d", pr.StreamID, ex, pr.PriorityParam.StreamDep, int(pr.PriorityParam.Weight)+1))
		}
		prio = strings.Join(pParts, ",")
	}

	var hParts []string
	for _, h := range prof.GetPseudoHeaderOrder() {
		switch h {
		case ":method":
			hParts = append(hParts, "m")
		case ":authority":
			hParts = append(hParts, "a")
		case ":scheme":
			hParts = append(hParts, "s")
		case ":path":
			hParts = append(hParts, "p")
		}
	}

	return strings.Join(sParts, ";") + "|" + fmt.Sprintf("%d", prof.GetConnectionFlow()) + "|" + prio + "|" + strings.Join(hParts, ",")
}
