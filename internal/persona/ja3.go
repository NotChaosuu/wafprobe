package persona

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/NotChaosuu/wafprobe/internal/ja4"
	tls "github.com/bogdanfinn/utls"
)

// BuildClientHelloRaw marshals the persona's ClientHello without sending it.
// utls needs a conn to build state, so it gets one end of a net.Pipe.
func BuildClientHelloRaw(p Persona, sni string) ([]byte, error) {
	if p.Stock {
		// HelloGolang is built by crypto/tls at handshake time, can't marshal it offline
		return nil, ErrNoOfflineJA3
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}

	// The wire client has h3 off, but some presets (Chrome_133) still list h3 in
	// ALPN, which would give an h3 JA4. Strip it when the spec is available.
	var uc *tls.UConn
	if spec, err := p.Profile.GetClientHelloSpec(); err == nil {
		for _, ext := range spec.Extensions {
			if a, ok := ext.(*tls.ALPNExtension); ok {
				a.AlpnProtocols = withoutH3(a.AlpnProtocols)
			}
		}
		uc = tls.UClient(c1, cfg, tls.HelloCustom, false, false, false)
		if err := uc.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("apply preset: %w", err)
		}
	} else {
		uc = tls.UClient(c1, cfg, p.Hello(), false, false, false)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("build handshake: %w", err)
	}
	if uc.HandshakeState.Hello == nil {
		return nil, errors.New("nil ClientHello after build")
	}
	raw := uc.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		return nil, errors.New("empty ClientHello bytes")
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func withoutH3(protos []string) []string {
	out := protos[:0]
	for _, p := range protos {
		if p == "h3" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ErrNoOfflineJA3 means the fingerprint is only known at connect time (stock TLS).
var ErrNoOfflineJA3 = errors.New("no offline JA3 available for this persona")

// JA3 computes the JA3 string and its MD5 hash for a persona's ClientHello.
// GREASE values are stripped per the spec (https://github.com/salesforce/ja3).
func JA3(p Persona, sni string) (string, string, error) {
	raw, err := BuildClientHelloRaw(p, sni)
	if err != nil {
		return "", "", err
	}
	h, err := parseHello(raw)
	if err != nil {
		return "", "", err
	}
	s := fmt.Sprintf("%d,%s,%s,%s,%s",
		h.clientVersion,
		joinU16(stripGREASE(h.cipherSuites)),
		joinU16(stripGREASE(h.extensionIDs)),
		joinU16(stripGREASE(h.curves)),
		joinU8(h.pointFormats),
	)
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:]), nil
}

// JA4 computes the FoxIO JA4 fingerprint. It sorts ciphers and extensions, so it
// survives utls's per-handshake extension shuffle where JA3 doesn't.
func JA4(p Persona, sni string) (string, error) {
	raw, err := BuildClientHelloRaw(p, sni)
	if err != nil {
		return "", err
	}
	h, err := parseHello(raw)
	if err != nil {
		return "", err
	}
	maxVer := h.clientVersion
	if h.supportedVersMax != 0 {
		maxVer = h.supportedVersMax
	}
	return ja4.JA4(ja4.ClientHello{
		TLSVersionMax: maxVer,
		SNIPresent:    h.sniPresent,
		CipherSuites:  h.cipherSuites,
		Extensions:    h.extensionIDs,
		SigAlgs:       h.sigAlgs,
		ALPN:          h.alpn,
	}), nil
}

type helloInfo struct {
	clientVersion    uint16
	supportedVersMax uint16
	cipherSuites     []uint16
	extensionIDs     []uint16
	curves           []uint16
	pointFormats     []uint8
	sigAlgs          []uint16
	alpn             []string
	sniPresent       bool
}

// parseHello expects the handshake message, not the TLS record header.
func parseHello(ch []byte) (helloInfo, error) {
	var h helloInfo
	if len(ch) < 4 || ch[0] != 0x01 {
		return h, errors.New("not a ClientHello handshake message")
	}
	r := bytes.NewReader(ch[4:]) // skip HandshakeType(1) + Length(3)

	if err := binary.Read(r, binary.BigEndian, &h.clientVersion); err != nil {
		return h, fmt.Errorf("client version: %w", err)
	}
	if _, err := r.Seek(32, io.SeekCurrent); err != nil { // Random
		return h, fmt.Errorf("random: %w", err)
	}
	var sidLen uint8
	if err := binary.Read(r, binary.BigEndian, &sidLen); err != nil {
		return h, fmt.Errorf("session id len: %w", err)
	}
	if _, err := r.Seek(int64(sidLen), io.SeekCurrent); err != nil {
		return h, fmt.Errorf("session id: %w", err)
	}
	var csLen uint16
	if err := binary.Read(r, binary.BigEndian, &csLen); err != nil {
		return h, fmt.Errorf("cipher suites len: %w", err)
	}
	if csLen%2 != 0 {
		return h, errors.New("cipher suites length not multiple of 2")
	}
	h.cipherSuites = make([]uint16, csLen/2)
	for i := range h.cipherSuites {
		if err := binary.Read(r, binary.BigEndian, &h.cipherSuites[i]); err != nil {
			return h, fmt.Errorf("cipher suite %d: %w", i, err)
		}
	}
	var cmLen uint8
	if err := binary.Read(r, binary.BigEndian, &cmLen); err != nil {
		return h, fmt.Errorf("compression methods len: %w", err)
	}
	if _, err := r.Seek(int64(cmLen), io.SeekCurrent); err != nil {
		return h, fmt.Errorf("compression methods: %w", err)
	}
	var extTotal uint16
	if err := binary.Read(r, binary.BigEndian, &extTotal); err != nil {
		return h, fmt.Errorf("extensions len: %w", err)
	}
	extPayload := make([]byte, extTotal)
	if _, err := io.ReadFull(r, extPayload); err != nil {
		return h, fmt.Errorf("extensions payload: %w", err)
	}

	for off := 0; off+4 <= len(extPayload); {
		extType := binary.BigEndian.Uint16(extPayload[off : off+2])
		extLen := int(binary.BigEndian.Uint16(extPayload[off+2 : off+4]))
		off += 4
		if off+extLen > len(extPayload) {
			return h, errors.New("truncated extension body")
		}
		body := extPayload[off : off+extLen]
		off += extLen
		h.extensionIDs = append(h.extensionIDs, extType)

		switch extType {
		case 0: // server_name
			h.sniPresent = true
		case 10: // supported_groups
			if len(body) >= 2 {
				groupsLen := int(binary.BigEndian.Uint16(body[:2]))
				for i := 2; i+2 <= 2+groupsLen && i+2 <= len(body); i += 2 {
					h.curves = append(h.curves, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}
		case 11: // ec_point_formats
			if len(body) >= 1 {
				formatsLen := int(body[0])
				for i := 1; i < 1+formatsLen && i < len(body); i++ {
					h.pointFormats = append(h.pointFormats, body[i])
				}
			}
		case 13: // signature_algorithms
			if len(body) >= 2 {
				saLen := int(binary.BigEndian.Uint16(body[:2]))
				for i := 2; i+2 <= 2+saLen && i+2 <= len(body); i += 2 {
					h.sigAlgs = append(h.sigAlgs, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}
		case 16: // application_layer_protocol_negotiation (ALPN)
			for i := 2; i < len(body); {
				n := int(body[i])
				i++
				if i+n > len(body) {
					break
				}
				h.alpn = append(h.alpn, string(body[i:i+n]))
				i += n
			}
		case 43: // supported_versions, real max version for JA4
			for i := 1; i+2 <= len(body); i += 2 {
				if v := binary.BigEndian.Uint16(body[i : i+2]); !isGREASE(v) && v > h.supportedVersMax {
					h.supportedVersMax = v
				}
			}
		}
	}
	return h, nil
}

// stripGREASE removes GREASE values (RFC 8701).
func stripGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func isGREASE(v uint16) bool {
	// 0x0A0A, 0x1A1A, ...: both bytes equal, low nibble 0xA
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0x00ff)
}

func joinU16(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinU8(vs []uint8) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}
