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

	utls "github.com/refraction-networking/utls"
)

// BuildClientHelloRaw constructs but does not send a ClientHello for the
// given persona, returning the marshalled handshake message bytes. Uses a
// net.Pipe pair so utls can build state without actual network I/O.
//
// Stock-TLS personas return ErrNoOfflineJA3 because their fingerprint is
// whatever crypto/tls produces at connect time.
func BuildClientHelloRaw(p Persona, sni string) ([]byte, error) {
	if p.UseStockTLS {
		return nil, ErrNoOfflineJA3
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	uc := utls.UClient(c1, cfg, p.ClientHello)
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

// ErrNoOfflineJA3 is returned by BuildClientHelloRaw / JA3 when the persona
// can't be pre-computed offline (stock-TLS personas). Callers should treat
// this as "captured at connect time" rather than a hard error.
var ErrNoOfflineJA3 = errors.New("no offline JA3 available for this persona")

// JA3 computes the JA3 string and its MD5 hash for a persona's ClientHello.
// GREASE values are stripped per the spec (https://github.com/salesforce/ja3).
func JA3(p Persona, sni string) (string, string, error) {
	raw, err := BuildClientHelloRaw(p, sni)
	if err != nil {
		return "", "", err
	}
	s, err := parseJA3(raw)
	if err != nil {
		return "", "", err
	}
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:]), nil
}

// parseJA3 extracts the JA3 string from a raw ClientHello handshake message
// (input starts at HandshakeType, not the TLS record header).
// Format: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
func parseJA3(ch []byte) (string, error) {
	if len(ch) < 4 || ch[0] != 0x01 {
		return "", errors.New("not a ClientHello handshake message")
	}
	// skip HandshakeType(1) + Length(3)
	r := bytes.NewReader(ch[4:])

	var clientVersion uint16
	if err := binary.Read(r, binary.BigEndian, &clientVersion); err != nil {
		return "", fmt.Errorf("client version: %w", err)
	}
	// Random (32 bytes)
	if _, err := r.Seek(32, io.SeekCurrent); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	// SessionID (1-byte len + data)
	var sidLen uint8
	if err := binary.Read(r, binary.BigEndian, &sidLen); err != nil {
		return "", fmt.Errorf("session id len: %w", err)
	}
	if _, err := r.Seek(int64(sidLen), io.SeekCurrent); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	// CipherSuites (2-byte len + uint16 list)
	var csLen uint16
	if err := binary.Read(r, binary.BigEndian, &csLen); err != nil {
		return "", fmt.Errorf("cipher suites len: %w", err)
	}
	if csLen%2 != 0 {
		return "", errors.New("cipher suites length not multiple of 2")
	}
	cipherSuites := make([]uint16, csLen/2)
	for i := range cipherSuites {
		if err := binary.Read(r, binary.BigEndian, &cipherSuites[i]); err != nil {
			return "", fmt.Errorf("cipher suite %d: %w", i, err)
		}
	}
	// CompressionMethods (1-byte len + data)
	var cmLen uint8
	if err := binary.Read(r, binary.BigEndian, &cmLen); err != nil {
		return "", fmt.Errorf("compression methods len: %w", err)
	}
	if _, err := r.Seek(int64(cmLen), io.SeekCurrent); err != nil {
		return "", fmt.Errorf("compression methods: %w", err)
	}
	// Extensions (2-byte len + payload)
	var extTotal uint16
	if err := binary.Read(r, binary.BigEndian, &extTotal); err != nil {
		return "", fmt.Errorf("extensions len: %w", err)
	}
	extPayload := make([]byte, extTotal)
	if _, err := io.ReadFull(r, extPayload); err != nil {
		return "", fmt.Errorf("extensions payload: %w", err)
	}

	var (
		extensionIDs []uint16
		curves       []uint16
		pointFormats []uint8
	)
	for off := 0; off+4 <= len(extPayload); {
		extType := binary.BigEndian.Uint16(extPayload[off : off+2])
		extLen := int(binary.BigEndian.Uint16(extPayload[off+2 : off+4]))
		off += 4
		if off+extLen > len(extPayload) {
			return "", errors.New("truncated extension body")
		}
		body := extPayload[off : off+extLen]
		off += extLen

		extensionIDs = append(extensionIDs, extType)

		switch extType {
		case 10: // supported_groups / elliptic_curves
			if len(body) >= 2 {
				groupsLen := int(binary.BigEndian.Uint16(body[:2]))
				for i := 2; i+2 <= 2+groupsLen && i+2 <= len(body); i += 2 {
					curves = append(curves, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}
		case 11: // ec_point_formats
			if len(body) >= 1 {
				formatsLen := int(body[0])
				for i := 1; i < 1+formatsLen && i < len(body); i++ {
					pointFormats = append(pointFormats, body[i])
				}
			}
		}
	}

	cs := stripGREASE(cipherSuites)
	ext := stripGREASE(extensionIDs)
	crv := stripGREASE(curves)

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		clientVersion,
		joinU16(cs),
		joinU16(ext),
		joinU16(crv),
		joinU8(pointFormats),
	), nil
}

// stripGREASE removes GREASE values (RFC 8701) from a uint16 slice.
// GREASE values follow the pattern 0x?A?A where both nibble-pairs match.
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
	// GREASE: 0x0A0A, 0x1A1A, 0x2A2A, ... — both bytes equal and low nibble == 0xA.
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
