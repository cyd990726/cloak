package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type Fingerprint struct {
	JA3            string
	JA3Hash        string
	TLSVersion     uint16
	SNI            string
	ALPN           []string
	CipherSuites   []uint16
	Extensions     []uint16
	Curves         []uint16
	PointFormats   []byte
	SupportedAlgs  []uint16
}

const (
	typeHandshake    = 0x16
	handshakeClientHello = 0x01

	extServerName        = 0x0000
	extSupportedGroups   = 0x000a
	extECPointFormats    = 0x000b
	extSignatureAlgs     = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
)

var knownCrawlerJA3 = map[string]string{
	"72a3e1e69d39cd98bfe2e4e9bb5b2e66": "Go HTTP (go default)",
	"e64d0991fe298dfd0e6bafcb72c19e3f": "Go HTTP (go 1.22+)",
	"a4f3f95a2c7ad3bdd3b67736e7e852bb": "Go HTTP (go 1.21)",
	"cc228765b8eb26e2bce3bbaf0b97ffd0": "Go HTTP (go older)",
	"a26c7fa04c6c2a7d1c6e6c79939862e2": "Python httpx",
	"659cedd01af02340e9e9438e3df7c49e": "Python requests (urllib3)",
	"e627d755de85d8b8c1b34243ab467bb4": "Python requests (alternate)",
	"f2f63ca89db12d9d59709cda8bd0ef7c": "Python aiohttp",
	"401e913b0163b4d0d0be1fbe1980e6fb": "Python httplib2",
	"3f4e5cae1c71ee44cbff70e0eabbcf94": "Python urllib",
	"b32309a26951912be7dba376398abc3b": "Node.js http (v18+)",
	"c292756cc5bcabe13bed6dc43a221f2e": "Node.js https (v16)",
	"42941b55b43a1721d849788aa330c319": "Node.js undici",
	"adadc1e573cbe6dd40f7e7711d9ae115": "curl (7.x, default)",
	"4dabf24c0dda857898856a1eb3233a82": "curl (alternate)",
	"7a27a6e9b7efedaa7d4f45d7eae0a95a": "curl (older)",
	"ab8a154b30c4a4e581d83903106e10d6": "Headless Chrome (Puppeteer default)",
	"38b79c85f25be80abef9c9b1939a7f78": "Headless Chrome (remote mode)",
	"c7458f5d7dd23bb2db0960162117a0f0": "Playwright headless",
	"cf1345ac0b3a3a7c1e175e99ce7ff9f1": "Selenium headless",
	"556dbb3ffff9664998e1e6bf143407f9": "Wget",
	"b6cdda92f90caee3517786d37446378e": "Java HttpClient",
	"93ade6c69a223846ac5f9ee732f0ca5e": "Java okhttp",
	"52e5f491aef3a096e0d8a9a3a49c5b3b": "Java Apache HTTP",
	"8cd9efb67ff81c4f60e8e553e8c8e064": "Scrapy",
	"5620e9d3c7e3b4c1b15db2e117a70aec": "Google AdsBot (rare fingerprint)",
	"d38b14421d05a3dcc8264c1b3ad6bc13": "Google crawler (Googlebot)",
	"271b1d8e0c3501b2ba31be2c173753ba": "YandexBot",
	"766dd8651bb0768e26e538e6d2b468f1": "BingBot",
	"042a951d1fd3cba9cc29d2c4505bbd19": "BaiduSpider",
}

func IsKnownCrawler(ja3Hash string) (bool, string) {
	if desc, ok := knownCrawlerJA3[ja3Hash]; ok {
		return true, desc
	}
	return false, ""
}

func ParseClientHello(data []byte) (*Fingerprint, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("too short for TLS record: %d bytes", len(data))
	}

	contentType := data[0]
	if contentType != typeHandshake {
		return nil, fmt.Errorf("not a handshake record: type=0x%02x", contentType)
	}

	recordVersion := binary.BigEndian.Uint16(data[1:3])
	recordLength := binary.BigEndian.Uint16(data[3:5])

	if len(data) < int(recordLength)+5 {
		return nil, fmt.Errorf("truncated record: need %d, got %d", recordLength+5, len(data))
	}

	hsData := data[5 : 5+recordLength]
	if len(hsData) < 4 {
		return nil, fmt.Errorf("handshake too short")
	}

	hsType := hsData[0]
	if hsType != handshakeClientHello {
		return nil, fmt.Errorf("not a ClientHello: type=0x%02x", hsType)
	}

	hsLen := uint32(hsData[1])<<16 | uint32(hsData[2])<<8 | uint32(hsData[3])
	if len(hsData) < int(hsLen)+4 {
		return nil, fmt.Errorf("handshake truncated")
	}

	clientHelloBody := hsData[4 : 4+hsLen]
	return parseClientHelloBody(clientHelloBody, recordVersion)
}

func parseClientHelloBody(body []byte, recordVersion uint16) (*Fingerprint, error) {
	if len(body) < 38 {
		return nil, fmt.Errorf("client hello body too short")
	}

	offset := 0

	clientVersion := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2

	_ = body[offset : offset+32] // Random
	offset += 32

	// Session ID
	sessIDLen := int(body[offset])
	offset++
	if len(body) < offset+sessIDLen {
		return nil, fmt.Errorf("session id overflow")
	}
	offset += sessIDLen

	// Cipher Suites
	if len(body) < offset+2 {
		return nil, fmt.Errorf("cipher suites length overflow")
	}
	csLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+csLen {
		return nil, fmt.Errorf("cipher suites overflow")
	}
	cipherSuites := make([]uint16, csLen/2)
	for i := 0; i < csLen/2; i++ {
		cipherSuites[i] = binary.BigEndian.Uint16(body[offset+i*2 : offset+i*2+2])
	}
	offset += csLen

	// Compression Methods
	if len(body) < offset+1 {
		return nil, fmt.Errorf("compression length overflow")
	}
	compLen := int(body[offset])
	offset++
	if len(body) < offset+compLen {
		return nil, fmt.Errorf("compression overflow")
	}
	offset += compLen

	// Extensions
	extensions := []uint16{}
	curves := []uint16{}
	pointFormats := []byte{}
	sigAlgs := []uint16{}
	var sni string
	alpn := []string{}

	if offset < len(body) {
		if len(body) < offset+2 {
			return nil, fmt.Errorf("extensions length overflow")
		}
		extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		extEnd := offset + extLen
		if extEnd > len(body) {
			extEnd = len(body)
		}

		for offset < extEnd {
			if len(body) < offset+4 {
				break
			}
			extType := binary.BigEndian.Uint16(body[offset : offset+2])
			extDataLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
			offset += 4

			extensions = append(extensions, extType)

			if len(body) < offset+extDataLen {
				break
			}
			extData := body[offset : offset+extDataLen]

			switch extType {
			case extServerName:
				sni = parseSNI(extData)
			case extSupportedGroups:
				curves = parseCurves(extData)
			case extECPointFormats:
				pointFormats = parsePointFormats(extData)
			case extSignatureAlgs:
				sigAlgs = parseSigAlgs(extData)
			case extALPN:
				alpn = parseALPN(extData)
			}

			offset += extDataLen
		}
	}

	fp := &Fingerprint{
		TLSVersion:    clientVersion,
		SNI:           sni,
		ALPN:          alpn,
		CipherSuites:  cipherSuites,
		Extensions:    extensions,
		Curves:        curves,
		PointFormats:  pointFormats,
		SupportedAlgs: sigAlgs,
	}

	fp.JA3 = computeJA3String(cipherSuites, extensions, curves, pointFormats)
	fp.JA3Hash = fmt.Sprintf("%x", md5.Sum([]byte(fp.JA3)))

	return fp, nil
}

func computeJA3String(ciphers, extensions, curves []uint16, pointFormats []byte) string {
	csParts := make([]string, len(ciphers))
	for i, c := range ciphers {
		csParts[i] = fmt.Sprintf("%d", c)
	}

	extParts := make([]string, 0)
	for _, e := range extensions {
		if e == 0x0015 { // GREASE - skip
			continue
		}
		extParts = append(extParts, fmt.Sprintf("%d", e))
	}

	curveParts := make([]string, len(curves))
	for i, c := range curves {
		curveParts[i] = fmt.Sprintf("%d", c)
	}

	pfParts := make([]string, len(pointFormats))
	for i, p := range pointFormats {
		pfParts[i] = fmt.Sprintf("%d", p)
	}

	cipherStr := strings.Join(csParts, ",")
	extStr := strings.Join(extParts, ",")
	curveStr := strings.Join(curveParts, ",")
	pfStr := strings.Join(pfParts, ",")

	return strings.Join([]string{cipherStr, extStr, curveStr, pfStr}, ";")
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2
	end := offset + listLen
	if end > len(data) {
		end = len(data)
	}
	for offset < end {
		if len(data) < offset+3 {
			break
		}
		nameType := data[offset]
		nameLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		if nameType == 0 && len(data) >= offset+nameLen {
			return string(data[offset : offset+nameLen])
		}
		offset += nameLen
	}
	return ""
}

func parseCurves(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2
	end := offset + listLen
	if end > len(data) {
		end = len(data)
	}
	curves := make([]uint16, 0)
	for offset+1 < end {
		curves = append(curves, binary.BigEndian.Uint16(data[offset:offset+2]))
		offset += 2
	}
	return curves
}

func parsePointFormats(data []byte) []byte {
	if len(data) < 1 {
		return nil
	}
	length := int(data[0])
	offset := 1
	end := offset + length
	if end > len(data) {
		end = len(data)
	}
	return data[offset:end]
}

func parseSigAlgs(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2
	end := offset + listLen
	if end > len(data) {
		end = len(data)
	}
	algs := make([]uint16, 0)
	for offset+1 < end {
		algs = append(algs, binary.BigEndian.Uint16(data[offset:offset+2]))
		offset += 2
	}
	return algs
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2
	end := offset + listLen
	if end > len(data) {
		end = len(data)
	}
	protocols := make([]string, 0)
	for offset < end {
		if len(data) < offset+1 {
			break
		}
		protoLen := int(data[offset])
		offset++
		if len(data) >= offset+protoLen {
			protocols = append(protocols, string(data[offset:offset+protoLen]))
			offset += protoLen
		} else {
			break
		}
	}
	return protocols
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = io.EOF
