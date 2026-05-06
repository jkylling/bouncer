// Package z85 implements the ZeroMQ Base-85 encoding (RFC 32) with a
// 1-byte pad-length frame so non-aligned inputs round-trip cleanly.
//
// Used inside the JWT `enc` claim because Z85's output embeds in a
// JSON string without escaping (no `"`, `\`) — so it survives the
// JWT payload unchanged.
package z85

import "fmt"

// alphabet is the 85-char Z85 set, in value order. See
// https://rfc.zeromq.org/spec/32/.
const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"

var decoder [256]byte

func init() {
	for i := range decoder {
		decoder[i] = 0xFF
	}
	for i, c := range []byte(alphabet) {
		decoder[c] = byte(i)
	}
}

// Encode encodes data of any length using a length-prefixed framing
// so the decoder can recover non-multiple-of-4 inputs. The first byte
// stores `(4 - (len(data)+1) % 4) % 4` (the pad count), then the data
// is right-padded with zero bytes up to a multiple of 4 and
// z85-encoded normally. Pad count + payload bytes are encoded as one
// stream so the result is always a valid Z85 length (multiple of 5).
func Encode(data []byte) string {
	pad := (4 - (len(data)+1)%4) % 4
	buf := make([]byte, 1+len(data)+pad)
	buf[0] = byte(pad)
	copy(buf[1:], data)
	out := make([]byte, 0, len(buf)/4*5)
	for i := 0; i < len(buf); i += 4 {
		v := uint32(buf[i])<<24 | uint32(buf[i+1])<<16 | uint32(buf[i+2])<<8 | uint32(buf[i+3])
		var chunk [5]byte
		for j := 4; j >= 0; j-- {
			chunk[j] = alphabet[v%85]
			v /= 85
		}
		out = append(out, chunk[:]...)
	}
	return string(out)
}

// Decode reverses Encode, recovering the original (possibly
// non-aligned) byte payload. Returns errors on bad length, unknown
// characters, or pad counts that exceed the encoded payload.
func Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("z85: empty input")
	}
	if len(s)%5 != 0 {
		return nil, fmt.Errorf("z85: input length %d not a multiple of 5", len(s))
	}
	raw := make([]byte, 0, len(s)/5*4)
	for i := 0; i < len(s); i += 5 {
		var v uint32
		for j := 0; j < 5; j++ {
			d := decoder[s[i+j]]
			if d == 0xFF {
				return nil, fmt.Errorf("z85: invalid character %q at %d", s[i+j], i+j)
			}
			v = v*85 + uint32(d)
		}
		raw = append(raw, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	pad := int(raw[0])
	if pad > 3 {
		return nil, fmt.Errorf("z85: invalid pad count %d", pad)
	}
	return raw[1 : len(raw)-pad], nil
}
