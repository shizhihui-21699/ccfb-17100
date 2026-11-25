// Package shortcode generates link codes.
//
// Codes are random, not sequential. Sequential codes let anyone enumerate
// every link the company has ever made — including the internal ones — and
// correlate them with campaigns. Random codes with a checksum-free alphabet
// make bulk enumeration infeasible while staying short enough for SMS.
package shortcode

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// alphabet is Crockford-ish base32 without characters that look alike
// (0/O, 1/I/L). Case-insensitive on lookup.
const alphabet = "23456789abcdefghjkmnpqrstuvwxyz"

const DefaultLen = 7

var ErrTooShort = errors.New("shortcode: length too short")

type Generator struct {
	Length int
}

func New(length int) *Generator {
	if length <= 0 {
		length = DefaultLen
	}
	return &Generator{Length: length}
}

func (g *Generator) New() (string, error) {
	if g.Length < 4 {
		return "", ErrTooShort
	}
	b := make([]byte, g.Length)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}

// Normalize lowercases and rejects characters outside the alphabet, so the
// lookup path never has to guess at case or homoglyphs.
func Normalize(code string) (string, bool) {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return "", false
	}
	for i := 0; i < len(code); i++ {
		if !strings.ContainsRune(alphabet, rune(code[i])) {
			return "", false
		}
	}
	return code, true
}

// EntropyBits is how much guessing space a code of length n has. Used in docs
// and tests to justify the default length.
func EntropyBits(n int) float64 {
	return float64(n) * 5 // log2(32) == 5
}
