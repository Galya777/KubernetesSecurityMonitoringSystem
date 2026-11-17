package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewID returns a collision-resistant random identifier with the given prefix.
func NewID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; fall back to time-based uniqueness.
		return prefix + "-" + time.Now().Format("20060102150405.000000000")
	}
	return prefix + "-" + hex.EncodeToString(b)
}
