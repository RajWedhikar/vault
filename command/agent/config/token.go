package config

import (
	"crypto/sha256"
	"fmt"
	"io"
)

func IdentityToken(secret string, input string) string {
	h := sha256.New()
	io.WriteString(h, secret)
	io.WriteString(h, "\n")
	io.WriteString(h, input)

	return fmt.Sprintf("%x", h.Sum(nil))
}
