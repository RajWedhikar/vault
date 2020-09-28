package cache

import (
	"net/http"
	"strings"

	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/sdk/helper/consts"
)

func authenticateToken(r *http.Request, tokenSecret string, patterns []string) bool {
	token := r.Header.Get(consts.RequestHeaderVaultAgentToken)
	identifier, match := extractIdentifier(r.URL.Path, patterns)
	if match && identifier != "" {
		if token == "" {
			return false
		}
		if token != config.IdentityToken(tokenSecret, identifier) {
			return false
		}
	}
	r.Header.Del(consts.RequestHeaderVaultAgentToken)
	return true
}

func extractIdentifier(path string, patterns []string) (rv string, match bool) {
	for _, p := range patterns {
		p = strings.Trim(p, "/")
		path = strings.Trim(path, "/")
		patternFragments := strings.Split(p, "/")
		pathFragments := strings.Split(path, "/")
		rv, match = matchPatterns(pathFragments, patternFragments)
		if match {
			return
		}
	}
	return
}

func matchPatterns(values, patterns []string) (rv string, match bool) {
	if len(values) != len(patterns) {
		return
	}
	match = true
	for i := 0; i < len(patterns); i++ {
		if patterns[i] == consts.AuthPatternIdentifier {
			if rv != "" {
				return "", false
			}
			rv = values[i]
		} else if patterns[i] != values[i] {
			return "", false
		}
	}
	return
}

func contains(sArray []string, str string) bool {
	for _, s := range sArray {
		if s == str {
			return true
		}
	}
	return false
}
