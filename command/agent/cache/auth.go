package cache

import (
	"net/http"
	"strings"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/sdk/helper/consts"
)

func authenticateToken(r *http.Request, tokenSecret string, patterns []string, logger hclog.Logger) bool {
	token := r.Header.Get(consts.RequestHeaderVaultAgentToken)
	identifier, match := extractIdentifier(r.URL.Path, patterns, logger)
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

func extractIdentifier(path string, patterns []string, logger hclog.Logger) (rv string, match bool) {
	for _, p := range patterns {
		p = strings.Trim(p, "/")
		path = strings.Trim(path, "/")
		patternFragments := strings.Split(p, "/")
		pathFragments := strings.Split(path, "/")
		rv, match = matchPatterns(pathFragments, patternFragments, logger)
		if match {
			return
		}
	}
	return
}

func matchPatterns(values, patterns []string, logger hclog.Logger) (rv string, match bool) {
	if len(values) != len(patterns) {
		return
	}
	match = true
	for i := 0; i < len(patterns); i++ {
		if patterns[i] == ":identifier" {
			if rv != "" {
				logger.Error("Error! A pattern should have only one :identifier. Pattern: " + strings.Join(patterns, "/"))
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
