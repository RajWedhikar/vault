package cache

import (
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
)

func extractIdentifierMatch(t *testing.T, identifier, path string, patterns []string) {
	logger := logging.NewVaultLogger(hclog.Trace)
	id, match := extractIdentifier(path, patterns, logger)
	if id != identifier {
		t.Error("Failed to extract identifier", "id", id)
	}
	if !match {
		t.Error("Failed to extract identifier", "match", match)
	}
}

func extractIdentifierNoMatch(t *testing.T, path string, patterns []string) {
	logger := logging.NewVaultLogger(hclog.Trace)
	id, match := extractIdentifier(path, patterns, logger)
	if id != "" {
		t.Error("Extract identifier should have not have identifier", "id", id)
	}
	if match {
		t.Error("Extract identifier should have no match", "match", match)
	}
}

func TestAuth_ExtractIdentifier(t *testing.T) {
	extractIdentifierMatch(t, "hello", "/svc/ent/dev/hello", []string{"/svc/ent/dev/:identifier"})
	extractIdentifierMatch(t, "hello", "/svc/ent/dev/hello/", []string{"/svc/ent/dev/:identifier"})
	extractIdentifierMatch(t, "hello", "/svc/ent/dev/hello/", []string{"/svc/ent/dev/:identifier/"})
	extractIdentifierMatch(t, "hello", "/svc/ent/dev/hello", []string{"/svc/ent/dev/:identifier/"})
	extractIdentifierMatch(t, "hello", "/svc/ent/dev/hello", []string{"svc/ent/dev/:identifier"})
	extractIdentifierMatch(t, "hello", "svc/ent/dev/hello", []string{"svc/ent/dev/:identifier"})
	extractIdentifierMatch(t, "hello2", "/svc/ent/dev/hello2", []string{"/svc/ent/dev/:identifier"})

	extractIdentifierMatch(t, "ent", "svc/ent/dev/hello", []string{"svc/:identifier/dev/hello"})
	extractIdentifierMatch(t, "svc", "svc/ent/dev/hello", []string{":identifier/ent/dev/hello"})

	extractIdentifierMatch(t, "hello", "/svc/ent/qas/hello", []string{"/svc/ent/prd/:identifier", "/svc/ent/qas/:identifier"})
	extractIdentifierMatch(t, "hello", "/svc/ent/qas/hello", []string{"/svc/ent/qas/:identifier", "/svc/ent/qas/:identifier"})

	extractIdentifierMatch(t, "", "/svc", []string{"/svc"})

	extractIdentifierNoMatch(t, "/svc1/ent/dev/hello", []string{"/svc/ent/dev/:identifier"})
	extractIdentifierNoMatch(t, "/svc/ent/dev/hello/1", []string{"/svc/ent/dev/:identifier"})
	extractIdentifierNoMatch(t, "/svc/ent/dev/", []string{"/svc/ent/dev/:identifier"})
	extractIdentifierNoMatch(t, "/svc/ent/dev", []string{"/svc/ent/dev/:identifier"})

	extractIdentifierNoMatch(t, "/svc/ent1/dev/hello", []string{"/svc/ent/dev/:identifier"})
	extractIdentifierNoMatch(t, "/svc/ent/dev1/hello", []string{"/svc/ent/dev/:identifier"})

	extractIdentifierNoMatch(t, "/svc/ent/dev/hello", []string{"/svc/ent/dev/identifier"})

	extractIdentifierNoMatch(t, "/svc/ent/stg/hello", []string{"/svc/ent/prd/:identifier", "/svc/ent/dev/:identifier"})

	extractIdentifierNoMatch(t, "svc/ent/dev/hello/aloha", []string{"svc/ent/dev/:identifier/:identifier"})
	extractIdentifierNoMatch(t, "svc/ent/dev/hello/aloha", []string{"svc/:identifier/:identifier/:identifier/:identifier"})
}

func matchPatternsPass(t *testing.T, identity string, values, patterns []string) {
	logger := logging.NewVaultLogger(hclog.Trace)
	id, match := matchPatterns(values, patterns, logger)
	if id != identity {
		t.Error("Failed to match patterns", "id", id)
	}
	if !match {
		t.Error("Failed to match patterns", "match", match)
	}
}

func matchPatternsFail(t *testing.T, values, patterns []string) {
	logger := logging.NewVaultLogger(hclog.Trace)
	id, match := matchPatterns(values, patterns, logger)
	if id != "" {
		t.Error("Failed to match patterns", "id", id)
	}
	if match {
		t.Error("Failed to match patterns", "match", match)
	}
}

func TestAuth_MatchPatterns_Pass(t *testing.T) {
	values := []string{"svc", "ent", "dev", "hello"}
	patterns := []string{"svc", "ent", "dev", ":identifier"}
	matchPatternsPass(t, "hello", values, patterns)

	values = []string{"svc", "ent", "dev", "hello"}
	patterns = []string{"svc", "ent", "dev", ":identifier"}
	matchPatternsPass(t, "hello", values, patterns)
}

func TestAuth_MatchPatterns_Fail(t *testing.T) {
	values := []string{"svc", "ent", "dev", "hello"}
	patterns := []string{"svc", "ent", "qas", ":identifier"}
	matchPatternsFail(t, values, patterns)
}
