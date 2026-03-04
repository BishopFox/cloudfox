package shared

import (
	"testing"
)

func TestMatchFileName_Credential(t *testing.T) {
	patterns := GetFilePatterns()

	tests := []struct {
		name     string
		input    string
		wantNil  bool
		category string
	}{
		{"service account key", "my-project-sa-key.json", false, "Credential"},
		{"pem file", "certs/server.pem", false, "Credential"},
		{"ssh key", "home/.ssh/id_rsa", false, "Credential"},
		{"p12 file", "keys/cert.p12", false, "Credential"},
		{"random txt", "readme.txt", true, ""},
		{"random png", "image.png", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchFileName(tt.input, patterns)
			if tt.wantNil && result != nil {
				t.Errorf("expected nil match for %q, got %+v", tt.input, result)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("expected match for %q, got nil", tt.input)
			}
			if !tt.wantNil && result != nil && result.Category != tt.category {
				t.Errorf("expected category %q for %q, got %q", tt.category, tt.input, result.Category)
			}
		})
	}
}

func TestMatchFileName_FalsePositives(t *testing.T) {
	patterns := GetFilePatterns()

	// These should be filtered as false positives
	fps := []string{
		"node_modules/package.json",
		"vendor/lib/config.yaml",
		".git/objects/abc123",
		"__pycache__/module.key",
		"dist/bundle.env",
	}

	for _, fp := range fps {
		result := MatchFileName(fp, patterns)
		if result != nil {
			t.Errorf("expected false positive for %q, got %+v", fp, result)
		}
	}
}

func TestMatchFileName_JSONFiltering(t *testing.T) {
	patterns := GetFilePatterns()

	// Plain .json should be filtered unless it contains credential keywords
	result := MatchFileName("data/report.json", patterns)
	if result != nil {
		t.Errorf("expected nil for non-credential json, got %+v", result)
	}

	// Credential-related .json should match
	result = MatchFileName("data/service-account-key.json", patterns)
	if result == nil {
		t.Errorf("expected match for service account json, got nil")
	}
}

func TestMatchContent(t *testing.T) {
	patterns := GetContentPatterns()

	tests := []struct {
		name      string
		input     string
		wantCount int
		category  string
	}{
		{
			"GCP SA key",
			`{"type": "service_account", "project_id": "test"}`,
			1, "Credential",
		},
		{
			"private key",
			`-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...`,
			1, "Credential",
		},
		{
			"AWS key",
			`access_key = AKIAIOSFODNN7EXAMPLE`,
			1, "Credential",
		},
		{
			"JWT",
			`token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc_def-ghi`,
			1, "Token",
		},
		{
			"password assignment",
			`db_password=SuperSecret123`,
			1, "Secret",
		},
		{
			"connection string",
			`url=postgres://user:pass@host:5432/db`,
			1, "Secret",
		},
		{
			"no match",
			`This is a normal log entry with no sensitive data.`,
			0, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := MatchContent(tt.input, patterns)
			if len(matches) != tt.wantCount {
				t.Errorf("expected %d matches for %q, got %d: %+v", tt.wantCount, tt.name, len(matches), matches)
			}
			if tt.wantCount > 0 && len(matches) > 0 && matches[0].Category != tt.category {
				t.Errorf("expected category %q, got %q", tt.category, matches[0].Category)
			}
		})
	}
}

func TestMatchResourceName(t *testing.T) {
	patterns := GetNamePatterns()

	tests := []struct {
		name     string
		input    string
		wantNil  bool
		category string
	}{
		{"password column", "user_password", false, "Credential"},
		{"secret table", "app_secrets", false, "Credential"},
		{"ssn column", "customer_ssn", false, "PII"},
		{"credit card", "credit_card_numbers", false, "PII"},
		{"pii dataset", "raw_pii_data", false, "Compliance"},
		{"payment table", "payment_transactions", false, "Financial"},
		{"normal table", "products", true, ""},
		{"normal column", "created_at", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchResourceName(tt.input, patterns)
			if tt.wantNil && result != nil {
				t.Errorf("expected nil for %q, got %+v", tt.input, result)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("expected match for %q, got nil", tt.input)
			}
			if !tt.wantNil && result != nil && result.Category != tt.category {
				t.Errorf("expected category %q for %q, got %q", tt.category, tt.input, result.Category)
			}
		})
	}
}

func TestIsFilePathFalsePositive(t *testing.T) {
	p := SensitivePattern{Pattern: ".key", Category: "Credential", RiskLevel: "CRITICAL"}

	if !IsFilePathFalsePositive("node_modules/crypto/test.key", p) {
		t.Error("expected node_modules to be false positive")
	}
	if IsFilePathFalsePositive("secrets/server.key", p) {
		t.Error("expected secrets/server.key to not be false positive")
	}
}

func TestExtractSnippet(t *testing.T) {
	text := "prefix some password=Secret123 suffix text"
	snippet := extractSnippet(text, 12, 29, 10)
	if len(snippet) == 0 {
		t.Error("expected non-empty snippet")
	}
	// Snippet should contain the match and some context
	if len(snippet) > len(text) {
		t.Error("snippet should not exceed original text length")
	}
}
