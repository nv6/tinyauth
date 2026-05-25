package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func newTestAuthService(whitelist []string) *AuthService {
	log := logger.NewLogger().WithTestConfig()
	log.Init()
	return &AuthService{
		log: log,
		runtime: model.RuntimeConfig{
			OAuthWhitelist: whitelist,
		},
	}
}

func TestIsEmailWhitelisted(t *testing.T) {
	tests := []struct {
		name      string
		whitelist []string
		email     string
		expected  bool
	}{
		{
			name:      "empty whitelist denies all",
			whitelist: []string{},
			email:     "user@example.com",
			expected:  false,
		},
		{
			name:      "nil whitelist denies all",
			whitelist: nil,
			email:     "user@example.com",
			expected:  false,
		},
		{
			name:      "matching email is allowed",
			whitelist: []string{"user@example.com"},
			email:     "user@example.com",
			expected:  true,
		},
		{
			name:      "non-matching email is denied",
			whitelist: []string{"user@example.com"},
			email:     "other@example.com",
			expected:  false,
		},
		{
			name:      "multiple entries, matching email is allowed",
			whitelist: []string{"alice@example.com", "bob@example.com"},
			email:     "bob@example.com",
			expected:  true,
		},
		{
			name:      "multiple entries, non-matching email is denied",
			whitelist: []string{"alice@example.com", "bob@example.com"},
			email:     "charlie@example.com",
			expected:  false,
		},
		{
			name:      "regex pattern matches email",
			whitelist: []string{"/@example\\.com$/"},
			email:     "anyone@example.com",
			expected:  true,
		},
		{
			name:      "regex pattern does not match different domain",
			whitelist: []string{"/@example\\.com$/"},
			email:     "anyone@other.com",
			expected:  false,
		},
		{
			name:      "wildcard domain pattern with regex",
			whitelist: []string{"/^.+@mycompany\\.org$/"},
			email:     "employee@mycompany.org",
			expected:  true,
		},
		{
			name:      "only global whitelist is used, not any per-provider list",
			whitelist: []string{"global@example.com"},
			email:     "global@example.com",
			expected:  true,
		},
		{
			name:      "whitespace-only entries are handled gracefully",
			whitelist: []string{"  "},
			email:     "user@example.com",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := newTestAuthService(tt.whitelist)
			result := auth.IsEmailWhitelisted(tt.email)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsEmailWhitelistedNoPerProviderList verifies the new behaviour where
// per-provider whitelist overrides are no longer applied; only the global
// OAuthWhitelist is consulted regardless of which OAuth provider was used.
func TestIsEmailWhitelistedNoPerProviderList(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	auth := &AuthService{
		log: log,
		runtime: model.RuntimeConfig{
			OAuthWhitelist: []string{"global@example.com"},
			// OAuthProviders still present but their Whitelist field has been removed
			OAuthProviders: map[string]model.OAuthServiceConfig{
				"github": {
					ClientID: "github-client-id",
				},
			},
		},
	}

	// Global whitelist allows this email regardless of provider
	assert.True(t, auth.IsEmailWhitelisted("global@example.com"))
	// Global whitelist denies this email even though it was previously
	// allowed by a provider-specific list in the old implementation
	assert.False(t, auth.IsEmailWhitelisted("provider-only@example.com"))
}
