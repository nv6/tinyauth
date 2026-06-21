package controller

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestOAuthController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	type testCase struct {
		description       string
		run               func(ctrl *OAuthController)
		trustedDomains    []string
		subdomainsEnabled bool
	}

	tests := []testCase{
		{
			description:       "Test exact match of redirect URI",
			trustedDomains:    []string{"https://tinyauth.example.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://tinyauth.example.com"
				assert.True(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test subdomain match of redirect URI",
			trustedDomains:    []string{"https://tinyauth.example.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://sub.example.com"
				assert.True(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test different trusted domain",
			trustedDomains:    []string{"https://tinyauth.example.com", "https://tinyauth.foo.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://app.foo.com"
				assert.True(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description: "Test invalid redirect URI",
			run: func(ctrl *OAuthController) {
				redirectUri := "https:/malicious"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description: "Test empty redirect URI",
			run: func(ctrl *OAuthController) {
				redirectUri := ""
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test redirect URI with different scheme",
			trustedDomains:    []string{"https://tinyauth.example.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "http://tinyauth.example.com"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test redirect URI with different port",
			trustedDomains:    []string{"https://tinyauth.example.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://tinyauth.example.com:8080"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			// weird case, subdomains enabled and domain without subdomain can't happen
			description:    "Test with trusted domain that's in PSL when split",
			trustedDomains: []string{"https://example.com"}, // will become .com which we
			// obviously don't want to allow
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://sub.example.com"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test subdomain redirect URI when subdomains are disabled",
			trustedDomains:    []string{"https://tinyauth.example.com"},
			subdomainsEnabled: false,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://sub.tinyauth.example.com"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test domain like the .co.uk",
			trustedDomains:    []string{"https://example.co.uk"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://sub.example.co.uk"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test domain like the .co.uk with subdomains disabled",
			trustedDomains:    []string{"https://example.co.uk"},
			subdomainsEnabled: false,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://example.co.uk"
				assert.True(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test caps domain",
			trustedDomains:    []string{"https://TINYAUTH.ExAmpLe.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://sUb.ExAmPle.com"
				assert.True(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
		{
			description:       "Test edge case with @",
			trustedDomains:    []string{"https://tinyauth.example.com"},
			subdomainsEnabled: true,
			run: func(ctrl *OAuthController) {
				redirectUri := "https://malicious.example.com@evil.com"
				assert.False(t, ctrl.isRedirectSafe(redirectUri))
			},
		},
	}

	// TODO: add auth service
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			router := gin.Default()
			group := router.Group("/api")
			gin.SetMode(gin.TestMode)
			// overwrite the trusted domains and subdomain setting for each test case
			runtime.TrustedDomains = tc.trustedDomains
			cfg.Auth.SubdomainsEnabled = tc.subdomainsEnabled
			ctrl := NewOAuthController(OAuthControllerInput{
				Log:           log,
				Config:        &cfg,
				RuntimeConfig: &runtime,
				RouterGroup:   group,
			})
			tc.run(ctrl)
		})
	}
}
