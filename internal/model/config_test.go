package model

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDatabaseConfig_DescriptionMentionsPostgres verifies that the DatabaseConfig
// Driver field description explicitly lists "postgres" as a valid value, reflecting
// the newly added PostgreSQL support.
func TestDatabaseConfig_DescriptionMentionsPostgres(t *testing.T) {
	rt := reflect.TypeOf(DatabaseConfig{})

	driverField, ok := rt.FieldByName("Driver")
	assert.True(t, ok, "DatabaseConfig should have a Driver field")

	description := driverField.Tag.Get("description")
	assert.Contains(t, description, "postgres", "DatabaseConfig.Driver description should mention postgres as a valid value")
	assert.Contains(t, description, "sqlite", "DatabaseConfig.Driver description should mention sqlite as a valid value")
	assert.Contains(t, description, "memory", "DatabaseConfig.Driver description should mention memory as a valid value")
}

// TestDatabaseConfig_PathDescriptionMentionsConnectionURL verifies that the Path
// field description covers both SQLite file path and PostgreSQL connection URL usage.
func TestDatabaseConfig_PathDescriptionMentionsConnectionURL(t *testing.T) {
	rt := reflect.TypeOf(DatabaseConfig{})

	pathField, ok := rt.FieldByName("Path")
	assert.True(t, ok, "DatabaseConfig should have a Path field")

	description := pathField.Tag.Get("description")
	assert.Contains(t, description, "postgres",
		"DatabaseConfig.Path description should mention postgres to clarify connection URL usage")
}

// TestIPConfig_NoBypassField verifies that the Bypass field has been removed
// from IPConfig as part of the PR changes. IP bypass lists are now only
// configured at the per-app ACL level.
func TestIPConfig_NoBypassField(t *testing.T) {
	rt := reflect.TypeOf(IPConfig{})

	_, hasBypass := rt.FieldByName("Bypass")
	assert.False(t, hasBypass, "IPConfig should not have a Bypass field after PR changes")
}

// TestIPConfig_HasAllowAndBlock ensures the remaining Allow and Block fields
// are still present in IPConfig after the Bypass removal.
func TestIPConfig_HasAllowAndBlock(t *testing.T) {
	rt := reflect.TypeOf(IPConfig{})

	_, hasAllow := rt.FieldByName("Allow")
	assert.True(t, hasAllow, "IPConfig should still have an Allow field")

	_, hasBlock := rt.FieldByName("Block")
	assert.True(t, hasBlock, "IPConfig should still have a Block field")
}

// TestOAuthServiceConfig_NoWhitelistField verifies that the per-provider Whitelist
// and WhitelistFile fields have been removed from OAuthServiceConfig. The global
// OAuthWhitelist on OAuthConfig/RuntimeConfig is now the only whitelist.
func TestOAuthServiceConfig_NoWhitelistField(t *testing.T) {
	rt := reflect.TypeOf(OAuthServiceConfig{})

	_, hasWhitelist := rt.FieldByName("Whitelist")
	assert.False(t, hasWhitelist, "OAuthServiceConfig should not have a Whitelist field after PR changes")

	_, hasWhitelistFile := rt.FieldByName("WhitelistFile")
	assert.False(t, hasWhitelistFile, "OAuthServiceConfig should not have a WhitelistFile field after PR changes")
}

// TestOAuthServiceConfig_CoreFieldsPreserved ensures that removing the whitelist
// fields did not inadvertently drop unrelated fields.
func TestOAuthServiceConfig_CoreFieldsPreserved(t *testing.T) {
	rt := reflect.TypeOf(OAuthServiceConfig{})

	for _, fieldName := range []string{"ClientID", "ClientSecret", "ClientSecretFile", "Scopes", "RedirectURL", "AuthURL", "TokenURL", "UserinfoURL"} {
		_, ok := rt.FieldByName(fieldName)
		assert.True(t, ok, "OAuthServiceConfig should still have a %s field", fieldName)
	}
}

// TestDatabaseConfig_ZeroValue ensures DatabaseConfig is usable as a zero value
// with the expected default (empty string) driver, which falls back to sqlite.
func TestDatabaseConfig_ZeroValue(t *testing.T) {
	var cfg DatabaseConfig
	assert.Equal(t, "", cfg.Driver, "zero-value Driver should be an empty string (defaults to sqlite)")
	assert.Equal(t, "", cfg.Path, "zero-value Path should be an empty string")
}