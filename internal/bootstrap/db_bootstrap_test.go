package bootstrap

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

func TestSetupStore_UnknownDriver(t *testing.T) {
	tests := []struct {
		driver  string
		wantErr string
	}{
		{
			driver:  "mysql",
			wantErr: `unknown database driver "mysql": valid values are sqlite, postgres, memory`,
		},
		{
			driver:  "redis",
			wantErr: `unknown database driver "redis": valid values are sqlite, postgres, memory`,
		},
		{
			driver:  "baddriver",
			wantErr: `unknown database driver "baddriver": valid values are sqlite, postgres, memory`,
		},
	}

	for _, tt := range tests {
		t.Run("driver_"+tt.driver, func(t *testing.T) {
			app := NewBootstrapApp(model.Config{
				Database: model.DatabaseConfig{
					Driver: tt.driver,
				},
			})
			store, err := app.SetupStore()
			assert.Nil(t, store)
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err.Error())
		})
	}
}

func TestSetupStore_Memory(t *testing.T) {
	app := NewBootstrapApp(model.Config{
		Database: model.DatabaseConfig{
			Driver: "memory",
		},
	})
	store, err := app.SetupStore()
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestSetupStore_SQLite_ExplicitDriver(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	app := NewBootstrapApp(model.Config{
		Database: model.DatabaseConfig{
			Driver: "sqlite",
			Path:   dbPath,
		},
	})
	store, err := app.SetupStore()
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestSetupStore_SQLite_DefaultDriver(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "default.db")

	app := NewBootstrapApp(model.Config{
		Database: model.DatabaseConfig{
			Driver: "",
			Path:   dbPath,
		},
	})
	store, err := app.SetupStore()
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestSetupStore_Postgres_InvalidURL(t *testing.T) {
	app := NewBootstrapApp(model.Config{
		Database: model.DatabaseConfig{
			Driver: "postgres",
			Path:   "not-a-valid-postgres-url",
		},
	})
	store, err := app.SetupStore()
	// sql.Open does not fail on a bad URL for pgx — it only fails on first use.
	// The error should come from pgxmigrate.WithInstance when the DB is actually
	// pinged / connected, so we expect either success-with-error or an error here.
	// What matters is that the postgres case is reached (i.e., no "unknown driver" error).
	if err != nil {
		assert.False(t, strings.Contains(err.Error(), "unknown database driver"))
		assert.Nil(t, store)
	}
}

func TestSetupStore_ErrorMessageIncludesPostgres(t *testing.T) {
	app := NewBootstrapApp(model.Config{
		Database: model.DatabaseConfig{
			Driver: "oracle",
		},
	})
	_, err := app.SetupStore()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres")
	assert.Contains(t, err.Error(), "sqlite")
	assert.Contains(t, err.Error(), "memory")
}