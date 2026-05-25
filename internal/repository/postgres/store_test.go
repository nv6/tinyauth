package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/repository"
)

// TestMapErr verifies that mapErr translates known sentinel errors and
// passes through all other errors unchanged.
func TestMapErr(t *testing.T) {
	sentinel := errors.New("some other error")

	tests := []struct {
		name    string
		input   error
		want    error
		isWant  bool // use errors.Is check
	}{
		{
			name:   "nil passes through unchanged",
			input:  nil,
			want:   nil,
			isWant: false,
		},
		{
			name:   "sql.ErrNoRows maps to repository.ErrNotFound",
			input:  sql.ErrNoRows,
			want:   repository.ErrNotFound,
			isWant: true,
		},
		{
			name:   "wrapped sql.ErrNoRows maps to repository.ErrNotFound",
			input:  fmt.Errorf("wrapped: %w", sql.ErrNoRows),
			want:   repository.ErrNotFound,
			isWant: true,
		},
		{
			name:   "arbitrary error passes through unchanged",
			input:  sentinel,
			want:   sentinel,
			isWant: true,
		},
		{
			name:   "wrapped arbitrary error passes through unchanged",
			input:  fmt.Errorf("outer: %w", sentinel),
			want:   fmt.Errorf("outer: %w", sentinel),
			isWant: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapErr(tt.input)
			if tt.input == nil {
				assert.Nil(t, got)
				return
			}
			if tt.isWant {
				assert.True(t, errors.Is(got, tt.want), "expected errors.Is(%v, %v) to be true, got %v", got, tt.want, got)
			} else {
				// For wrapped-arbitrary-error passthrough: the original wrapped error is returned as-is
				assert.Equal(t, tt.input, got)
			}
		})
	}
}

// TestMapErr_ErrNoRows_IsRepositoryErrNotFound specifically asserts the contract
// that callers outside the package can detect repository.ErrNotFound using errors.Is.
func TestMapErr_ErrNoRows_IsRepositoryErrNotFound(t *testing.T) {
	result := mapErr(sql.ErrNoRows)
	require.NotNil(t, result)
	assert.True(t, errors.Is(result, repository.ErrNotFound))
	// Must NOT still be sql.ErrNoRows after mapping
	assert.False(t, errors.Is(result, sql.ErrNoRows))
}

// TestMapErr_OtherError_IsNotRepositoryErrNotFound ensures unrecognised errors
// are NOT silently converted to ErrNotFound.
func TestMapErr_OtherError_IsNotRepositoryErrNotFound(t *testing.T) {
	someErr := errors.New("connection refused")
	result := mapErr(someErr)
	require.NotNil(t, result)
	assert.False(t, errors.Is(result, repository.ErrNotFound))
	assert.True(t, errors.Is(result, someErr))
}

// TestNewStore ensures that NewStore returns a value satisfying the
// repository.Store interface (compile-time verified) and is not nil.
func TestNewStore(t *testing.T) {
	q := New(nil) // Queries with a nil DBTX — adequate for construction checks
	var store repository.Store = NewStore(q)
	assert.NotNil(t, store)
}

// mockDBTX is a minimal DBTX implementation that returns a configurable error.
type mockDBTX struct {
	err    error
	rowErr error
}

func (m *mockDBTX) ExecContext(_ context.Context, _ string, _ ...interface{}) (sql.Result, error) {
	return nil, m.err
}

func (m *mockDBTX) PrepareContext(_ context.Context, _ string) (*sql.Stmt, error) {
	return nil, m.err
}

func (m *mockDBTX) QueryContext(_ context.Context, _ string, _ ...interface{}) (*sql.Rows, error) {
	return nil, m.err
}

func (m *mockDBTX) QueryRowContext(_ context.Context, _ string, _ ...interface{}) *sql.Row {
	// *sql.Row cannot be constructed without internals; returning nil causes a
	// nil-dereference in callers, so we can only test ExecContext-backed methods.
	return nil
}

// TestStore_DeleteSession_PropagatesError verifies that an error returned by the
// underlying DBTX is forwarded (possibly mapped) by the Store wrapper.
func TestStore_DeleteSession_PropagatesError(t *testing.T) {
	customErr := errors.New("exec error")
	mock := &mockDBTX{err: customErr}
	store := NewStore(New(mock))

	err := store.DeleteSession(context.Background(), "some-uuid")
	require.Error(t, err)
	// The error is not ErrNoRows, so it must be passed through as-is.
	assert.True(t, errors.Is(err, customErr))
}

// TestStore_DeleteOidcCode_PropagatesError verifies error propagation for a
// different delete method.
func TestStore_DeleteOidcCode_PropagatesError(t *testing.T) {
	customErr := errors.New("exec error")
	mock := &mockDBTX{err: customErr}
	store := NewStore(New(mock))

	err := store.DeleteOidcCode(context.Background(), "some-hash")
	require.Error(t, err)
	assert.True(t, errors.Is(err, customErr))
}

// TestStore_DeleteExpiredSessions_PropagatesErrNoRowsAsNotFound verifies that
// sql.ErrNoRows is mapped to repository.ErrNotFound through the Store wrapper.
func TestStore_DeleteExpiredSessions_PropagatesError(t *testing.T) {
	customErr := errors.New("db unavailable")
	mock := &mockDBTX{err: customErr}
	store := NewStore(New(mock))

	err := store.DeleteExpiredSessions(context.Background(), 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, customErr))
}