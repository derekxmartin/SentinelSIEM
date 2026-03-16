package auth

import (
	"testing"
	"time"
)

func TestGenerateMFAToken_HasPurposeClaim(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	user := &User{
		ID:       "user-123",
		Username: "testuser",
		Role:     RoleAnalyst,
	}

	token, err := mgr.GenerateMFAToken(user)
	if err != nil {
		t.Fatalf("GenerateMFAToken: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Validate as MFA token — should succeed.
	claims, err := mgr.ValidateMFAToken(token)
	if err != nil {
		t.Fatalf("ValidateMFAToken: %v", err)
	}

	if claims.Purpose != "mfa" {
		t.Fatalf("Purpose = %q, want %q", claims.Purpose, "mfa")
	}
	if claims.UserID != "user-123" {
		t.Fatalf("UserID = %q, want %q", claims.UserID, "user-123")
	}
}

func TestMFAToken_RejectedAsAccessToken(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	user := &User{
		ID:       "user-123",
		Username: "testuser",
		Role:     RoleAnalyst,
	}

	// Generate MFA token.
	mfaToken, _ := mgr.GenerateMFAToken(user)

	// ValidateAccessToken should parse it fine (same signing key).
	claims, err := mgr.ValidateAccessToken(mfaToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken should parse MFA token: %v", err)
	}

	// But the Purpose should be "mfa" — middleware should reject it.
	if claims.Purpose != "mfa" {
		t.Fatalf("Purpose = %q, want %q", claims.Purpose, "mfa")
	}
}

func TestAccessToken_RejectedAsMFAToken(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	user := &User{
		ID:       "user-123",
		Username: "testuser",
		Role:     RoleAnalyst,
	}

	// Generate regular access token.
	accessToken, _ := mgr.GenerateAccessToken(user)

	// ValidateMFAToken should reject it (wrong purpose).
	_, err := mgr.ValidateMFAToken(accessToken)
	if err == nil {
		t.Fatal("ValidateMFAToken should reject regular access tokens")
	}
}

func TestMFAToken_ShorterExpiry(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	user := &User{
		ID:       "user-123",
		Username: "testuser",
		Role:     RoleAnalyst,
	}

	mfaToken, _ := mgr.GenerateMFAToken(user)
	claims, _ := mgr.ValidateAccessToken(mfaToken)

	expiry := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	if expiry > 6*time.Minute {
		t.Fatalf("MFA token expiry = %v, want ≤ 5 minutes", expiry)
	}
	if expiry < 4*time.Minute {
		t.Fatalf("MFA token expiry = %v, want ~5 minutes", expiry)
	}
}
