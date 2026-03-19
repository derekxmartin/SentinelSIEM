package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestTOTPManager_GenerateSecret(t *testing.T) {
	mgr := NewTOTPManager("AkesoSIEM")

	secret, uri, err := mgr.GenerateSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if secret == "" {
		t.Fatal("expected non-empty secret")
	}

	if uri == "" {
		t.Fatal("expected non-empty URI")
	}

	// URI should be an otpauth:// URL.
	if len(uri) < 10 || uri[:10] != "otpauth://" {
		t.Fatalf("URI should start with otpauth://, got %q", uri[:20])
	}
}

func TestTOTPManager_ValidateCode_Valid(t *testing.T) {
	mgr := NewTOTPManager("AkesoSIEM")

	secret, _, err := mgr.GenerateSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	// Generate a valid code for right now.
	code, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if !mgr.ValidateCode(secret, code) {
		t.Fatal("expected valid code to pass validation")
	}
}

func TestTOTPManager_ValidateCode_Invalid(t *testing.T) {
	mgr := NewTOTPManager("AkesoSIEM")

	secret, _, err := mgr.GenerateSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if mgr.ValidateCode(secret, "000000") {
		// There's a tiny chance this is the actual code, but extremely unlikely.
		if mgr.ValidateCode(secret, "999999") {
			t.Fatal("both 000000 and 999999 should not be valid simultaneously")
		}
	}
}

func TestTOTPManager_ValidateCode_WindowTolerance(t *testing.T) {
	mgr := NewTOTPManager("AkesoSIEM")

	secret, _, err := mgr.GenerateSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	// Generate a code for the previous 30s window (should be accepted with Skew=1).
	prevTime := time.Now().UTC().Add(-30 * time.Second)
	code, err := totp.GenerateCodeCustom(secret, prevTime, totp.ValidateOpts{
		Period:    30,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if !mgr.ValidateCode(secret, code) {
		t.Fatal("code from previous window should be accepted with ±1 tolerance")
	}
}
