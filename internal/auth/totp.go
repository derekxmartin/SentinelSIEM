package auth

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPManager handles TOTP secret generation, URI creation, and code validation.
type TOTPManager struct {
	issuer string
}

// NewTOTPManager creates a new TOTPManager with the given issuer name.
func NewTOTPManager(issuer string) *TOTPManager {
	return &TOTPManager{issuer: issuer}
}

// GenerateSecret creates a new TOTP secret and returns the raw secret string
// and the otpauth:// URI for QR code display.
func (t *TOTPManager) GenerateSecret(username string) (secret string, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: username,
		Period:      30,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		SecretSize:  20,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateCode checks a TOTP code against a secret with ±1 window tolerance.
func (t *TOTPManager) ValidateCode(secret, code string) bool {
	valid, _ := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:     1,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}
