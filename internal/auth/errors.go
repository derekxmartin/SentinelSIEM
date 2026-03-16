package auth

import (
	"errors"
	"fmt"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrUserDisabled     = errors.New("user account is disabled")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrUsernameExists   = errors.New("username already exists")
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionExpired   = errors.New("session expired")
	ErrInvalidToken     = errors.New("invalid token")
	ErrMFARequired      = errors.New("MFA verification required")
	ErrMFAAlreadyEnabled = errors.New("MFA is already enabled")
	ErrMFANotEnabled    = errors.New("MFA is not enabled")
	ErrMFANotEnrolled   = errors.New("no MFA enrollment pending")
	ErrInvalidMFACode   = errors.New("invalid MFA code")
	ErrMFANotConfigured = errors.New("MFA encryption key not configured on server")
)

func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
