package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
)

// APIHandler handles auth-related HTTP endpoints.
type APIHandler struct {
	service     *Service
	rateLimiter *LoginRateLimiter
}

// NewAPIHandler creates a new auth APIHandler.
func NewAPIHandler(service *Service, rateLimiter *LoginRateLimiter) *APIHandler {
	return &APIHandler{service: service, rateLimiter: rateLimiter}
}

// HandleLogin handles POST /api/v1/auth/login.
// Rate limited: 5 failed attempts per 30s per IP → 429.
func (h *APIHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Strip port from RemoteAddr so rate limiting keys on IP only
	// (proxies like Vite use different ephemeral ports per request).
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}

	// Check rate limit before processing.
	if !h.rateLimiter.Allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "too many login attempts, try again later",
		})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	userAgent := r.UserAgent()

	resp, err := h.service.Login(r.Context(), &req, userAgent, ip)
	if err != nil {
		if errors.Is(err, ErrInvalidPassword) || errors.Is(err, ErrUserDisabled) || errors.Is(err, ErrUserNotFound) {
			h.rateLimiter.Record(ip)
			writeError(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		log.Printf("login error: %v", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}

	// Successful login — clear rate limit for this IP.
	h.rateLimiter.Reset(ip)
	writeJSON(w, http.StatusOK, resp)
}

// HandleRefresh handles POST /api/v1/auth/refresh.
func (h *APIHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	resp, err := h.service.RefreshAccessToken(r.Context(), body.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		writeError(w, http.StatusInternalServerError, "refresh failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleLogout handles POST /api/v1/auth/logout.
func (h *APIHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	if err := h.service.Logout(r.Context(), body.RefreshToken); err != nil {
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// HandleGetProfile handles GET /api/v1/auth/profile.
func (h *APIHandler) HandleGetProfile(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	user, err := h.service.GetUser(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, user.ToResponse())
}

// HandleUpdateProfile handles PUT /api/v1/auth/profile.
func (h *APIHandler) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.service.UpdateProfile(r.Context(), claims.UserID, body.DisplayName, body.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "profile update failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleChangePassword handles POST /api/v1/auth/password.
func (h *APIHandler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.CurrentPassword == "" || body.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	if err := h.service.ChangePassword(r.Context(), claims.UserID, body.CurrentPassword, body.NewPassword); err != nil {
		if errors.Is(err, ErrInvalidPassword) {
			writeError(w, http.StatusUnauthorized, "current password is incorrect")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

// HandleSetupRequired handles GET /api/v1/auth/setup-required.
// Returns whether the first-run admin setup is needed (no users exist).
func (h *APIHandler) HandleSetupRequired(w http.ResponseWriter, r *http.Request) {
	count, err := h.service.UserCount(r.Context())
	if err != nil {
		// If index doesn't exist yet, setup is required.
		writeJSON(w, http.StatusOK, map[string]bool{"setup_required": true})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"setup_required": count == 0})
}

// HandleFirstRunSetup handles POST /api/v1/auth/setup.
// Creates the first admin user. Only works when no users exist.
func (h *APIHandler) HandleFirstRunSetup(w http.ResponseWriter, r *http.Request) {
	count, err := h.service.UserCount(r.Context())
	if err == nil && count > 0 {
		writeError(w, http.StatusConflict, "setup already completed")
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Force admin role for first-run setup.
	req.Role = RoleAdmin

	user, err := h.service.CreateUser(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, user.ToResponse())
}

// HandleMFAVerify handles POST /api/v1/auth/mfa.
// Completes the MFA login challenge with a TOTP code.
func (h *APIHandler) HandleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.MFAToken == "" || body.Code == "" {
		writeError(w, http.StatusBadRequest, "mfa_token and code are required")
		return
	}

	userAgent := r.UserAgent()
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}

	resp, err := h.service.VerifyMFALogin(r.Context(), body.MFAToken, body.Code, userAgent, ip)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			writeError(w, http.StatusUnauthorized, "invalid or expired MFA token")
			return
		}
		if errors.Is(err, ErrInvalidMFACode) {
			writeError(w, http.StatusUnauthorized, "invalid MFA code")
			return
		}
		if errors.Is(err, ErrMFANotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "MFA not configured on server")
			return
		}
		log.Printf("MFA verify error: %v", err)
		writeError(w, http.StatusInternalServerError, "MFA verification failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleMFAEnroll handles POST /api/v1/auth/me/mfa/enroll.
// Starts MFA enrollment by generating a TOTP secret.
func (h *APIHandler) HandleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	secret, uri, err := h.service.EnrollMFA(r.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, ErrMFAAlreadyEnabled) {
			writeError(w, http.StatusConflict, "MFA is already enabled")
			return
		}
		if errors.Is(err, ErrMFANotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "MFA not configured on server")
			return
		}
		log.Printf("MFA enroll error: %v", err)
		writeError(w, http.StatusInternalServerError, "MFA enrollment failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"uri":    uri,
	})
}

// HandleMFAVerifyEnrollment handles POST /api/v1/auth/me/mfa/verify.
// Completes MFA enrollment by verifying a TOTP code.
func (h *APIHandler) HandleMFAVerifyEnrollment(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	if err := h.service.VerifyMFAEnrollment(r.Context(), claims.UserID, body.Code); err != nil {
		if errors.Is(err, ErrMFAAlreadyEnabled) {
			writeError(w, http.StatusConflict, "MFA is already enabled")
			return
		}
		if errors.Is(err, ErrMFANotEnrolled) {
			writeError(w, http.StatusBadRequest, "no MFA enrollment pending — enroll first")
			return
		}
		if errors.Is(err, ErrInvalidMFACode) {
			writeError(w, http.StatusUnauthorized, "invalid MFA code")
			return
		}
		if errors.Is(err, ErrMFANotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "MFA not configured on server")
			return
		}
		log.Printf("MFA verify enrollment error: %v", err)
		writeError(w, http.StatusInternalServerError, "MFA verification failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_enabled"})
}

// HandleMFADisable handles DELETE /api/v1/auth/me/mfa.
// Disables MFA after verifying the user's password.
func (h *APIHandler) HandleMFADisable(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	if err := h.service.DisableMFA(r.Context(), claims.UserID, body.Password); err != nil {
		if errors.Is(err, ErrMFANotEnabled) {
			writeError(w, http.StatusBadRequest, "MFA is not enabled")
			return
		}
		if errors.Is(err, ErrInvalidPassword) {
			writeError(w, http.StatusUnauthorized, "invalid password")
			return
		}
		log.Printf("MFA disable error: %v", err)
		writeError(w, http.StatusInternalServerError, "MFA disable failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_disabled"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
