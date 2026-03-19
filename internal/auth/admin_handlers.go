package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// AdminHandler handles admin-only user and API key management endpoints.
type AdminHandler struct {
	service  *Service
	keyStore *common.APIKeyStore
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(service *Service, keyStore *common.APIKeyStore) *AdminHandler {
	return &AdminHandler{service: service, keyStore: keyStore}
}

// Routes registers admin routes on the given router.
// All routes require auth middleware + admin role.
func (h *AdminHandler) Routes(r chi.Router) {
	r.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(RequireRole(RoleAdmin))

		// User management.
		r.Get("/users", h.HandleListUsers)
		r.Post("/users", h.HandleCreateUser)
		r.Put("/users/{id}/disable", h.HandleDisableUser)
		r.Put("/users/{id}/enable", h.HandleEnableUser)
		r.Delete("/users/{id}/mfa", h.HandleResetMFA)

		// API key management.
		r.Get("/keys", h.HandleListKeys)
		r.Post("/keys", h.HandleCreateKey)
		r.Delete("/keys/{id}", h.HandleRevokeKey)
	})
}

// HandleListUsers handles GET /api/v1/admin/users.
func (h *AdminHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.service.ListUsers(r.Context())
	if err != nil {
		log.Printf("list users error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"users": users,
		"total": len(users),
	})
}

// HandleCreateUser handles POST /api/v1/admin/users.
func (h *AdminHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := h.service.CreateUser(r.Context(), &req)
	if err != nil {
		if errors.Is(err, ErrUsernameExists) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "username already exists"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, user.ToResponse())
}

// HandleDisableUser handles PUT /api/v1/admin/users/{id}/disable.
func (h *AdminHandler) HandleDisableUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user ID is required"})
		return
	}

	// Prevent admins from disabling themselves.
	claims := ClaimsFromContext(r.Context())
	if claims != nil && claims.UserID == id {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot disable your own account"})
		return
	}

	if err := h.service.DisableUser(r.Context(), id); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Printf("disable user error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable user"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "user disabled"})
}

// HandleEnableUser handles PUT /api/v1/admin/users/{id}/enable.
func (h *AdminHandler) HandleEnableUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user ID is required"})
		return
	}

	if err := h.service.EnableUser(r.Context(), id); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Printf("enable user error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to enable user"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "user enabled"})
}

// HandleResetMFA handles DELETE /api/v1/admin/users/{id}/mfa.
func (h *AdminHandler) HandleResetMFA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user ID is required"})
		return
	}

	if err := h.service.ResetMFA(r.Context(), id); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Printf("reset MFA error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to reset MFA"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_reset"})
}

// HandleListKeys handles GET /api/v1/admin/keys.
func (h *AdminHandler) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	keys := h.keyStore.List()

	// Sanitize: don't expose hashes.
	type safeKey struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Prefix    string    `json:"prefix"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at,omitempty"`
		Revoked   bool      `json:"revoked"`
		RevokedAt time.Time `json:"revoked_at,omitempty"`
		Scopes    []string  `json:"scopes,omitempty"`
	}

	safe := make([]safeKey, 0, len(keys))
	for _, k := range keys {
		safe = append(safe, safeKey{
			ID:        k.ID,
			Name:      k.Name,
			Prefix:    k.Prefix,
			CreatedAt: k.CreatedAt,
			ExpiresAt: k.ExpiresAt,
			Revoked:   k.Revoked,
			RevokedAt: k.RevokedAt,
			Scopes:    k.Scopes,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"keys":  safe,
		"total": len(safe),
	})
}

// HandleCreateKey handles POST /api/v1/admin/keys.
func (h *AdminHandler) HandleCreateKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresIn int      `json:"expires_in"` // seconds, 0 = no expiry
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	var expiresAt time.Time
	if body.ExpiresIn > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(body.ExpiresIn) * time.Second)
	}

	result, err := h.keyStore.Create(r.Context(), body.Name, body.Scopes, expiresAt)
	if err != nil {
		log.Printf("create API key error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create API key"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":            result.Key.ID,
		"name":          result.Key.Name,
		"prefix":        result.Key.Prefix,
		"plaintext_key": result.PlaintextKey,
		"scopes":        result.Key.Scopes,
		"created_at":    result.Key.CreatedAt,
		"expires_at":    result.Key.ExpiresAt,
	})
}

// HandleRevokeKey handles DELETE /api/v1/admin/keys/{id}.
func (h *AdminHandler) HandleRevokeKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key ID is required"})
		return
	}

	if err := h.keyStore.Revoke(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "key revoked"})
}
