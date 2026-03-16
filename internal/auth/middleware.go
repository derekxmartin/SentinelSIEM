package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/SentinelSIEM/sentinel-siem/internal/common"
)

type contextKey string

const (
	// ContextKeyClaims is the context key for JWT claims.
	ContextKeyClaims contextKey = "auth_claims"

	// ContextKeyAPIKey is the context key for authenticated API key.
	ContextKeyAPIKey contextKey = "auth_api_key"
)

// ClaimsFromContext extracts JWT claims from the request context.
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(ContextKeyClaims).(*Claims)
	return claims
}

// APIKeyFromContext extracts the API key from the request context.
func APIKeyFromContext(ctx context.Context) *common.APIKey {
	key, _ := ctx.Value(ContextKeyAPIKey).(*common.APIKey)
	return key
}

// Middleware creates an HTTP middleware that authenticates requests using either
// a JWT Bearer token or an X-API-Key header. This dual-auth approach allows
// dashboard users (JWT) and ingestion/CLI integrations (API key) to coexist.
//
// Unauthenticated requests receive a 401 response.
func Middleware(jwtManager *JWTManager, apiKeyStore *common.APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try JWT Bearer token first.
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
					claims, err := jwtManager.ValidateAccessToken(tokenStr)
					if err != nil {
						http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
						return
					}
					// Reject MFA-purpose tokens from normal API access.
					if claims.Purpose == "mfa" {
						http.Error(w, `{"error":"MFA verification required"}`, http.StatusUnauthorized)
						return
					}
					ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Try X-API-Key header.
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				key := apiKeyStore.Authenticate(apiKey)
				if key == nil {
					http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
					return
				}
				ctx := context.WithValue(r.Context(), ContextKeyAPIKey, key)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		})
	}
}

// RequireRole returns middleware that checks the authenticated user has one of
// the specified roles. Must be used after the auth Middleware.
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := make(map[Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// JWT-authenticated users have role claims.
			claims := ClaimsFromContext(r.Context())
			if claims != nil {
				if !allowed[claims.Role] {
					http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// API key-authenticated requests bypass role checks (they have scopes instead).
			apiKey := APIKeyFromContext(r.Context())
			if apiKey != nil {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		})
	}
}

// RequireAPIKeyScope returns middleware that verifies the API key has a specific scope.
// Only applies to API key auth — JWT-authenticated requests pass through.
func RequireAPIKeyScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// JWT users pass through (they use role-based auth).
			if ClaimsFromContext(r.Context()) != nil {
				next.ServeHTTP(w, r)
				return
			}

			apiKey := APIKeyFromContext(r.Context())
			if apiKey == nil {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			if !apiKey.HasScope(scope) {
				http.Error(w, `{"error":"insufficient API key scope"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
