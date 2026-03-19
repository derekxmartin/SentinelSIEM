package auth

import "time"

// Role represents a user's role for RBAC.
type Role string

const (
	RoleAdmin            Role = "admin"
	RoleDetectionEngineer Role = "detection_engineer"
	RoleSOCLead          Role = "soc_lead"
	RoleAnalyst          Role = "analyst"
	RoleReadOnly         Role = "read_only"
)

// ValidRoles is the set of allowed roles.
var ValidRoles = map[Role]bool{
	RoleAdmin:             true,
	RoleDetectionEngineer: true,
	RoleSOCLead:           true,
	RoleAnalyst:           true,
	RoleReadOnly:          true,
}

// User represents a AkesoSIEM user account.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	Email        string     `json:"email,omitempty"`
	PasswordHash string     `json:"password_hash"`
	Role         Role       `json:"role"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	MFASecret    string     `json:"mfa_secret,omitempty"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// Session represents a refresh token session stored in ES.
type Session struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	TokenHash    string     `json:"token_hash"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Revoked      bool       `json:"revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
	IP           string     `json:"ip,omitempty"`
}

// IsValid returns true if the session is not revoked and not expired.
func (s *Session) IsValid() bool {
	return !s.Revoked && time.Now().UTC().Before(s.ExpiresAt)
}

// UserResponse is the safe representation of a user (no password hash or MFA secret).
type UserResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email,omitempty"`
	Role        Role       `json:"role"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// ToResponse converts a User to its safe public representation.
func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Email:       u.Email,
		Role:        u.Role,
		MFAEnabled:  u.MFAEnabled,
		Disabled:    u.Disabled,
		CreatedAt:   u.CreatedAt,
		LastLoginAt: u.LastLoginAt,
	}
}

// LoginRequest is the request body for login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the response from a successful login.
type LoginResponse struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int           `json:"expires_in"`
	User         *UserResponse `json:"user"`
	MFARequired  bool          `json:"mfa_required,omitempty"`
	MFAToken     string        `json:"mfa_token,omitempty"`
}

// CreateUserRequest is the request body for creating a user.
type CreateUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
	Role        Role   `json:"role"`
}

// Validate checks the request for required fields.
func (r *CreateUserRequest) Validate() error {
	if r.Username == "" {
		return errorf("username is required")
	}
	if len(r.Username) < 3 || len(r.Username) > 64 {
		return errorf("username must be 3-64 characters")
	}
	if r.Password == "" {
		return errorf("password is required")
	}
	if len(r.Password) < 8 {
		return errorf("password must be at least 8 characters")
	}
	if r.DisplayName == "" {
		return errorf("display_name is required")
	}
	if !ValidRoles[r.Role] {
		return errorf("invalid role: %s", r.Role)
	}
	return nil
}
