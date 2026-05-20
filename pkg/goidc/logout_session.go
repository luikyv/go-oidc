package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// LogoutManager contains all the logic needed to manage logout sessions.
type LogoutManager interface {
	SaveLogoutSession(context.Context, *LogoutSession) error
	// LogoutSession returns the logout session identified by id.
	// It must return [ErrNotFound] when the session does not exist.
	LogoutSession(context.Context, string) (*LogoutSession, error)
}

type LogoutSession struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	ClientID string `json:"client_id,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	StepID   string `json:"step_id,omitempty"`

	ExpiresAt         int            `json:"expires_at"`
	CreatedAt         int            `json:"created_at"`
	IDTokenHintClaims map[string]any `json:"id_token_hint_claims,omitempty"`
	LogoutParameters
}

func (ls *LogoutSession) IsExpired() bool {
	return timeutil.TimestampNow() >= ls.ExpiresAt
}
