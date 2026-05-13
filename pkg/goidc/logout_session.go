package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// LogoutSessionManager contains all the logic needed to manage logout sessions.
type LogoutSessionManager interface {
	SaveLogoutSession(ctx context.Context, session *LogoutSession) error
	LogoutSession(ctx context.Context, callbackID string) (*LogoutSession, error)
	DeleteLogoutSession(ctx context.Context, id string) error
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
