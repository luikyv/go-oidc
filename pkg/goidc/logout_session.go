package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// LogoutSessionManager contains all the logic needed to manage logout sessions.
type LogoutSessionManager interface {
	Save(ctx context.Context, session *LogoutSession) error
	SessionByCallbackID(ctx context.Context, callbackID string) (*LogoutSession, error)
	Delete(ctx context.Context, id string) error
}

type LogoutSession struct {
	ID         string `json:"id"`
	ClientID   string `json:"client_id,omitempty"`
	PolicyID   string `json:"policy_id,omitempty"`
	CallbackID string `json:"callback_id,omitempty"`
	StepID     string `json:"step_id,omitempty"`

	ExpiresAtTimestamp int            `json:"expires_at"`
	CreatedAtTimestamp int            `json:"created_at"`
	IDTokenHintClaims  map[string]any `json:"id_token_hint_claims,omitempty"`
	LogoutParameters
}

func (ls *LogoutSession) IsExpired() bool {
	return timeutil.TimestampNow() >= ls.ExpiresAtTimestamp
}
