package ssf

import (
	"fmt"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type requestVerificationEvent struct {
	StreamID string `json:"stream_id"`
	State    string `json:"state,omitempty"`
}

func scheduleVerificationEvent(ctx oidc.Context, req requestVerificationEvent) error {
	stream, _, err := authorizedStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	now := timeutil.TimestampNow()
	if ctx.SSFVerificationMinInterval != 0 && stream.VerifiedAt != 0 && stream.VerifiedAt+ctx.SSFVerificationMinInterval > now {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "verification event cannot be triggered within the minimum verification interval").WithStatusCode(http.StatusTooManyRequests)
	}

	claims := make(map[string]any)
	if req.State != "" {
		claims["state"] = req.State
	}
	event := goidc.SSFEvent{
		ID:   ctx.SSFEventID(),
		Type: goidc.SSFEventTypeVerification,
		Subject: goidc.SSFSubject{
			Format: goidc.SSFSubjectFormatOpaque,
			ID:     stream.ID,
		},
		Claims:   claims,
		IssuedAt: now,
	}

	if err := ctx.SSFScheduleVerificationEvent(stream.ID, event); err != nil {
		return fmt.Errorf("could not schedule the verification event: %w", err)
	}

	stream.VerifiedAt = now
	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = now + ctx.SSFInactivityTimeoutSecs
	}
	if err := ctx.SSFSaveStream(stream); err != nil {
		return fmt.Errorf("could not update the event stream verification timestamp: %w", err)
	}

	return nil
}
