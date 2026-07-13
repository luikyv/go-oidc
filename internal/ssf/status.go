package ssf

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const maxStatusReasonSize = 1024

type requestStatus struct {
	ID           string                `json:"stream_id"`
	Status       goidc.SSFStreamStatus `json:"status"`
	StatusReason string                `json:"status_reason,omitempty"`
}

type responseStatus struct {
	ID           string                `json:"stream_id"`
	Status       goidc.SSFStreamStatus `json:"status"`
	StatusReason string                `json:"status_reason,omitempty"`
}

func fetchStreamStatus(ctx oidc.Context, id string) (responseStatus, error) {
	stream, _, err := authorizedStream(ctx, id)
	if err != nil {
		return responseStatus{}, err
	}

	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFSaveStream(stream); err != nil {
			return responseStatus{}, fmt.Errorf("could not save the event stream: %w", err)
		}
	}

	return responseStatus{
		ID:           stream.ID,
		Status:       stream.Status,
		StatusReason: stream.StatusReason,
	}, nil
}

func updateStreamStatus(ctx oidc.Context, req requestStatus) (responseStatus, error) {
	if req.ID == "" {
		return responseStatus{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required")
	}

	stream, _, err := authorizedStream(ctx, req.ID)
	if err != nil {
		return responseStatus{}, err
	}

	if req.Status == "" {
		return responseStatus{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream status is required")
	}

	if !slices.Contains([]goidc.SSFStreamStatus{
		goidc.SSFStreamStatusEnabled,
		goidc.SSFStreamStatusPaused,
		goidc.SSFStreamStatusDisabled,
	}, req.Status) {
		return responseStatus{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "stream status %q is not supported", req.Status)
	}

	if len(req.StatusReason) > maxStatusReasonSize {
		return responseStatus{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream status_reason is too long")
	}

	for _, r := range req.StatusReason {
		if r < 0x20 || r == 0x7f {
			return responseStatus{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream status_reason cannot contain control characters")
		}
	}

	if err := ctx.SSFHandleStatus(stream, goidc.SSFStatusOptions{
		Status: req.Status,
		Reason: req.StatusReason,
	}); err != nil {
		return responseStatus{}, fmt.Errorf("could not handle the stream status update: %w", err)
	}

	stream.Status = req.Status
	stream.StatusReason = req.StatusReason
	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
	}
	if err := ctx.SSFSaveStream(stream); err != nil {
		return responseStatus{}, fmt.Errorf("could not update the event stream status: %w", err)
	}

	return responseStatus{
		ID:           stream.ID,
		Status:       stream.Status,
		StatusReason: stream.StatusReason,
	}, nil
}
