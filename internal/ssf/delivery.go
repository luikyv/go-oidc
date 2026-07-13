package ssf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	maxPushErrorBodySize        = 4096
	jwtTypeSecurityEventJWT     = "secevent+jwt"
	contentTypeSecurityEventJWT = "application/secevent+jwt"
)

type requestPollEvents struct {
	MaxEvents         *int `json:"maxEvents,omitempty"`
	ReturnImmediately bool `json:"returnImmediately,omitempty"`
	// Acknowledgements is a list of JWT IDs of the events that have been acknowledged.
	Acknowledgements []string `json:"ack,omitempty"`
	// Errors is a map of JWT IDs to errors of the events that have been delivered.
	Errors map[string]goidc.SSFEventError `json:"setErrs,omitempty"`
}

type responsePollEvents struct {
	SecurityEventTokens map[string]string `json:"sets"`
	MoreAvailable       bool              `json:"moreAvailable"`
}

// PushEvent delivers a security event token using SET push delivery.
// See [RFC 8935].
func PushEvent(ctx oidc.Context, streamID string, event goidc.SSFEvent) error {
	stream, err := ctx.SSFStream(streamID)
	if err != nil {
		return fmt.Errorf("could not load the event stream %q: %w", streamID, err)
	}

	// Return an error if the stream did not subscribe to the event type and the event is not a verification event.
	if !slices.Contains(stream.EventsDelivered, event.Type) && (!ctx.SSFVerificationEnabled || event.Type != goidc.SSFEventTypeVerification) {
		return fmt.Errorf("stream did not subscribe to event type %s", event.Type)
	}

	if stream.Delivery.Method != goidc.SSFDeliveryMethodPush {
		return fmt.Errorf("unsupported SSF delivery method %q", stream.Delivery.Method)
	}

	// [SSF 1.0 §8.1.2] Paused and disabled streams must not transmit events.
	if stream.Status != goidc.SSFStreamStatusEnabled {
		return nil
	}

	if event.Claims == nil {
		event.Claims = make(map[string]any)
	}

	set, err := signEvent(ctx, stream, event)
	if err != nil {
		return fmt.Errorf("could not sign the security event token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodPost, stream.Delivery.Endpoint, strings.NewReader(set))
	if err != nil {
		return fmt.Errorf("could not create the event push request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeSecurityEventJWT)
	req.Header.Set("Accept", "application/json")
	if stream.Delivery.AuthorizationHeader != "" {
		req.Header.Set("Authorization", stream.Delivery.AuthorizationHeader)
	}

	resp, err := ctx.SSFHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("could not send the event push request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// [RFC 8935 §2.2] A successful push delivery response must be 202 Accepted.
	if resp.StatusCode != http.StatusAccepted {
		var eventErr goidc.SSFEventError
		if resp.StatusCode == http.StatusBadRequest {
			_ = json.NewDecoder(io.LimitReader(resp.Body, maxPushErrorBodySize)).Decode(&eventErr)
		}
		return fmt.Errorf("sending the event push request returned status %d: %v", resp.StatusCode, eventErr)
	}

	// [RFC 8935 §2.2] A successful push delivery response body must be empty.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1))
	if err != nil {
		return fmt.Errorf("could not read the event push response body: %w", err)
	}
	if len(body) != 0 {
		return fmt.Errorf("event push response body must be empty")
	}

	return nil
}

// pollEvents returns pending security event tokens using SET poll delivery.
// See [RFC 8936].
func pollEvents(ctx oidc.Context, streamID string, req requestPollEvents) (responsePollEvents, error) {
	stream, _, err := authorizedStream(ctx, streamID)
	if err != nil {
		return responsePollEvents{}, err
	}

	if stream.Delivery.Method != goidc.SSFDeliveryMethodPoll {
		return responsePollEvents{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream is not configured for polling")
	}

	if req.MaxEvents != nil && *req.MaxEvents < 0 {
		return responsePollEvents{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "maxEvents cannot be negative")
	}

	if req.Acknowledgements != nil {
		if err := ctx.SSFAcknowledgeEvents(streamID, req.Acknowledgements, goidc.SSFAcknowledgementOptions{
			ReturnImmediately: req.ReturnImmediately,
		}); err != nil {
			return responsePollEvents{}, fmt.Errorf("could not acknowledge the polled security events: %w", err)
		}
	}

	if req.Errors != nil {
		errs := make([]goidc.SSFEventError, 0, len(req.Errors))
		for id, err := range req.Errors {
			err.ID = id
			errs = append(errs, err)
		}
		if err := ctx.SSFAcknowledgeErrors(streamID, errs, goidc.SSFAcknowledgementOptions{
			ReturnImmediately: req.ReturnImmediately,
		}); err != nil {
			return responsePollEvents{}, fmt.Errorf("could not acknowledge the polled security event errors: %w", err)
		}
	}

	// [SSF 1.0 §8.1.2] Paused and disabled streams must not transmit events.
	if stream.Status != goidc.SSFStreamStatusEnabled {
		return responsePollEvents{SecurityEventTokens: map[string]string{}, MoreAvailable: false}, nil
	}

	// [RFC 8936 §2.2] If maxEvents is 0, no events should be returned.
	if req.MaxEvents != nil && *req.MaxEvents == 0 {
		if ctx.SSFInactivityTimeoutSecs > 0 {
			stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
			if err := ctx.SSFSaveStream(stream); err != nil {
				return responsePollEvents{}, fmt.Errorf("could not save the event stream: %w", err)
			}
		}
		return responsePollEvents{SecurityEventTokens: make(map[string]string)}, nil
	}

	events, err := ctx.SSFPollEvents(streamID, goidc.SSFPollOptions{
		MaxEvents:         req.MaxEvents,
		ReturnImmediately: req.ReturnImmediately,
	})
	if err != nil {
		return responsePollEvents{}, fmt.Errorf("could not poll the pending security events: %w", err)
	}

	sets := make(map[string]string, len(events.Events))
	for _, event := range events.Events {
		set, err := signEvent(ctx, stream, event)
		if err != nil {
			return responsePollEvents{}, fmt.Errorf("could not sign the polled security event token: %w", err)
		}
		sets[event.ID] = set
	}

	if ctx.SSFInactivityTimeoutSecs > 0 {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFSaveStream(stream); err != nil {
			return responsePollEvents{}, fmt.Errorf("could not save the event stream: %w", err)
		}
	}

	return responsePollEvents{SecurityEventTokens: sets, MoreAvailable: events.MoreAvailable}, nil
}

func signEvent(ctx oidc.Context, stream *goidc.SSFStream, event goidc.SSFEvent) (string, error) {
	token := struct {
		Issuer      string                     `json:"iss"`
		JWTID       string                     `json:"jti"`
		Audience    goidc.Audiences            `json:"aud"`
		IssuedAt    int                        `json:"iat"`
		Transaction string                     `json:"txn,omitempty"`
		Subject     goidc.SSFSubject           `json:"sub_id"`
		Events      map[goidc.SSFEventType]any `json:"events"`
	}{
		Issuer:      ctx.SSFIssuer,
		JWTID:       event.ID,
		Audience:    stream.Audiences,
		IssuedAt:    event.IssuedAt,
		Transaction: event.Transaction,
		Subject:     event.Subject,
		Events:      map[goidc.SSFEventType]any{event.Type: event.Claims},
	}
	return ctx.SSFSign(token, (&jose.SignerOptions{}).WithType(jwtTypeSecurityEventJWT))
}
