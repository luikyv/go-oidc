package ssf

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const maxDescriptionLength = 1024

type request struct {
	ID              string               `json:"stream_id"`
	EventsRequested []goidc.SSFEventType `json:"events_requested"`
	Delivery        struct {
		Method              goidc.SSFDeliveryMethod `json:"method"`
		Endpoint            *string                 `json:"endpoint_url,omitempty"`
		AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
	} `json:"delivery"`
	Description *string `json:"description,omitempty"`
}

type response struct {
	ID              string               `json:"stream_id"`
	Issuer          string               `json:"iss"`
	Audience        goidc.Audiences      `json:"aud"`
	EventsSupported []goidc.SSFEventType `json:"events_supported"`
	EventsRequested []goidc.SSFEventType `json:"events_requested"`
	EventsDelivered []goidc.SSFEventType `json:"events_delivered"`
	Delivery        struct {
		Method   goidc.SSFDeliveryMethod `json:"method"`
		Endpoint string                  `json:"endpoint_url,omitempty"`
	} `json:"delivery"`
	MinVerificationInterval int    `json:"min_verification_interval,omitempty"`
	Description             string `json:"description,omitempty"`
	InactivityTimeout       int    `json:"inactivity_timeout,omitempty"`
}

func newResponse(ctx oidc.Context, stream *goidc.SSFStream) response {
	return response{
		ID:              stream.ID,
		Issuer:          ctx.SSFIssuer,
		Audience:        stream.Audiences,
		EventsSupported: stream.EventsSupported,
		EventsRequested: stream.EventsRequested,
		EventsDelivered: stream.EventsDelivered,
		Delivery: struct {
			Method   goidc.SSFDeliveryMethod `json:"method"`
			Endpoint string                  `json:"endpoint_url,omitempty"`
		}{
			Method: stream.Delivery.Method,
			Endpoint: func() string {
				if stream.Delivery.Method == goidc.SSFDeliveryMethodPoll {
					return ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFPollingEndpoint + "/" + stream.ID
				}
				return stream.Delivery.Endpoint
			}(),
		},
		Description:             stream.Description,
		MinVerificationInterval: ctx.SSFVerificationMinInterval,
		InactivityTimeout: func() int {
			if ctx.SSFInactivityTimeoutSecs == 0 {
				return 0
			}
			timeout := stream.InactiveAt - timeutil.TimestampNow()
			if timeout < 0 {
				return 0
			}
			return timeout
		}(),
	}
}

// createStream handles receiver-requested stream creation.
// See [SSF 1.0 §8.1.1.1].
func createStream(ctx oidc.Context, req request) (response, error) {
	receiver, err := receiver(ctx)
	if err != nil {
		return response{}, err
	}

	if !ctx.SSFMultipleStreamsPerReceiverEnabled {
		streams, err := ctx.SSFStreams(receiver.ID)
		if err != nil {
			return response{}, fmt.Errorf("could not load event streams for receiver %s: %w", receiver.ID, err)
		}
		if len(streams) > 0 {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "multiple streams per receiver are not allowed").WithStatusCode(http.StatusConflict)
		}
	}

	stream := &goidc.SSFStream{
		ID:              ctx.SSFEventStreamID(),
		ReceiverID:      receiver.ID,
		Status:          goidc.SSFStreamStatusEnabled,
		EventsSupported: receiver.EventTypes,
		EventsRequested: req.EventsRequested,
		EventsDelivered: eventTypeIntersection(receiver.EventTypes, req.EventsRequested),
		CreatedAt:       timeutil.TimestampNow(),
	}

	if len(receiver.Audiences) > 0 {
		stream.Audiences = receiver.Audiences
	} else {
		stream.Audiences = []string{receiver.ID}
	}

	stream.Delivery.Method = req.Delivery.Method
	// [SSF 1.0 §8.1.1.1] Default to poll delivery when unspecified.
	if slices.Contains(ctx.SSFDeliveryMethods, goidc.SSFDeliveryMethodPoll) && stream.Delivery.Method == "" {
		stream.Delivery.Method = goidc.SSFDeliveryMethodPoll
	}

	if req.Delivery.Endpoint != nil {
		stream.Delivery.Endpoint = *req.Delivery.Endpoint
	}

	if req.Delivery.AuthorizationHeader != nil {
		stream.Delivery.AuthorizationHeader = *req.Delivery.AuthorizationHeader
	}

	if req.Description != nil {
		stream.Description = *req.Description
	}

	if ctx.SSFInactivityTimeoutSecs > 0 {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
	}

	if err := validateStream(ctx, stream); err != nil {
		return response{}, fmt.Errorf("event stream not valid: %w", err)
	}

	if err := ctx.SSFSaveStream(stream); err != nil {
		return response{}, fmt.Errorf("could not create the event stream: %w", err)
	}

	return newResponse(ctx, stream), nil
}

// updateStream handles receiver-requested stream configuration replacement.
// See [SSF 1.0 §8.1.1.4].
func updateStream(ctx oidc.Context, req request) (response, error) {
	stream, r, err := authorizedStream(ctx, req.ID)
	if err != nil {
		return response{}, err
	}

	stream.Audiences = r.Audiences
	if len(stream.Audiences) == 0 {
		stream.Audiences = []string{r.ID}
	}
	stream.EventsSupported = r.EventTypes
	stream.EventsRequested = req.EventsRequested
	stream.EventsDelivered = eventTypeIntersection(r.EventTypes, req.EventsRequested)
	stream.Delivery.Method = req.Delivery.Method
	// [SSF 1.0 §8.1.1.1] Default to poll delivery when unspecified.
	if slices.Contains(ctx.SSFDeliveryMethods, goidc.SSFDeliveryMethodPoll) && stream.Delivery.Method == "" {
		stream.Delivery.Method = goidc.SSFDeliveryMethodPoll
	}

	if req.Delivery.Endpoint != nil {
		stream.Delivery.Endpoint = *req.Delivery.Endpoint
	} else {
		stream.Delivery.Endpoint = ""
	}

	if req.Delivery.AuthorizationHeader != nil {
		stream.Delivery.AuthorizationHeader = *req.Delivery.AuthorizationHeader
	} else {
		stream.Delivery.AuthorizationHeader = ""
	}

	if req.Description != nil {
		stream.Description = *req.Description
	} else {
		stream.Description = ""
	}

	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
	}

	if err := validateStream(ctx, stream); err != nil {
		return response{}, fmt.Errorf("event stream not valid: %w", err)
	}

	if err := ctx.SSFSaveStream(stream); err != nil {
		return response{}, fmt.Errorf("could not update the event stream: %w", err)
	}

	return newResponse(ctx, stream), nil
}

// patchStream handles receiver-requested stream configuration updates.
// See [SSF 1.0 §8.1.1.3].
// TODO: Validate transmitter-supplied config if sent.
// Transmitter-Supplied properties besides the stream_id MAY be present, but they MUST match the expected value. Missing Transmitter-Supplied properties MUST be ignored by the Transmitter. The events_delivered property, if present, MUST match the Transmitter's expected value before any updates are applied.
func patchStream(ctx oidc.Context, req request) (response, error) {
	stream, r, err := authorizedStream(ctx, req.ID)
	if err != nil {
		return response{}, err
	}

	if req.EventsRequested != nil {
		stream.EventsSupported = r.EventTypes
		stream.EventsRequested = req.EventsRequested
		stream.EventsDelivered = eventTypeIntersection(r.EventTypes, req.EventsRequested)
	}
	if req.Delivery.Method != "" {
		stream.Delivery.Method = req.Delivery.Method
	}
	if req.Delivery.Endpoint != nil {
		stream.Delivery.Endpoint = *req.Delivery.Endpoint
	}
	if req.Delivery.AuthorizationHeader != nil {
		stream.Delivery.AuthorizationHeader = *req.Delivery.AuthorizationHeader
	}
	if req.Description != nil {
		stream.Description = *req.Description
	}
	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
	}
	if err := validateStream(ctx, stream); err != nil {
		return response{}, fmt.Errorf("event stream not valid: %w", err)
	}

	if err := ctx.SSFSaveStream(stream); err != nil {
		return response{}, fmt.Errorf("could not update the event stream: %w", err)
	}

	return newResponse(ctx, stream), nil
}

func fetchStream(ctx oidc.Context, id string) (response, error) {
	stream, _, err := authorizedStream(ctx, id)
	if err != nil {
		return response{}, err
	}

	if ctx.SSFInactivityTimeoutSecs > 0 && stream.Status == goidc.SSFStreamStatusEnabled {
		stream.InactiveAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFSaveStream(stream); err != nil {
			return response{}, fmt.Errorf("could not save stream: %w", err)
		}
	}

	return newResponse(ctx, stream), nil
}

func fetchStreams(ctx oidc.Context) ([]response, error) {
	receiver, err := ctx.SSFReceiver()
	if err != nil {
		return []response{}, err
	}

	streams, err := ctx.SSFStreams(receiver.ID)
	if err != nil {
		return []response{}, fmt.Errorf("could not load the event streams for receiver %q: %w", receiver.ID, err)
	}

	responses := make([]response, 0, len(streams))
	for _, stream := range streams {
		responses = append(responses, newResponse(ctx, stream))
	}
	return responses, nil
}

func deleteStream(ctx oidc.Context, id string) error {
	if _, _, err := authorizedStream(ctx, id); err != nil {
		return err
	}

	if err := ctx.SSFDeleteStream(id); err != nil {
		return fmt.Errorf("could not delete the event stream: %w", err)
	}

	return nil
}

func validateStream(ctx oidc.Context, stream *goidc.SSFStream) error {
	if stream.Delivery.Method == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery method is required")
	}

	if !slices.Contains(ctx.SSFDeliveryMethods, stream.Delivery.Method) {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "delivery method %q is not supported", stream.Delivery.Method)
	}

	if endpoint := stream.Delivery.Endpoint; stream.Delivery.Method == goidc.SSFDeliveryMethodPush {
		if endpoint == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url is required for push delivery")
		}

		u, err := url.Parse(endpoint)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url is invalid", err)
		}

		if u.Scheme != "https" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url must use https")
		}
		if u.Host == "" || u.Hostname() == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url host is required")
		}
		if u.User != nil {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url userinfo is not allowed")
		}
		if u.Fragment != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url fragment is not allowed")
		}

		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url localhost host is not allowed")
		}

		if ip, err := netip.ParseAddr(host); err == nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url private host is not allowed")
			}
		}

		for _, r := range stream.Delivery.AuthorizationHeader {
			if r < 0x20 || r == 0x7f {
				return goidc.NewError(goidc.ErrorCodeInvalidRequest, "authorization_header cannot contain control characters")
			}
		}
	}

	if stream.Delivery.Method == goidc.SSFDeliveryMethodPoll {
		if stream.Delivery.Endpoint != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "delivery endpoint_url is not allowed for poll delivery")
		}

		if stream.Delivery.AuthorizationHeader != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "authorization_header is not allowed for poll delivery")
		}
	}

	if len(stream.Description) > maxDescriptionLength {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "description is too long")
	}

	for _, r := range stream.Description {
		if r < 0x20 && r != '\t' {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "description cannot contain control characters")
		}
	}

	return nil
}

func eventTypeIntersection(a, b []goidc.SSFEventType) []goidc.SSFEventType {
	inB := make(map[goidc.SSFEventType]struct{}, len(b))
	for _, event := range b {
		inB[event] = struct{}{}
	}

	seen := make(map[goidc.SSFEventType]struct{}, min(len(a), len(b)))
	result := make([]goidc.SSFEventType, 0, min(len(a), len(b)))
	for _, event := range a {
		if _, ok := inB[event]; !ok {
			continue
		}
		if _, ok := seen[event]; ok {
			continue
		}
		seen[event] = struct{}{}
		result = append(result, event)
	}

	return result
}
