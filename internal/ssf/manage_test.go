package ssf

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestCreateStream(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{
				ID:        "receiver_id",
				Audiences: []string{"receiver_audience"},
			}, nil
		}
		ctx.SSFEventStreamIDFunc = func(context.Context) string {
			return "stream_id"
		}
		ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{
			goidc.SSFDeliveryMethodPoll,
			goidc.SSFDeliveryMethodPush,
		}
		ctx.SSFEventTypes = []goidc.SSFEventType{
			goidc.SSFEventTypeCAEPSessionRevoked,
			goidc.SSFEventTypeCAEPCredentialChange,
		}
		ctx.SSFIssuer = "https://transmitter.example.com"
		ctx.SSFPollingEndpoint = "/poll"
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, request)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				if resp.ID != "stream_id" {
					t.Fatalf("stream ID = %q, want stream_id", resp.ID)
				}
				if resp.Issuer != "https://transmitter.example.com" {
					t.Fatalf("issuer = %q, want https://transmitter.example.com", resp.Issuer)
				}
				if len(resp.Audience) != 1 || resp.Audience[0] != "receiver_audience" {
					t.Fatalf("audience = %v, want [receiver_audience]", resp.Audience)
				}
				if resp.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("delivery method = %q, want %q", resp.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
				if resp.Delivery.Endpoint != "https://transmitter.example.com/poll/stream_id" {
					t.Fatalf("delivery endpoint = %q, want https://transmitter.example.com/poll/stream_id", resp.Delivery.Endpoint)
				}
				if len(resp.EventsSupported) != 2 {
					t.Fatalf("events supported = %v, want 2 event types", resp.EventsSupported)
				}
				if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeCAEPSessionRevoked)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPSessionRevoked)
				}

				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("created stream was not saved: %v", err)
				}
				if stream.Status != goidc.SSFStreamStatusEnabled {
					t.Fatalf("stream status = %q, want %q", stream.Status, goidc.SSFStreamStatusEnabled)
				}
				if stream.ReceiverID != "receiver_id" {
					t.Fatalf("stream receiver ID = %q, want receiver_id", stream.ReceiverID)
				}
				if len(stream.Audiences) != 1 || stream.Audiences[0] != "receiver_audience" {
					t.Fatalf("stream audiences = %v, want [receiver_audience]", stream.Audiences)
				}
				if len(stream.EventsSupported) != 2 {
					t.Fatalf("stream events supported = %v, want 2 event types", stream.EventsSupported)
				}
				if len(stream.EventsRequested) != 1 || stream.EventsRequested[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("stream events requested = %v, want [%s]", stream.EventsRequested, goidc.SSFEventTypeCAEPSessionRevoked)
				}
				if len(stream.EventsDelivered) != 1 || stream.EventsDelivered[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("stream events delivered = %v, want [%s]", stream.EventsDelivered, goidc.SSFEventTypeCAEPSessionRevoked)
				}
				if stream.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("stream delivery method = %q, want %q", stream.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
				if stream.CreatedAt == 0 {
					t.Fatal("stream created_at should be set")
				}
			},
		},
		{
			name: "defaults to poll delivery",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if resp.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("delivery method = %q, want %q", resp.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
			},
		},
		{
			name: "poll delivery endpoint includes endpoint prefix",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFEndpointPrefix = "/ssf"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if resp.Delivery.Endpoint != "https://transmitter.example.com/ssf/poll/stream_id" {
					t.Fatalf("delivery endpoint = %q, want https://transmitter.example.com/ssf/poll/stream_id", resp.Delivery.Endpoint)
				}
			},
		},
		{
			name: "invalid delivery method",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "delivery method is required when poll is not supported",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery requires endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPush,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery requires valid endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "://bad-url"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery requires https endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "http://receiver.example.com/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery requires endpoint host",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https:///events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery disallows endpoint userinfo",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://user:pass@receiver.example.com/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery disallows endpoint fragment",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://receiver.example.com/events#fragment"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery disallows localhost endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://localhost/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery disallows private IP endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://192.168.1.10/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "poll delivery disallows endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPoll,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "poll delivery disallows authorization header",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				authHeader := "Bearer token123"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPoll,
						AuthorizationHeader: &authHeader,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "push delivery disallows authorization header control characters",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://receiver.example.com/events"
				authHeader := "Bearer token\r\nX-Injected: value"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPush,
						Endpoint:            &endpoint,
						AuthorizationHeader: &authHeader,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "multiple streams not allowed",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFMultipleStreamsPerReceiverEnabled = false
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "existing_stream_id",
					ReceiverID: "receiver_id",
				}); err != nil {
					tb.Fatalf("could not save existing stream: %v", err)
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "multiple streams check is scoped to receiver",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFMultipleStreamsPerReceiverEnabled = false
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "other_receiver_stream_id",
					ReceiverID: "other_receiver_id",
				}); err != nil {
					tb.Fatalf("could not save existing stream: %v", err)
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if resp.ID != "stream_id" {
					t.Fatalf("stream ID = %q, want stream_id", resp.ID)
				}
			},
		},
		{
			name: "with description",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}
				description := "My stream description"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					Description: &description,
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if resp.Description != "My stream description" {
					t.Fatalf("description = %q, want %q", resp.Description, "My stream description")
				}
			},
		},
		{
			name: "description too long",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				description := strings.Repeat("a", maxDescriptionLength+1)
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Description:     &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "description disallows control characters",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				description := "description\ninjection"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Description:     &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "with authorization header",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://receiver.example.com/events"
				authHeader := "Bearer token123"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPush,
						Endpoint:            &endpoint,
						AuthorizationHeader: &authHeader,
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				if resp.ID == "" {
					t.Fatal("stream ID should not be empty")
				}
				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("created stream was not saved: %v", err)
				}
				if stream.Delivery.AuthorizationHeader != "Bearer token123" {
					t.Fatalf("authorization header = %q, want %q", stream.Delivery.AuthorizationHeader, "Bearer token123")
				}
			},
		},
		{
			name: "receiver ID is audience when receiver audiences are empty",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{ID: "receiver_id"}, nil
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.Audience) != 1 || resp.Audience[0] != "receiver_id" {
					t.Fatalf("audience = %v, want [receiver_id]", resp.Audience)
				}
			},
		},
		{
			name: "receiver event types override global supported events",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID:         "receiver_id",
						EventTypes: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
					}, nil
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{
						goidc.SSFEventTypeCAEPSessionRevoked,
						goidc.SSFEventTypeCAEPCredentialChange,
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsSupported) != 1 || resp.EventsSupported[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events supported = %v, want [%s]", resp.EventsSupported, goidc.SSFEventTypeCAEPCredentialChange)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPCredentialChange)
				}
			},
		},
		{
			name: "receiver unsupported event types are ignored",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID: "receiver_id",
						EventTypes: []goidc.SSFEventType{
							goidc.SSFEventTypeCAEPSessionRevoked,
							goidc.SSFEventTypeVerification,
						},
					}, nil
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{
						goidc.SSFEventTypeCAEPSessionRevoked,
						goidc.SSFEventTypeVerification,
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsSupported) != 1 || resp.EventsSupported[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events supported = %v, want [%s]", resp.EventsSupported, goidc.SSFEventTypeCAEPSessionRevoked)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPSessionRevoked)
				}
			},
		},
		{
			name: "delivered events are not duplicated",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID: "receiver_id",
						EventTypes: []goidc.SSFEventType{
							goidc.SSFEventTypeCAEPSessionRevoked,
							goidc.SSFEventTypeCAEPSessionRevoked,
							goidc.SSFEventTypeCAEPCredentialChange,
						},
					}, nil
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{
						goidc.SSFEventTypeCAEPSessionRevoked,
						goidc.SSFEventTypeCAEPSessionRevoked,
						goidc.SSFEventTypeCAEPCredentialChange,
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsDelivered) != 2 {
					t.Fatalf("events delivered = %v, want 2 unique event types", resp.EventsDelivered)
				}
				if resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events delivered[0] = %q, want %q", resp.EventsDelivered[0], goidc.SSFEventTypeCAEPSessionRevoked)
				}
				if resp.EventsDelivered[1] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events delivered[1] = %q, want %q", resp.EventsDelivered[1], goidc.SSFEventTypeCAEPCredentialChange)
				}
			},
		},
		{
			name: "receiver only unsupported event types does not fall back to global events",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID:         "receiver_id",
						EventTypes: []goidc.SSFEventType{goidc.SSFEventTypeVerification},
					}, nil
				}
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsSupported) != 0 {
					t.Fatalf("events supported = %v, want empty", resp.EventsSupported)
				}
				if len(resp.EventsDelivered) != 0 {
					t.Fatalf("events delivered = %v, want empty", resp.EventsDelivered)
				}
			},
		},
		{
			name: "unsupported requested events are requested but not delivered",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeVerification},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeVerification {
					t.Fatalf("events requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeVerification)
				}
				if len(resp.EventsDelivered) != 0 {
					t.Fatalf("events delivered = %v, want empty", resp.EventsDelivered)
				}
			},
		},
		{
			name: "push delivery returns and persists receiver endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush}
				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				if resp.Delivery.Endpoint != "https://receiver.example.com/events" {
					t.Fatalf("delivery endpoint = %q, want https://receiver.example.com/events", resp.Delivery.Endpoint)
				}
				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("created stream was not saved: %v", err)
				}
				if stream.Delivery.Endpoint != "https://receiver.example.com/events" {
					t.Fatalf("persisted endpoint = %q, want https://receiver.example.com/events", stream.Delivery.Endpoint)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx, req := tt.setup(t)

			// When.
			resp, err := createStream(ctx, req)

			// Then.
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errCode != "" {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) || oidcErr.Code != tt.errCode {
						t.Fatalf("got %v, want error code %s", err, tt.errCode)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, ctx, resp)
			}
		})
	}
}

func TestUpdateStream(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{
			goidc.SSFDeliveryMethodPoll,
			goidc.SSFDeliveryMethodPush,
		}
		ctx.SSFEventTypes = []goidc.SSFEventType{
			goidc.SSFEventTypeCAEPSessionRevoked,
			goidc.SSFEventTypeCAEPCredentialChange,
		}
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, request)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				stream := &goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/new-events"
				authHeader := "Bearer token123"
				description := "Updated stream"
				return ctx, request{
					ID:              stream.ID,
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPush,
						Endpoint:            &endpoint,
						AuthorizationHeader: &authHeader,
					},
					Description: &description,
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				if resp.Delivery.Method != goidc.SSFDeliveryMethodPush {
					t.Fatalf("delivery method = %q, want %q", resp.Delivery.Method, goidc.SSFDeliveryMethodPush)
				}
				if resp.Description != "Updated stream" {
					t.Fatalf("description = %q, want %q", resp.Description, "Updated stream")
				}
				if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeCAEPCredentialChange)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPCredentialChange)
				}

				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("updated stream was not saved: %v", err)
				}
				if stream.Delivery.AuthorizationHeader != "Bearer token123" {
					t.Fatalf("authorization header = %q, want %q", stream.Delivery.AuthorizationHeader, "Bearer token123")
				}
			},
		},
		{
			name: "invalid stream ID",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{ID: "nonexistent"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "description too long",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				description := strings.Repeat("a", maxDescriptionLength+1)
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Description:     &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "description disallows control characters",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				description := "description\ninjection"
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Description:     &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver cannot update stream",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "other_receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, request{ID: "stream_id"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "preserves stream metadata",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				stream := &goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusPaused,
					StatusReason:    "maintenance",
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					CreatedAt:  123,
					InactiveAt: 456,
					VerifiedAt: 789,
					Store:      map[string]any{"key": "value"},
				}
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID:              stream.ID,
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("updated stream was not saved: %v", err)
				}
				if stream.Status != goidc.SSFStreamStatusPaused {
					t.Fatalf("status = %q, want %q", stream.Status, goidc.SSFStreamStatusPaused)
				}
				if stream.StatusReason != "maintenance" {
					t.Fatalf("status reason = %q, want maintenance", stream.StatusReason)
				}
				if stream.CreatedAt != 123 {
					t.Fatalf("created_at = %d, want 123", stream.CreatedAt)
				}
				if stream.InactiveAt != 456 {
					t.Fatalf("inactive_at = %d, want 456", stream.InactiveAt)
				}
				if stream.VerifiedAt != 789 {
					t.Fatalf("verified_at = %d, want 789", stream.VerifiedAt)
				}
				if stream.Store["key"] != "value" {
					t.Fatalf("store key = %v, want value", stream.Store["key"])
				}
			},
		},
		{
			name: "defaults to poll delivery",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPush,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				if resp.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("delivery method = %q, want %q", resp.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("updated stream was not saved: %v", err)
				}
				if stream.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("persisted delivery method = %q, want %q", stream.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
			},
		},
		{
			name: "uses receiver ID as audience when receiver audiences are empty",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"old_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				if len(resp.Audience) != 1 || resp.Audience[0] != "receiver_id" {
					t.Fatalf("audience = %v, want [receiver_id]", resp.Audience)
				}
				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("updated stream was not saved: %v", err)
				}
				if len(stream.Audiences) != 1 || stream.Audiences[0] != "receiver_id" {
					t.Fatalf("persisted audiences = %v, want [receiver_id]", stream.Audiences)
				}
			},
		},
		{
			name: "replaces push delivery with poll and clears push fields",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPush,
						Endpoint:            "https://receiver.example.com/events",
						AuthorizationHeader: "Bearer old",
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("updated stream was not saved: %v", err)
				}
				if stream.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("delivery method = %q, want %q", stream.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
				if stream.Delivery.Endpoint != "" {
					t.Fatalf("delivery endpoint = %q, want empty", stream.Delivery.Endpoint)
				}
				if stream.Delivery.AuthorizationHeader != "" {
					t.Fatalf("authorization header = %q, want empty", stream.Delivery.AuthorizationHeader)
				}
			},
		},
		{
			name: "uses current receiver event types",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID:         "receiver_id",
						EventTypes: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
					}, nil
				}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID: "stream_id",
					EventsRequested: []goidc.SSFEventType{
						goidc.SSFEventTypeCAEPSessionRevoked,
						goidc.SSFEventTypeCAEPCredentialChange,
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsSupported) != 1 || resp.EventsSupported[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events supported = %v, want [%s]", resp.EventsSupported, goidc.SSFEventTypeCAEPCredentialChange)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPCredentialChange)
				}
			},
		},
		{
			name: "requested unsupported events are not delivered",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeVerification},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeVerification {
					t.Fatalf("events requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeVerification)
				}
				if len(resp.EventsDelivered) != 0 {
					t.Fatalf("events delivered = %v, want empty", resp.EventsDelivered)
				}
			},
		},
		{
			name: "rejects poll delivery with endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPoll,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "rejects push delivery without https endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "http://receiver.example.com/events"
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid update does not persist partial changes",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					Description: "original",
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/events"
				description := "changed"
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPoll,
						Endpoint: &endpoint,
					},
					Description: &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				t.Helper()

				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.Description != "original" {
					t.Fatalf("description = %q, want original", stream.Description)
				}
				if stream.Delivery.Endpoint != "" {
					t.Fatalf("delivery endpoint = %q, want empty", stream.Delivery.Endpoint)
				}
			},
		},
		{
			name: "invalid update does not refresh inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					InactiveAt: 1,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPoll,
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				t.Helper()

				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.InactiveAt != 1 {
					t.Fatalf("inactive_at = %d, want 1", stream.InactiveAt)
				}
			},
		},
		{
			name: "empty stream ID",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{ID: ""}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx, req := tt.setup(t)

			// When.
			resp, err := updateStream(ctx, req)

			// Then.
			if tt.wantErr || tt.errCode != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errCode != "" {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) || oidcErr.Code != tt.errCode {
						t.Fatalf("got %v, want error code %s", err, tt.errCode)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, ctx, resp)
			}
		})
	}
}

func TestPatchStream(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{
			goidc.SSFDeliveryMethodPoll,
			goidc.SSFDeliveryMethodPush,
		}
		ctx.SSFEventTypes = []goidc.SSFEventType{
			goidc.SSFEventTypeCAEPSessionRevoked,
			goidc.SSFEventTypeCAEPCredentialChange,
		}
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, request)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "description",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				description := "Patched description"
				return ctx, request{
					ID:          "stream_id",
					Description: &description,
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()
				if resp.Description != "Patched description" {
					t.Fatalf("description = %q, want %q", resp.Description, "Patched description")
				}
				if resp.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("delivery method = %q, want %q", resp.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
			},
		},
		{
			name: "invalid stream ID",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{ID: "nonexistent"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "description too long",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				description := strings.Repeat("a", maxDescriptionLength+1)
				return ctx, request{
					ID:          "stream_id",
					Description: &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "description disallows control characters",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				description := "description\ninjection"
				return ctx, request{
					ID:          "stream_id",
					Description: &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "empty stream ID",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				return ctx, request{ID: ""}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver cannot patch stream",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "other_receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				description := "patched"
				return ctx, request{ID: "stream_id", Description: &description}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "events requested",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()
				if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeCAEPCredentialChange)
				}
			},
		},
		{
			name: "preserves stream metadata",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusPaused,
					StatusReason:    "maintenance",
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					CreatedAt:  123,
					InactiveAt: 456,
					VerifiedAt: 789,
					Store:      map[string]any{"key": "value"},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				description := "patched"
				return ctx, request{
					ID:          "stream_id",
					Description: &description,
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("patched stream was not saved: %v", err)
				}
				if stream.Status != goidc.SSFStreamStatusPaused {
					t.Fatalf("status = %q, want %q", stream.Status, goidc.SSFStreamStatusPaused)
				}
				if stream.StatusReason != "maintenance" {
					t.Fatalf("status reason = %q, want maintenance", stream.StatusReason)
				}
				if stream.CreatedAt != 123 {
					t.Fatalf("created_at = %d, want 123", stream.CreatedAt)
				}
				if stream.InactiveAt != 456 {
					t.Fatalf("inactive_at = %d, want 456", stream.InactiveAt)
				}
				if stream.VerifiedAt != 789 {
					t.Fatalf("verified_at = %d, want 789", stream.VerifiedAt)
				}
				if stream.Store["key"] != "value" {
					t.Fatalf("store key = %v, want value", stream.Store["key"])
				}
			},
		},
		{
			name: "uses current receiver event types when requested events change",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID:         "receiver_id",
						EventTypes: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
					}, nil
				}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID: "stream_id",
					EventsRequested: []goidc.SSFEventType{
						goidc.SSFEventTypeCAEPSessionRevoked,
						goidc.SSFEventTypeCAEPCredentialChange,
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsSupported) != 1 || resp.EventsSupported[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events supported = %v, want [%s]", resp.EventsSupported, goidc.SSFEventTypeCAEPCredentialChange)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPCredentialChange {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPCredentialChange)
				}
			},
		},
		{
			name: "preserves supported events when requested events are not changed",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{
						ID:         "receiver_id",
						EventTypes: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
					}, nil
				}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				description := "patched"
				return ctx, request{
					ID:          "stream_id",
					Description: &description,
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsSupported) != 1 || resp.EventsSupported[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events supported = %v, want [%s]", resp.EventsSupported, goidc.SSFEventTypeCAEPSessionRevoked)
				}
				if len(resp.EventsDelivered) != 1 || resp.EventsDelivered[0] != goidc.SSFEventTypeCAEPSessionRevoked {
					t.Fatalf("events delivered = %v, want [%s]", resp.EventsDelivered, goidc.SSFEventTypeCAEPSessionRevoked)
				}
			},
		},
		{
			name: "requested unsupported events are not delivered",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID:              "stream_id",
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeVerification},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeVerification {
					t.Fatalf("events requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeVerification)
				}
				if len(resp.EventsDelivered) != 0 {
					t.Fatalf("events delivered = %v, want empty", resp.EventsDelivered)
				}
			},
		},
		{
			name: "delivery method",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:   goidc.SSFDeliveryMethodPush,
						Endpoint: &endpoint,
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()
				if resp.Delivery.Method != goidc.SSFDeliveryMethodPush {
					t.Fatalf("delivery method = %q, want %q", resp.Delivery.Method, goidc.SSFDeliveryMethodPush)
				}
			},
		},
		{
			name: "authorization header",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPush,
						Endpoint:            "https://receiver.example.com/events",
						AuthorizationHeader: "Bearer initial",
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				authHeader := "Bearer updated"
				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						AuthorizationHeader: &authHeader,
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()
				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("patched stream was not saved: %v", err)
				}
				if stream.Delivery.AuthorizationHeader != "Bearer updated" {
					t.Fatalf("authorization header = %q, want %q", stream.Delivery.AuthorizationHeader, "Bearer updated")
				}
			},
		},
		{
			name: "changes push delivery to poll when push fields are cleared",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPush,
						Endpoint:            "https://receiver.example.com/events",
						AuthorizationHeader: "Bearer token",
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := ""
				authHeader := ""
				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method:              goidc.SSFDeliveryMethodPoll,
						Endpoint:            &endpoint,
						AuthorizationHeader: &authHeader,
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				t.Helper()

				stream, err := ctx.SSFStream(resp.ID)
				if err != nil {
					t.Fatalf("patched stream was not saved: %v", err)
				}
				if stream.Delivery.Method != goidc.SSFDeliveryMethodPoll {
					t.Fatalf("delivery method = %q, want %q", stream.Delivery.Method, goidc.SSFDeliveryMethodPoll)
				}
				if stream.Delivery.Endpoint != "" {
					t.Fatalf("delivery endpoint = %q, want empty", stream.Delivery.Endpoint)
				}
				if stream.Delivery.AuthorizationHeader != "" {
					t.Fatalf("authorization header = %q, want empty", stream.Delivery.AuthorizationHeader)
				}
			},
		},
		{
			name: "rejects poll delivery with endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "rejects push delivery without endpoint",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPush,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid patch does not persist partial changes",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Audiences:       []string{"receiver_audience"},
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					Description: "original",
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/events"
				description := "changed"
				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Endpoint: &endpoint,
					},
					Description: &description,
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				t.Helper()

				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.Description != "original" {
					t.Fatalf("description = %q, want original", stream.Description)
				}
				if stream.Delivery.Endpoint != "" {
					t.Fatalf("delivery endpoint = %q, want empty", stream.Delivery.Endpoint)
				}
			},
		},
		{
			name: "invalid patch does not refresh inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, request) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:              "stream_id",
					ReceiverID:      "receiver_id",
					Status:          goidc.SSFStreamStatusEnabled,
					EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
					InactiveAt: 1,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}

				endpoint := "https://receiver.example.com/events"
				return ctx, request{
					ID: "stream_id",
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            *string                 `json:"endpoint_url,omitempty"`
						AuthorizationHeader *string                 `json:"authorization_header,omitempty"`
					}{
						Endpoint: &endpoint,
					},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				t.Helper()

				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.InactiveAt != 1 {
					t.Fatalf("inactive_at = %d, want 1", stream.InactiveAt)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, req := tt.setup(t)
			resp, err := patchStream(ctx, req)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errCode != "" {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) || oidcErr.Code != tt.errCode {
						t.Fatalf("got %v, want error code %s", err, tt.errCode)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, ctx, resp)
			}
		})
	}
}

func TestFetchStream(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, string)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Audiences:  []string{"receiver_audience"},
					Status:     goidc.SSFStreamStatusEnabled,
					Delivery: struct {
						Method              goidc.SSFDeliveryMethod `json:"method"`
						Endpoint            string                  `json:"endpoint,omitempty"`
						AuthorizationHeader string                  `json:"authorization_header,omitempty"`
					}{
						Method: goidc.SSFDeliveryMethodPoll,
					},
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, "stream_id"
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()
				if resp.ID != "stream_id" {
					t.Fatalf("stream ID = %q, want stream_id", resp.ID)
				}
			},
		},
		{
			name: "not found",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				return ctx, "nonexistent"
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong owner",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{ID: "different_receiver"}, nil
				}
				return ctx, "stream_id"
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "disabled stream does not refresh inactivity",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusDisabled,
					InactiveAt: 1,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				tb.Cleanup(func() {
					stream, err := ctx.SSFStream("stream_id")
					if err != nil {
						tb.Fatalf("could not load stream: %v", err)
					}
					if stream.InactiveAt != 1 {
						tb.Fatalf("inactive_at = %d, want 1", stream.InactiveAt)
					}
				})
				return ctx, "stream_id"
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				t.Helper()

				if resp.InactivityTimeout != 0 {
					t.Fatalf("inactivity timeout = %d, want 0", resp.InactivityTimeout)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, id := tt.setup(t)
			resp, err := fetchStream(ctx, id)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errCode != "" {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) || oidcErr.Code != tt.errCode {
						t.Fatalf("got %v, want error code %s", err, tt.errCode)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, ctx, resp)
			}
		})
	}
}

func TestFetchStreams(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) oidc.Context
		want     int
		wantErr  bool
		validate func(*testing.T, []response)
	}{
		{
			name: "streams",
			setup: func(tb testing.TB) oidc.Context {
				ctx := setup(tb)
				ctx.SSFMultipleStreamsPerReceiverEnabled = true
				for _, id := range []string{"stream_1", "stream_2"} {
					if err := ctx.SSFSaveStream(&goidc.SSFStream{
						ID:         id,
						ReceiverID: "receiver_id",
					}); err != nil {
						tb.Fatalf("could not save stream: %v", err)
					}
				}
				return ctx
			},
			want: 2,
		},
		{
			name: "only authenticated receiver streams",
			setup: func(tb testing.TB) oidc.Context {
				ctx := setup(tb)
				ctx.SSFMultipleStreamsPerReceiverEnabled = true
				for _, stream := range []*goidc.SSFStream{
					{ID: "stream_1", ReceiverID: "receiver_id"},
					{ID: "stream_2", ReceiverID: "receiver_id"},
					{ID: "other_stream", ReceiverID: "other_receiver_id"},
				} {
					if err := ctx.SSFSaveStream(stream); err != nil {
						tb.Fatalf("could not save stream: %v", err)
					}
				}
				return ctx
			},
			want: 2,
			validate: func(t *testing.T, streams []response) {
				t.Helper()

				for _, stream := range streams {
					if stream.ID == "other_stream" {
						t.Fatal("fetchStreams returned a stream for a different receiver")
					}
				}
			},
		},
		{
			name: "empty",
			setup: func(tb testing.TB) oidc.Context {
				return setup(tb)
			},
		},
		{
			name: "receiver error",
			setup: func(tb testing.TB) oidc.Context {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{}, errors.New("receiver failed")
				}
				return ctx
			},
			wantErr: true,
		},
		{
			name: "does not refresh inactivity",
			setup: func(tb testing.TB) oidc.Context {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					InactiveAt: 1,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				tb.Cleanup(func() {
					stream, err := ctx.SSFStream("stream_id")
					if err != nil {
						tb.Fatalf("could not load stream: %v", err)
					}
					if stream.InactiveAt != 1 {
						tb.Fatalf("inactive_at = %d, want 1", stream.InactiveAt)
					}
				})
				return ctx
			},
			want: 1,
		},
		{
			name: "expired inactive stream has no remaining inactivity timeout",
			setup: func(tb testing.TB) oidc.Context {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					InactiveAt: 1,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx
			},
			want: 1,
			validate: func(t *testing.T, streams []response) {
				t.Helper()

				if streams[0].InactivityTimeout != 0 {
					t.Fatalf("inactivity timeout = %d, want 0", streams[0].InactivityTimeout)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup(t)
			streams, err := fetchStreams(ctx)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(streams) != tt.want {
				t.Fatalf("got %d streams, want %d", len(streams), tt.want)
			}
			if tt.validate != nil {
				tt.validate(t, streams)
			}
		})
	}
}

func TestDeleteStream(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, string)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, string)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, "stream_id"
			},
		},
		{
			name: "not found",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				return ctx, "nonexistent"
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "empty stream ID",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				return ctx, ""
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "delete does not refresh inactivity",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					InactiveAt: 1,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				tb.Cleanup(func() {
					if _, err := ctx.SSFStream("stream_id"); !errors.Is(err, goidc.ErrNotFound) {
						tb.Fatalf("stream load error = %v, want ErrNotFound", err)
					}
				})
				return ctx, "stream_id"
			},
			validate: func(t *testing.T, ctx oidc.Context, id string) {
				t.Helper()

				if _, err := ctx.SSFStream(id); err == nil {
					t.Fatal("stream should be deleted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, id := tt.setup(t)
			err := deleteStream(ctx, id)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errCode != "" {
					var oidcErr goidc.Error
					if !errors.As(err, &oidcErr) || oidcErr.Code != tt.errCode {
						t.Fatalf("got %v, want error code %s", err, tt.errCode)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, ctx, id)
				return
			}
			if _, err = ctx.SSFStream(id); err == nil {
				t.Fatal("stream should be deleted")
			}
		})
	}
}
