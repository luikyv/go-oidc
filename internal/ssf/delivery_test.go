package ssf

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type deliveryRoundTripFunc func(*http.Request) (*http.Response, error)

func (f deliveryRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPushEvent(t *testing.T) {
	const receiverID = "delivery_receiver_id"

	testCases := []struct {
		name         string
		streamMethod goidc.SSFDeliveryMethod
		eventType    goidc.SSFEventType
		setup        func(oidc.Context, *goidc.SSFStream) string
		statusCode   int
		responseBody string
		transportErr error
		errContains  []string
		wantErr      bool
		wantRequests int
	}{
		{
			name:         "pushes subscribed event",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			wantRequests: 1,
		},
		{
			name:         "rejects unsupported poll stream",
			streamMethod: goidc.SSFDeliveryMethodPoll,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			wantErr:      true,
		},
		{
			name:         "rejects unsupported delivery method",
			streamMethod: goidc.SSFDeliveryMethodPoll,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			setup: func(ctx oidc.Context, stream *goidc.SSFStream) string {
				stream.Delivery.Method = "unsupported"
				if err := ctx.SSFSaveStream(stream); err != nil {
					t.Fatalf("could not save stream: %v", err)
				}
				return stream.ID
			},
			wantErr: true,
		},
		{
			name:         "rejects unsubscribed event type",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeStreamUpdated,
			wantErr:      true,
		},
		{
			name:         "ignores disabled stream",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			setup: func(ctx oidc.Context, stream *goidc.SSFStream) string {
				_, _ = updateStreamStatus(ctx, requestStatus{
					ID:     stream.ID,
					Status: goidc.SSFStreamStatusDisabled,
				})
				return stream.ID
			},
		},
		{
			name:         "allows verification event",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeVerification,
			wantRequests: 1,
		},
		{
			name:         "rejects non-accepted response",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			statusCode:   http.StatusOK,
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "rejects successful response with body",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			responseBody: "{}",
			wantErr:      true,
			errContains:  []string{"response body must be empty"},
			wantRequests: 1,
		},
		{
			name:         "returns transport error",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			transportErr: errors.New("network failed"),
			wantErr:      true,
			errContains:  []string{"could not send the event push request", "network failed"},
			wantRequests: 1,
		},
		{
			name:         "parses bad request error response",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			statusCode:   http.StatusBadRequest,
			responseBody: `{"err":"invalid_key","description":"bad key"}`,
			wantErr:      true,
			errContains:  []string{"status 400", "invalid_key", "bad key"},
			wantRequests: 1,
		},
		{
			name:         "returns error for missing stream",
			streamMethod: goidc.SSFDeliveryMethodPush,
			eventType:    goidc.SSFEventTypeCAEPSessionRevoked,
			setup: func(ctx oidc.Context, stream *goidc.SSFStream) string {
				return "nonexistent"
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager := storage.NewManager(100)
			ctx := oidctest.NewContext(t)
			ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
				return goidc.SSFReceiver{ID: receiverID}, nil
			}
			ctx.SSFStreamManager = manager
			ctx.SSFStatusHandleFunc = func(context.Context, *goidc.SSFStream, goidc.SSFStatusOptions) error {
				return nil
			}
			ctx.SSFEventTypes = []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange}
			ctx.SSFVerificationEnabled = true
			ctx.SSFJWKSFunc = ctx.JWKSFunc
			ctx.SSFDefaultSigAlg = goidc.PS256
			ctx.SSFIssuer = ctx.Issuer()

			requests := 0
			ctx.SSFHTTPClientFunc = func(context.Context) *http.Client {
				return &http.Client{
					Transport: deliveryRoundTripFunc(func(req *http.Request) (*http.Response, error) {
						requests++
						if req.Header.Get("Content-Type") != contentTypeSecurityEventJWT {
							t.Errorf("Content-Type = %q, want %q", req.Header.Get("Content-Type"), contentTypeSecurityEventJWT)
						}
						if req.Header.Get("Accept") != "application/json" {
							t.Errorf("Accept = %q, want application/json", req.Header.Get("Accept"))
						}
						body, err := io.ReadAll(req.Body)
						if err != nil {
							t.Fatalf("could not read push request body: %v", err)
						}
						if len(body) == 0 {
							t.Error("push request body cannot be empty")
						}
						if tc.transportErr != nil {
							return nil, tc.transportErr
						}
						statusCode := tc.statusCode
						if statusCode == 0 {
							statusCode = http.StatusAccepted
						}
						return &http.Response{
							StatusCode: statusCode,
							Body:       io.NopCloser(strings.NewReader(tc.responseBody)),
							Header:     make(http.Header),
						}, nil
					}),
				}
			}

			stream := &goidc.SSFStream{
				ID:              "stream_id",
				ReceiverID:      receiverID,
				Audiences:       []string{receiverID},
				Status:          goidc.SSFStreamStatusEnabled,
				EventsSupported: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				EventsDelivered: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
				Delivery: struct {
					Method              goidc.SSFDeliveryMethod `json:"method"`
					Endpoint            string                  `json:"endpoint,omitempty"`
					AuthorizationHeader string                  `json:"authorization_header,omitempty"`
				}{
					Method: tc.streamMethod,
				},
			}
			if tc.streamMethod == goidc.SSFDeliveryMethodPush {
				stream.Delivery.Endpoint = "https://receiver.example.com/events"
				stream.Delivery.AuthorizationHeader = "Bearer receiver-token"
			}
			if err := ctx.SSFSaveStream(stream); err != nil {
				t.Fatalf("could not save stream: %v", err)
			}

			streamID := stream.ID
			if tc.setup != nil {
				streamID = tc.setup(ctx, stream)
			}

			err := PushEvent(ctx, streamID, goidc.SSFEvent{
				Type:    tc.eventType,
				Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("PushEvent() error = %v, wantErr %v", err, tc.wantErr)
			}
			for _, want := range tc.errContains {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("PushEvent() error = %v, want containing %q", err, want)
				}
			}
			if requests != tc.wantRequests {
				t.Fatalf("push requests = %d, want %d", requests, tc.wantRequests)
			}
		})
	}
}

func TestSignEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    goidc.SSFEvent
		validate func(*testing.T, map[string]any)
	}{
		{
			name: "required claims",
			event: goidc.SSFEvent{
				ID:       "event_id",
				Type:     goidc.SSFEventTypeCAEPSessionRevoked,
				Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				Claims:   map[string]any{goidc.SSFClaimReasonAdmin: "policy"},
				IssuedAt: 123,
			},
			validate: func(t *testing.T, claims map[string]any) {
				t.Helper()

				if claims["iss"] != "https://transmitter.example.com" {
					t.Fatalf("iss = %v, want https://transmitter.example.com", claims["iss"])
				}
				if claims["jti"] != "event_id" {
					t.Fatalf("jti = %v, want event_id", claims["jti"])
				}
				if claims["aud"] != "receiver_id" {
					t.Fatalf("aud = %v, want receiver_id", claims["aud"])
				}
				if claims["iat"] != float64(123) {
					t.Fatalf("iat = %v, want 123", claims["iat"])
				}
				subject, ok := claims["sub_id"].(map[string]any)
				if !ok {
					t.Fatalf("sub_id = %T, want object", claims["sub_id"])
				}
				if subject["format"] != string(goidc.SSFSubjectFormatEmail) {
					t.Fatalf("sub_id.format = %v, want email", subject["format"])
				}
				if subject["email"] != "user@example.com" {
					t.Fatalf("sub_id.email = %v, want user@example.com", subject["email"])
				}
				if _, ok := claims["txn"]; ok {
					t.Fatal("txn should be omitted")
				}
				events, ok := claims["events"].(map[string]any)
				if !ok {
					t.Fatalf("events = %T, want object", claims["events"])
				}
				eventClaims, ok := events[string(goidc.SSFEventTypeCAEPSessionRevoked)].(map[string]any)
				if !ok {
					t.Fatalf("session revoked event claims = %T, want object", events[string(goidc.SSFEventTypeCAEPSessionRevoked)])
				}
				if eventClaims[goidc.SSFClaimReasonAdmin] != "policy" {
					t.Fatalf("reason_admin = %v, want policy", eventClaims[goidc.SSFClaimReasonAdmin])
				}
			},
		},
		{
			name: "transaction claim",
			event: goidc.SSFEvent{
				ID:          "event_id",
				Type:        goidc.SSFEventTypeCAEPCredentialChange,
				Subject:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "subject_id"},
				Transaction: "transaction_id",
				Claims:      map[string]any{goidc.SSFClaimCredentialType: goidc.SSFCredentialTypePassword},
				IssuedAt:    456,
			},
			validate: func(t *testing.T, claims map[string]any) {
				t.Helper()

				if claims["txn"] != "transaction_id" {
					t.Fatalf("txn = %v, want transaction_id", claims["txn"])
				}
				if claims["iat"] != float64(456) {
					t.Fatalf("iat = %v, want 456", claims["iat"])
				}
				events, ok := claims["events"].(map[string]any)
				if !ok {
					t.Fatalf("events = %T, want object", claims["events"])
				}
				eventClaims, ok := events[string(goidc.SSFEventTypeCAEPCredentialChange)].(map[string]any)
				if !ok {
					t.Fatalf("credential change event claims = %T, want object", events[string(goidc.SSFEventTypeCAEPCredentialChange)])
				}
				if eventClaims[goidc.SSFClaimCredentialType] != string(goidc.SSFCredentialTypePassword) {
					t.Fatalf("credential_type = %v, want password", eventClaims[goidc.SSFClaimCredentialType])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx := oidctest.NewContext(t)
			ctx.SSFJWKSFunc = ctx.JWKSFunc
			ctx.SSFDefaultSigAlg = goidc.PS256
			ctx.SSFIssuer = "https://transmitter.example.com"
			stream := &goidc.SSFStream{
				Audiences: []string{"receiver_id"},
			}

			// When.
			set, err := signEvent(ctx, stream, tt.event)

			// Then.
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			claims, err := oidctest.UnsafeClaims(set, goidc.PS256)
			if err != nil {
				t.Fatalf("could not parse SET claims: %v", err)
			}
			tt.validate(t, claims)
		})
	}
}

func TestPollEvents(t *testing.T) {
	const receiverID = "delivery_receiver_id"

	tests := []struct {
		name     string
		setup    func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, string, responsePollEvents)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				if err := manager.SaveEvent(ctx, stream.ID, goidc.SSFEvent{
					ID:       "event_id",
					Type:     goidc.SSFEventTypeCAEPSessionRevoked,
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
					IssuedAt: timeutil.TimestampNow(),
				}); err != nil {
					tb.Fatalf("could not save event: %v", err)
				}
				return stream.ID, requestPollEvents{}
			},
			validate: func(t *testing.T, _ oidc.Context, _ string, resp responsePollEvents) {
				t.Helper()

				if len(resp.SecurityEventTokens) != 1 {
					t.Fatalf("sets = %d, want 1", len(resp.SecurityEventTokens))
				}
				set := resp.SecurityEventTokens["event_id"]
				if set == "" {
					t.Fatal("set for event_id should not be empty")
				}
				claims, err := oidctest.UnsafeClaims(set, goidc.PS256)
				if err != nil {
					t.Fatalf("could not parse SET claims: %v", err)
				}
				if claims["jti"] != "event_id" {
					t.Fatalf("jti = %v, want event_id", claims["jti"])
				}
				if resp.MoreAvailable {
					t.Fatal("more_available should be false")
				}
			},
		},
		{
			name: "max events limits response",
			setup: func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				for _, id := range []string{"event_1", "event_2"} {
					if err := manager.SaveEvent(ctx, stream.ID, goidc.SSFEvent{
						ID:       id,
						Type:     goidc.SSFEventTypeCAEPSessionRevoked,
						Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
						IssuedAt: timeutil.TimestampNow(),
					}); err != nil {
						tb.Fatalf("could not save event: %v", err)
					}
				}
				maxEvents := 1
				return stream.ID, requestPollEvents{MaxEvents: &maxEvents}
			},
			validate: func(t *testing.T, _ oidc.Context, _ string, resp responsePollEvents) {
				t.Helper()

				if len(resp.SecurityEventTokens) != 1 {
					t.Fatalf("sets = %d, want 1", len(resp.SecurityEventTokens))
				}
				if !resp.MoreAvailable {
					t.Fatal("more_available should be true")
				}
			},
		},
		{
			name: "max events zero returns no events",
			setup: func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				stream.InactiveAt = 1
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				if err := manager.SaveEvent(ctx, stream.ID, goidc.SSFEvent{
					ID:       "event_id",
					Type:     goidc.SSFEventTypeCAEPSessionRevoked,
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
					IssuedAt: timeutil.TimestampNow(),
				}); err != nil {
					tb.Fatalf("could not save event: %v", err)
				}
				maxEvents := 0
				return stream.ID, requestPollEvents{MaxEvents: &maxEvents}
			},
			validate: func(t *testing.T, _ oidc.Context, _ string, resp responsePollEvents) {
				t.Helper()

				if len(resp.SecurityEventTokens) != 0 {
					t.Fatalf("sets = %d, want 0", len(resp.SecurityEventTokens))
				}
			},
		},
		{
			name: "negative max events",
			setup: func(_ testing.TB, _ oidc.Context, _ *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				maxEvents := -1
				return stream.ID, requestPollEvents{MaxEvents: &maxEvents}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "acknowledges events before polling",
			setup: func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				for _, id := range []string{"event_1", "event_2"} {
					if err := manager.SaveEvent(ctx, stream.ID, goidc.SSFEvent{
						ID:       id,
						Type:     goidc.SSFEventTypeCAEPSessionRevoked,
						Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
						IssuedAt: timeutil.TimestampNow(),
					}); err != nil {
						tb.Fatalf("could not save event: %v", err)
					}
				}
				return stream.ID, requestPollEvents{Acknowledgements: []string{"event_1"}}
			},
			validate: func(t *testing.T, _ oidc.Context, _ string, resp responsePollEvents) {
				t.Helper()

				if len(resp.SecurityEventTokens) != 1 {
					t.Fatalf("sets = %d, want 1", len(resp.SecurityEventTokens))
				}
				if _, ok := resp.SecurityEventTokens["event_1"]; ok {
					t.Fatal("acknowledged event should not be returned")
				}
				if resp.SecurityEventTokens["event_2"] == "" {
					t.Fatal("event_2 should be returned")
				}
			},
		},
		{
			name: "acknowledges event errors before polling",
			setup: func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				for _, id := range []string{"event_1", "event_2", "event_3"} {
					if err := manager.SaveEvent(ctx, stream.ID, goidc.SSFEvent{
						ID:       id,
						Type:     goidc.SSFEventTypeCAEPSessionRevoked,
						Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
						IssuedAt: timeutil.TimestampNow(),
					}); err != nil {
						tb.Fatalf("could not save event: %v", err)
					}
				}
				return stream.ID, requestPollEvents{
					Errors: map[string]goidc.SSFEventError{
						"event_1": {Error: goidc.SSFEventErrorCodeInvalidRequest, Description: "bad event"},
					},
				}
			},
			validate: func(t *testing.T, _ oidc.Context, _ string, resp responsePollEvents) {
				t.Helper()

				if len(resp.SecurityEventTokens) != 2 {
					t.Fatalf("sets = %d, want 2", len(resp.SecurityEventTokens))
				}
				if _, ok := resp.SecurityEventTokens["event_1"]; ok {
					t.Fatal("errored event should not be returned")
				}
			},
		},
		{
			name: "disabled stream returns no events",
			setup: func(tb testing.TB, ctx oidc.Context, manager *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				stream.Status = goidc.SSFStreamStatusDisabled
				stream.InactiveAt = 1
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				if err := manager.SaveEvent(ctx, stream.ID, goidc.SSFEvent{
					ID:       "event_id",
					Type:     goidc.SSFEventTypeCAEPSessionRevoked,
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
					IssuedAt: timeutil.TimestampNow(),
				}); err != nil {
					tb.Fatalf("could not save event: %v", err)
				}
				return stream.ID, requestPollEvents{}
			},
			validate: func(t *testing.T, ctx oidc.Context, streamID string, resp responsePollEvents) {
				t.Helper()

				if len(resp.SecurityEventTokens) != 0 {
					t.Fatalf("sets = %d, want 0", len(resp.SecurityEventTokens))
				}
				if resp.MoreAvailable {
					t.Fatal("more_available should be false")
				}
				stream, err := ctx.SSFStream(streamID)
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.InactiveAt != 1 {
					t.Fatalf("inactive_at = %d, want 1", stream.InactiveAt)
				}
			},
		},
		{
			name: "push stream is rejected",
			setup: func(tb testing.TB, ctx oidc.Context, _ *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				stream.Delivery.Method = goidc.SSFDeliveryMethodPush
				stream.Delivery.Endpoint = "https://receiver.example.com/events"
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return stream.ID, requestPollEvents{}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "stream not found",
			setup: func(testing.TB, oidc.Context, *storage.Manager, *goidc.SSFStream) (string, requestPollEvents) {
				return "missing", requestPollEvents{}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver",
			setup: func(tb testing.TB, ctx oidc.Context, _ *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				stream.ReceiverID = "other_receiver_id"
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return stream.ID, requestPollEvents{}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "receiver error",
			setup: func(_ testing.TB, ctx oidc.Context, _ *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{}, errors.New("receiver failed")
				}
				return stream.ID, requestPollEvents{}
			},
			wantErr: true,
		},
		{
			name: "refreshes inactivity deadline",
			setup: func(tb testing.TB, ctx oidc.Context, _ *storage.Manager, stream *goidc.SSFStream) (string, requestPollEvents) {
				ctx.SSFInactivityTimeoutSecs = 3600
				stream.InactiveAt = 1
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return stream.ID, requestPollEvents{}
			},
			validate: func(t *testing.T, ctx oidc.Context, streamID string, _ responsePollEvents) {
				t.Helper()

				stream, err := ctx.SSFStream(streamID)
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.InactiveAt <= timeutil.TimestampNow() {
					t.Fatalf("inactive_at = %d, want future timestamp", stream.InactiveAt)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			manager := storage.NewManager(100)
			ctx := oidctest.NewContext(t)
			ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
				return goidc.SSFReceiver{ID: receiverID}, nil
			}
			ctx.SSFStreamManager = manager
			ctx.SSFEventPollManager = manager
			ctx.SSFEventTypes = []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange}
			ctx.SSFJWKSFunc = ctx.JWKSFunc
			ctx.SSFDefaultSigAlg = goidc.PS256
			ctx.SSFIssuer = ctx.Issuer()

			stream := &goidc.SSFStream{
				ID:              "stream_id",
				ReceiverID:      receiverID,
				Audiences:       []string{receiverID},
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
			}
			if err := ctx.SSFSaveStream(stream); err != nil {
				t.Fatalf("could not save stream: %v", err)
			}
			streamID, req := tt.setup(t, ctx, manager, stream)

			// When.
			resp, err := pollEvents(ctx, streamID, req)

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
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, ctx, streamID, resp)
			}
		})
	}
}
