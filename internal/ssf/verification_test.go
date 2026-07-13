package ssf

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestScheduleVerificationEvent(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		manager := oidctest.Manager(tb, ctx)
		ctx.SSFStreamManager = manager
		ctx.SSFEventPollManager = manager
		ctx.SSFVerificationManager = manager
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		ctx.SSFEventIDFunc = func(context.Context) string {
			return "ssf_event_id"
		}
		return ctx
	}

	waitForPollEvent := func(t testing.TB, ctx oidc.Context, streamID string) goidc.SSFEvent {
		t.Helper()

		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			events, err := ctx.SSFPollEvents(streamID, goidc.SSFPollOptions{})
			if err != nil {
				t.Fatalf("error polling events: %v", err)
			}
			if len(events.Events) > 0 {
				return events.Events[0]
			}
			time.Sleep(10 * time.Millisecond)
		}

		t.Fatal("timed out waiting for poll event")
		return goidc.SSFEvent{}
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, requestVerificationEvent)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
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
				return ctx, requestVerificationEvent{
					StreamID: "stream_id",
					State:    "test_state",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				t.Helper()

				event := waitForPollEvent(t, ctx, "stream_id")
				if event.ID != "ssf_event_id" {
					t.Fatalf("event ID = %q, want ssf_event_id", event.ID)
				}
				if event.Type != goidc.SSFEventTypeVerification {
					t.Fatalf("event type = %q, want %q", event.Type, goidc.SSFEventTypeVerification)
				}
				if event.Subject.Format != goidc.SSFSubjectFormatOpaque {
					t.Fatalf("subject format = %q, want %q", event.Subject.Format, goidc.SSFSubjectFormatOpaque)
				}
				if event.Subject.ID != "stream_id" {
					t.Fatalf("subject ID = %q, want stream_id", event.Subject.ID)
				}
				if event.Claims["state"] != "test_state" {
					t.Fatalf("state claim = %v, want test_state", event.Claims["state"])
				}
				if event.IssuedAt <= 0 {
					t.Fatalf("issued_at = %d, want positive timestamp", event.IssuedAt)
				}

				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.VerifiedAt != event.IssuedAt {
					t.Fatalf("verified_at = %d, want %d", stream.VerifiedAt, event.IssuedAt)
				}
			},
		},
		{
			name: "omits empty state claim",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
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
				return ctx, requestVerificationEvent{StreamID: "stream_id"}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				t.Helper()

				event := waitForPollEvent(t, ctx, "stream_id")
				if _, ok := event.Claims["state"]; ok {
					t.Fatal("state claim should not be set")
				}
			},
		},
		{
			name: "stream not found",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				return ctx, requestVerificationEvent{StreamID: "missing"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "empty stream ID",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				return ctx, requestVerificationEvent{}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "other_receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestVerificationEvent{StreamID: "stream_id"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "receiver error",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{}, errors.New("receiver failed")
				}
				return ctx, requestVerificationEvent{StreamID: "stream_id"}
			},
			wantErr: true,
		},
		{
			name: "rate limited",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				ctx.SSFVerificationMinInterval = 60
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					VerifiedAt: timeutil.TimestampNow(),
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
				return ctx, requestVerificationEvent{StreamID: "stream_id"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context) {
				t.Helper()

				events, err := ctx.SSFPollEvents("stream_id", goidc.SSFPollOptions{})
				if err != nil {
					t.Fatalf("could not poll events: %v", err)
				}
				if len(events.Events) != 0 {
					t.Fatalf("scheduled events = %d, want 0", len(events.Events))
				}
			},
		},
		{
			name: "refreshes inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
					InactiveAt: 1,
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
				return ctx, requestVerificationEvent{StreamID: "stream_id"}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				t.Helper()

				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.InactiveAt <= timeutil.TimestampNow() {
					t.Fatalf("inactive_at = %d, want future timestamp", stream.InactiveAt)
				}
			},
		},
		{
			name: "disabled stream does not refresh inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, requestVerificationEvent) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusDisabled,
					InactiveAt: 1,
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
				return ctx, requestVerificationEvent{StreamID: "stream_id"}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
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
			// Given.
			ctx, req := tt.setup(t)

			// When.
			err := scheduleVerificationEvent(ctx, req)

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
				if tt.validate != nil {
					tt.validate(t, ctx)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, ctx)
			}
		})
	}
}
