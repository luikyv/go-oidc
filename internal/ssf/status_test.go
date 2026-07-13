package ssf

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestFetchStreamStatus(t *testing.T) {
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
		validate func(*testing.T, oidc.Context, responseStatus)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:           "stream_id",
					ReceiverID:   "receiver_id",
					Status:       goidc.SSFStreamStatusPaused,
					StatusReason: "maintenance",
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, "stream_id"
			},
			validate: func(t *testing.T, _ oidc.Context, resp responseStatus) {
				t.Helper()
				if resp.ID != "stream_id" {
					t.Fatalf("stream ID = %q, want stream_id", resp.ID)
				}
				if resp.Status != goidc.SSFStreamStatusPaused {
					t.Fatalf("status = %q, want %q", resp.Status, goidc.SSFStreamStatusPaused)
				}
				if resp.StatusReason != "maintenance" {
					t.Fatalf("status reason = %q, want maintenance", resp.StatusReason)
				}
			},
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
			name: "stream not found",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				return ctx, "missing"
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "other_receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, "stream_id"
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "receiver error",
			setup: func(tb testing.TB) (oidc.Context, string) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{}, errors.New("receiver failed")
				}
				return ctx, "stream_id"
			},
			wantErr: true,
		},
		{
			name: "refreshes inactivity deadline",
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
				return ctx, "stream_id"
			},
			validate: func(t *testing.T, ctx oidc.Context, _ responseStatus) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx, id := tt.setup(t)

			// When.
			resp, err := fetchStreamStatus(ctx, id)

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
				tt.validate(t, ctx, resp)
			}
		})
	}
}

func TestUpdateStreamStatus(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.SSFStreamManager = oidctest.Manager(tb, ctx)
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
		ctx.SSFStatusHandleFunc = func(context.Context, *goidc.SSFStream, goidc.SSFStatusOptions) error {
			return nil
		}
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, requestStatus)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, responseStatus)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{
					ID:           "stream_id",
					Status:       goidc.SSFStreamStatusPaused,
					StatusReason: "maintenance",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp responseStatus) {
				t.Helper()
				if resp.Status != goidc.SSFStreamStatusPaused {
					t.Fatalf("status = %q, want %q", resp.Status, goidc.SSFStreamStatusPaused)
				}
				if resp.StatusReason != "maintenance" {
					t.Fatalf("status reason = %q, want maintenance", resp.StatusReason)
				}
				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.Status != goidc.SSFStreamStatusPaused {
					t.Fatalf("persisted status = %q, want %q", stream.Status, goidc.SSFStreamStatusPaused)
				}
			},
		},
		{
			name: "empty stream ID",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				return ctx, requestStatus{Status: goidc.SSFStreamStatusPaused}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "stream not found",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				return ctx, requestStatus{ID: "missing", Status: goidc.SSFStreamStatusPaused}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver checked before status validation",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "other_receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{ID: "stream_id", Status: "unsupported"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "status is required",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{ID: "stream_id"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported status",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{ID: "stream_id", Status: "unsupported"}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "status reason too long",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{
					ID:           "stream_id",
					Status:       goidc.SSFStreamStatusPaused,
					StatusReason: strings.Repeat("a", maxStatusReasonSize+1),
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "status reason control characters",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{
					ID:           "stream_id",
					Status:       goidc.SSFStreamStatusPaused,
					StatusReason: "maintenance\nnext line",
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "calls status handler before applying status",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				handlerCalled := false
				ctx.SSFStatusHandleFunc = func(_ context.Context, stream *goidc.SSFStream, opts goidc.SSFStatusOptions) error {
					handlerCalled = true
					if stream.Status != goidc.SSFStreamStatusEnabled {
						tb.Fatalf("handler saw status = %q, want %q", stream.Status, goidc.SSFStreamStatusEnabled)
					}
					if opts.Status != goidc.SSFStreamStatusPaused {
						tb.Fatalf("handler option status = %q, want %q", opts.Status, goidc.SSFStreamStatusPaused)
					}
					if opts.Reason != "maintenance" {
						tb.Fatalf("handler option reason = %q, want maintenance", opts.Reason)
					}
					return nil
				}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				tb.Cleanup(func() {
					if !handlerCalled {
						tb.Errorf("status handler should be called")
					}
				})
				return ctx, requestStatus{
					ID:           "stream_id",
					Status:       goidc.SSFStreamStatusPaused,
					StatusReason: "maintenance",
				}
			},
		},
		{
			name: "status handler error prevents update",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
				ctx := setup(tb)
				ctx.SSFStatusHandleFunc = func(context.Context, *goidc.SSFStream, goidc.SSFStatusOptions) error {
					return errors.New("status handler failed")
				}
				if err := ctx.SSFSaveStream(&goidc.SSFStream{
					ID:         "stream_id",
					ReceiverID: "receiver_id",
					Status:     goidc.SSFStreamStatusEnabled,
				}); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestStatus{ID: "stream_id", Status: goidc.SSFStreamStatusPaused}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context, _ responseStatus) {
				t.Helper()
				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					t.Fatalf("could not load stream: %v", err)
				}
				if stream.Status != goidc.SSFStreamStatusEnabled {
					t.Fatalf("persisted status = %q, want %q", stream.Status, goidc.SSFStreamStatusEnabled)
				}
			},
		},
		{
			name: "does not refresh inactivity deadline when paused",
			setup: func(tb testing.TB) (oidc.Context, requestStatus) {
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
				return ctx, requestStatus{ID: "stream_id", Status: goidc.SSFStreamStatusPaused}
			},
			validate: func(t *testing.T, ctx oidc.Context, _ responseStatus) {
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
			resp, err := updateStreamStatus(ctx, req)

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
					tt.validate(t, ctx, resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, ctx, resp)
			}
		})
	}
}
