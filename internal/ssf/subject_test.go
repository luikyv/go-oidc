package ssf

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestAddSubject(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		manager := oidctest.Manager(tb, ctx)
		ctx.SSFStreamManager = manager
		ctx.SSFSubjectManager = manager
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
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
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, requestSubject)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
		},
		{
			name: "verified false is passed through",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				verified := false
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
					Verified: &verified,
				}
			},
		},
		{
			name: "invalid subject",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid subject does not refresh inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					tb.Fatalf("could not load stream: %v", err)
				}
				stream.InactiveAt = 1
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
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
		{
			name: "stream not found",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				return ctx, requestSubject{
					StreamID: "missing",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{ID: "other_receiver_id"}, nil
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "receiver error",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{}, errors.New("receiver failed")
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
			wantErr: true,
		},
		{
			name: "refreshes inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					tb.Fatalf("could not load stream: %v", err)
				}
				stream.InactiveAt = 1
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx, req := tt.setup(t)

			// When.
			err := addSubject(ctx, req)

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

func TestRemoveSubject(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		manager := oidctest.Manager(tb, ctx)
		ctx.SSFStreamManager = manager
		ctx.SSFSubjectManager = manager
		ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
			return goidc.SSFReceiver{ID: "receiver_id"}, nil
		}
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
		return ctx
	}

	tests := []struct {
		name     string
		setup    func(tb testing.TB) (oidc.Context, requestSubject)
		wantErr  bool
		errCode  goidc.ErrorCode
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "happy path",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
		},
		{
			name: "invalid subject",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "stream not found",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				return ctx, requestSubject{
					StreamID: "missing",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong receiver",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{ID: "other_receiver_id"}, nil
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
			wantErr: true,
			errCode: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "receiver error",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFReceiverFunc = func(context.Context) (goidc.SSFReceiver, error) {
					return goidc.SSFReceiver{}, errors.New("receiver failed")
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
			},
			wantErr: true,
		},
		{
			name: "refreshes inactivity deadline",
			setup: func(tb testing.TB) (oidc.Context, requestSubject) {
				ctx := setup(tb)
				ctx.SSFInactivityTimeoutSecs = 3600
				stream, err := ctx.SSFStream("stream_id")
				if err != nil {
					tb.Fatalf("could not load stream: %v", err)
				}
				stream.InactiveAt = 1
				if err := ctx.SSFSaveStream(stream); err != nil {
					tb.Fatalf("could not save stream: %v", err)
				}
				return ctx, requestSubject{
					StreamID: "stream_id",
					Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				}
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx, req := tt.setup(t)

			// When.
			err := removeSubject(ctx, req)

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

func TestCompareSubjects(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()
		return oidctest.NewContext(tb)
	}

	tests := []struct {
		name    string
		a, b    goidc.SSFSubject
		wantErr bool
	}{
		{
			name: "same simple subject",
			a:    goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b:    goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
		},
		{
			name:    "different simple subject",
			a:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "other@example.com"},
			wantErr: true,
		},
		{
			name:    "different simple subject formats",
			a:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user@example.com"},
			wantErr: true,
		},
		{
			name: "simple subject does not match complex subject",
			a:    goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			wantErr: true,
		},
		{
			name: "complex subject does not match simple subject",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			b:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			wantErr: true,
		},
		{
			name: "complex subject matches when one side omits a member",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Tenant: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "tenant_id"},
			},
		},
		{
			name: "complex subject matches identical common member",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
		},
		{
			name: "complex subject rejects different common member",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "other@example.com"},
			},
			wantErr: true,
		},
		{
			name: "complex subject checks common additional members",
			a: goidc.SSFSubject{
				Format:            goidc.SSFSubjectFormatComplex,
				User:              &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalMembers: map[string]goidc.SSFSubject{"custom": {Format: goidc.SSFSubjectFormatOpaque, ID: "a"}},
			},
			b: goidc.SSFSubject{
				Format:            goidc.SSFSubjectFormatComplex,
				User:              &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalMembers: map[string]goidc.SSFSubject{"custom": {Format: goidc.SSFSubjectFormatOpaque, ID: "b"}},
			},
			wantErr: true,
		},
		{
			name: "complex subject ignores additional members present on one side",
			a: goidc.SSFSubject{
				Format:            goidc.SSFSubjectFormatComplex,
				User:              &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalMembers: map[string]goidc.SSFSubject{"a": {Format: goidc.SSFSubjectFormatOpaque, ID: "a"}},
			},
			b: goidc.SSFSubject{
				Format:            goidc.SSFSubjectFormatComplex,
				User:              &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalMembers: map[string]goidc.SSFSubject{"b": {Format: goidc.SSFSubjectFormatOpaque, ID: "b"}},
			},
		},
		{
			name:    "invalid subject",
			a:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
			b:       goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx := setup(t)

			// When.
			err := CompareSubjects(ctx, tt.a, tt.b)

			// Then.
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSubject(t *testing.T) {
	setup := func(tb testing.TB) oidc.Context {
		tb.Helper()
		return oidctest.NewContext(tb)
	}

	tests := []struct {
		name    string
		subject goidc.SSFSubject
		wantErr bool
	}{
		{
			name:    "opaque",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "subject_id"},
		},
		{
			name:    "email",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
		},
		{
			name:    "phone number",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatPhoneNumber, Phone: "+15555550100"},
		},
		{
			name:    "account",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatAccount, URI: "acct:user@example.com"},
		},
		{
			name:    "issuer subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatIssuerSubject, Iss: "https://issuer.example.com", Sub: "subject"},
		},
		{
			name:    "did",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectDecentralizedIdentifier, URL: "did:example:123"},
		},
		{
			name:    "uri",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatURI, URI: "https://example.com/users/123"},
		},
		{
			name: "aliases",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatAliases,
				Identifiers: []goidc.SSFSubject{
					{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
					{Format: goidc.SSFSubjectFormatOpaque, ID: "subject_id"},
				},
			},
		},
		{
			name:    "jwt id",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectJWTID, JTI: "jti", Iss: "https://issuer.example.com"},
		},
		{
			name:    "saml assertion id",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectSAMLAssertionID, AssertionID: "assertion_id", Issuer: "https://issuer.example.com"},
		},
		{
			name:    "ip addresses",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectIPAddresses, IPAddresses: []string{"192.0.2.1", "2001:db8::1"}},
		},
		{
			name: "complex",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalMembers: map[string]goidc.SSFSubject{
					"custom": {Format: goidc.SSFSubjectFormatOpaque, ID: "subject_id"},
				},
			},
		},
		{
			name:    "unsupported format",
			subject: goidc.SSFSubject{Format: "unsupported"},
			wantErr: true,
		},
		{
			name:    "missing required field",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
			wantErr: true,
		},
		{
			name:    "disallowed field",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", ID: "subject_id"},
			wantErr: true,
		},
		{
			name:    "invalid ip address",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectIPAddresses, IPAddresses: []string{"not-an-ip"}},
			wantErr: true,
		},
		{
			name: "aliases cannot contain aliases",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatAliases,
				Identifiers: []goidc.SSFSubject{
					{Format: goidc.SSFSubjectFormatAliases, Identifiers: []goidc.SSFSubject{{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"}}},
				},
			},
			wantErr: true,
		},
		{
			name: "aliases cannot contain complex subjects",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatAliases,
				Identifiers: []goidc.SSFSubject{
					{Format: goidc.SSFSubjectFormatComplex, User: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"}},
				},
			},
			wantErr: true,
		},
		{
			name:    "complex requires member",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatComplex},
			wantErr: true,
		},
		{
			name: "complex cannot contain complex subject",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User: &goidc.SSFSubject{
					Format: goidc.SSFSubjectFormatComplex,
					User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "complex validates member",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx := setup(t)

			// When.
			err := validateSubject(ctx, tt.subject)

			// Then.
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
