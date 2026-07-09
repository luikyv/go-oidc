package vc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	vcutil "github.com/luikyv/go-oidc/internal/vc/util"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNewMetadata(t *testing.T) {
	baseConfig := func() *oidc.Configuration {
		return &oidc.Configuration{
			Host:                      "https://op.example.com",
			VCISelfHost:               "https://credential-issuer.example.com",
			VCISelfCredentialEndpoint: "/credential",
			VCISelfConfigurations:     map[goidc.VCConfigurationID]goidc.VCConfiguration{},
		}
	}

	tests := []struct {
		name   string
		config func() *oidc.Configuration
		check  func(t *testing.T, m metadata)
	}{
		{
			name: "batch credential issuance omitted when batch size is one",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfBatchSize = 1
				return config
			},
			check: func(t *testing.T, m metadata) {
				if m.BatchCredentialIssuance != nil {
					t.Fatal("batch_credential_issuance must be omitted")
				}
			},
		},
		{
			name: "batch credential issuance advertised when batch size is greater than one",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfBatchSize = 10
				return config
			},
			check: func(t *testing.T, m metadata) {
				if m.BatchCredentialIssuance == nil {
					t.Fatal("batch_credential_issuance must be advertised")
				}
				if m.BatchCredentialIssuance.BatchSize != 10 {
					t.Fatalf("batch_size = %d, want 10", m.BatchCredentialIssuance.BatchSize)
				}
			},
		},
		{
			name: "response encryption omitted when disabled",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				config.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return config
			},
			check: func(t *testing.T, m metadata) {
				if m.CredentialResponseEncryption != nil {
					t.Fatal("credential_response_encryption must be omitted")
				}
			},
		},
		{
			name: "response encryption advertised when enabled",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfResponseEncEnabled = true
				config.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				config.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return config
			},
			check: func(t *testing.T, m metadata) {
				if m.CredentialResponseEncryption == nil {
					t.Fatal("credential_response_encryption must be advertised")
				}
				if diff := cmp.Diff(m.CredentialResponseEncryption.AlgValuesSupported, []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(m.CredentialResponseEncryption.EncValuesSupported, []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}); diff != "" {
					t.Error(diff)
				}
				if m.CredentialResponseEncryption.EncryptionRequired {
					t.Fatal("encryption_required = true, want false")
				}
			},
		},
		{
			name: "response encryption advertised when required",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfResponseEncEnabled = true
				config.VCISelfResponseEncRequired = true
				config.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				config.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return config
			},
			check: func(t *testing.T, m metadata) {
				if m.CredentialResponseEncryption == nil {
					t.Fatal("credential_response_encryption must be advertised")
				}
				if !m.CredentialResponseEncryption.EncryptionRequired {
					t.Fatal("encryption_required = false, want true")
				}
			},
		},
		{
			name:   "deferred credential endpoint omitted when disabled",
			config: baseConfig,
			check: func(t *testing.T, m metadata) {
				if m.DeferredCredentialEndpoint != "" {
					t.Fatal("deferred_credential_endpoint must be omitted")
				}
			},
		},
		{
			name: "deferred credential endpoint advertised when enabled",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfDeferredEnabled = true
				config.VCISelfDeferredCredentialEndpoint = "/deferred_credential"
				return config
			},
			check: func(t *testing.T, m metadata) {
				want := "https://credential-issuer.example.com/deferred_credential"
				if m.DeferredCredentialEndpoint != want {
					t.Fatalf("deferred_credential_endpoint = %q, want %q", m.DeferredCredentialEndpoint, want)
				}
			},
		},
		{
			name:   "notification endpoint omitted when disabled",
			config: baseConfig,
			check: func(t *testing.T, m metadata) {
				if m.NotificationEndpoint != "" {
					t.Fatal("notification_endpoint must be omitted")
				}
			},
		},
		{
			name: "notification endpoint advertised when enabled",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfNotificationEnabled = true
				config.VCISelfNotificationEndpoint = "/notification"
				return config
			},
			check: func(t *testing.T, m metadata) {
				want := "https://credential-issuer.example.com/notification"
				if m.NotificationEndpoint != want {
					t.Fatalf("notification_endpoint = %q, want %q", m.NotificationEndpoint, want)
				}
			},
		},
		{
			name: "credential configuration type advertised as vct",
			config: func() *oidc.Configuration {
				config := baseConfig()
				config.VCISelfConfigurations = map[goidc.VCConfigurationID]goidc.VCConfiguration{
					"identity": {
						Format: goidc.VCFormatDCSDJWT,
						Type:   "IdentityCredential",
					},
				}
				return config
			},
			check: func(t *testing.T, m metadata) {
				got := m.CredentialConfigurations["identity"].Type
				if got != "IdentityCredential" {
					t.Fatalf("vct = %q, want %q", got, "IdentityCredential")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := newMetadata(oidc.Context{Configuration: test.config()})
			test.check(t, m)
		})
	}
}

func TestResolve_Disabled(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = false

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIssue(t *testing.T) {
	scope := goidc.NewScope("identity")
	encJWK := oidctest.PrivateRSAOAEPJWK(t, "wallet_key")

	checkDeferred := func(t *testing.T, ctx oidc.Context, resp response, wantInterval int) {
		t.Helper()

		if !resp.Deferred {
			t.Fatal("resp.Deferred must be true")
		}
		if resp.TransactionID != "txn_id" {
			t.Fatalf("transaction_id = %q, want %q", resp.TransactionID, "txn_id")
		}
		if resp.Interval != wantInterval {
			t.Fatalf("interval = %d, want %d", resp.Interval, wantInterval)
		}
		if len(resp.Credentials) != 0 {
			t.Fatal("credentials must be empty when deferred")
		}

		deferral, err := ctx.VCDeferral("txn_id")
		if err != nil {
			t.Fatalf("VCDeferral() error = %v", err)
		}
		if deferral.GrantID != "grant" {
			t.Fatalf("grant_id = %q, want %q", deferral.GrantID, "grant")
		}
		if deferral.CredentialConfigurationID != "identity" {
			t.Fatalf("credential_configuration_id = %q, want %q", deferral.CredentialConfigurationID, "identity")
		}
	}

	tests := []struct {
		name     string
		ctx      func(t *testing.T) oidc.Context
		req      request
		wantCode goidc.ErrorCode
		check    func(t *testing.T, ctx oidc.Context, resp response)
	}{
		{
			name: "encrypted response",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncRequired = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return ctx
			},
			req: request{
				CredentialConfigurationID: "identity",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			},
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.JWT == "" {
					t.Fatal("encrypted credential response is empty")
				}

				jwe, err := jose.ParseEncrypted(
					resp.JWT,
					[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
					[]goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
				)
				if err != nil {
					t.Fatalf("ParseEncrypted() error = %v", err)
				}
				payload, err := jwe.Decrypt(encJWK.Key)
				if err != nil {
					t.Fatalf("Decrypt() error = %v", err)
				}

				var decrypted response
				if err := json.Unmarshal(payload, &decrypted); err != nil {
					t.Fatalf("Unmarshal() error = %v", err)
				}
				if len(decrypted.Credentials) != 1 || decrypted.Credentials[0].Credential != "credential" {
					t.Fatalf("credentials = %+v, want credential", decrypted.Credentials)
				}
			},
		},
		{
			name: "required encryption missing",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncRequired = true
				return ctx
			},
			req:      request{CredentialConfigurationID: "identity"},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "request encryption when unsupported",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				return ctx
			},
			req: request{
				CredentialConfigurationID: "identity",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "private jwk",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return ctx
			},
			req: request{
				CredentialConfigurationID: "identity",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK,
					ContentEncAlg: goidc.A128GCM,
				},
			},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported key algorithm",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return ctx
			},
			req: request{
				CredentialConfigurationID: "identity",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported content algorithm",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A256GCM}
				return ctx
			},
			req: request{
				CredentialConfigurationID: "identity",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "zip unsupported",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				ctx.VCISelfResponseEncCompressionEnabled = true
				return ctx
			},
			req: request{
				CredentialConfigurationID: "identity",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
					ZipAlg:        "DEF",
				},
			},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "notification id",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)
				ctx.VCISelfNotificationEnabled = true
				ctx.VCISelfNotificationManager = oidctest.Manager(t, ctx)
				ctx.VCISelfNotificationIDFunc = func(context.Context) string { return "notification_id" }

				config := ctx.VCISelfConfigurations["identity"]
				config.Issue = func(_ context.Context, _ *goidc.Grant, opts goidc.VCIssuanceOptions) (string, error) {
					if opts.NotificationID != "notification_id" {
						t.Fatalf("VCIssuanceOptions.NotificationID = %q, want %q", opts.NotificationID, "notification_id")
					}
					return "credential", nil
				}
				ctx.VCISelfConfigurations["identity"] = config
				return ctx
			},
			req: request{CredentialConfigurationID: "identity"},
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.NotificationID != "notification_id" {
					t.Fatalf("notification_id = %q, want %q", resp.NotificationID, "notification_id")
				}
				notification, err := ctx.VCNotification("notification_id")
				if err != nil {
					t.Fatalf("VCNotification() error = %v", err)
				}
				if notification.GrantID != "grant" {
					t.Fatalf("grant_id = %q, want %q", notification.GrantID, "grant")
				}
				if notification.ClientID != "client" {
					t.Fatalf("client_id = %q, want %q", notification.ClientID, "client")
				}
				if notification.CredentialConfigurationID != "identity" {
					t.Fatalf("credential_configuration_id = %q, want %q", notification.CredentialConfigurationID, "identity")
				}
			},
		},
		{
			name: "notification disabled",
			ctx: func(t *testing.T) oidc.Context {
				ctx := newCredentialIssueContext(t, scope)

				config := ctx.VCISelfConfigurations["identity"]
				config.Issue = func(_ context.Context, _ *goidc.Grant, opts goidc.VCIssuanceOptions) (string, error) {
					if opts.NotificationID != "" {
						t.Fatalf("VCIssuanceOptions.NotificationID = %q, want empty", opts.NotificationID)
					}
					return "credential", nil
				}
				ctx.VCISelfConfigurations["identity"] = config
				return ctx
			},
			req: request{CredentialConfigurationID: "identity"},
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.NotificationID != "" {
					t.Fatalf("notification_id = %q, want empty", resp.NotificationID)
				}
			},
		},
		{
			name: "deferred with default interval",
			ctx: func(t *testing.T) oidc.Context {
				return newDeferredContext(t, func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
					return goidc.VCDeferralResult{Pending: true}, nil
				})
			},
			req: request{CredentialConfigurationID: "identity"},
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				checkDeferred(t, ctx, resp, 5)
			},
		},
		{
			name: "deferred with custom interval",
			ctx: func(t *testing.T) oidc.Context {
				return newDeferredContext(t, func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
					return goidc.VCDeferralResult{Pending: true, IntervalSecs: 42}, nil
				})
			},
			req: request{CredentialConfigurationID: "identity"},
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				checkDeferred(t, ctx, resp, 42)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.ctx(t)
			resp, err := issue(ctx, test.req)
			if test.wantCode != "" {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantCode {
					t.Fatalf("error = %v, want code %q", err, test.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("issue() error = %v", err)
			}
			test.check(t, ctx, resp)
		})
	}
}

func newCredentialIssueContext(t *testing.T, scope goidc.Scope) oidc.Context {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.OpaqueTokenEnabled = true
	ctx.OpaqueTokenManager = oidctest.Manager(t, ctx)
	ctx.Request.Header.Set("Authorization", "Bearer access_token")
	ctx.VCISelfHost = ctx.Host
	ctx.VCISelfConfigurations = map[goidc.VCConfigurationID]goidc.VCConfiguration{
		"identity": {
			Scope: scope,
			Issue: func(context.Context, *goidc.Grant, goidc.VCIssuanceOptions) (string, error) {
				return "credential", nil
			},
		},
	}
	now := timeutil.TimestampNow()
	grant := &goidc.Grant{
		ID:        "grant",
		ClientID:  "client",
		CreatedAt: now,
		Scopes:    scope.ID,
	}
	if err := ctx.SaveGrant(grant); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}
	if err := ctx.SaveOpaqueToken(&goidc.Token{
		ID:        "access_token",
		GrantID:   grant.ID,
		ClientID:  grant.ClientID,
		CreatedAt: now,
		ExpiresAt: now + 60,
		Format:    goidc.TokenFormatOpaque,
		Type:      goidc.TokenTypeBearer,
		Scopes:    scope.ID,
	}); err != nil {
		t.Fatalf("SaveOpaqueToken() error = %v", err)
	}

	return ctx
}

func newDeferredContext(t *testing.T, isDeferred goidc.VCIsDeferredFunc) oidc.Context {
	t.Helper()

	ctx := newCredentialIssueContext(t, goidc.NewScope("identity"))
	ctx.RefreshTokenManager = oidctest.Manager(t, ctx)
	ctx.VCISelfDeferredEnabled = true
	ctx.VCISelfDeferredManager = oidctest.Manager(t, ctx)
	ctx.VCISelfDeferredIDFunc = func(context.Context) string { return "txn_id" }
	ctx.VCISelfDeferredIntervalSecs = 5

	config := ctx.VCISelfConfigurations["identity"]
	config.IsDeferred = isDeferred
	ctx.VCISelfConfigurations["identity"] = config

	return ctx
}

func TestDeferredCredential_Errors(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, ctx oidc.Context) oidc.Context
		req      deferredRequest
		wantCode goidc.ErrorCode
	}{
		{
			name:     "missing transaction id",
			req:      deferredRequest{},
			wantCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid token",
			setup: func(t *testing.T, ctx oidc.Context) oidc.Context {
				ctx.Request.Header.Set("Authorization", "Bearer not_the_access_token")
				return ctx
			},
			req:      deferredRequest{TransactionID: "txn_id"},
			wantCode: goidc.ErrorCodeInvalidToken,
		},
		{
			name:     "unknown transaction id",
			req:      deferredRequest{TransactionID: "does_not_exist"},
			wantCode: goidc.ErrorCodeInvalidTransactionID,
		},
		{
			name: "grant mismatch",
			setup: func(t *testing.T, ctx oidc.Context) oidc.Context {
				if err := ctx.VCSaveDeferral(&goidc.VCDeferral{
					ID:                        "txn_id",
					GrantID:                   "some_other_grant",
					CredentialConfigurationID: "identity",
				}); err != nil {
					t.Fatalf("VCSaveDeferral() error = %v", err)
				}
				return ctx
			},
			req:      deferredRequest{TransactionID: "txn_id"},
			wantCode: goidc.ErrorCodeInvalidTransactionID,
		},
		{
			name: "already consumed",
			setup: func(t *testing.T, ctx oidc.Context) oidc.Context {
				if err := ctx.VCSaveDeferral(&goidc.VCDeferral{
					ID:                        "txn_id",
					GrantID:                   "grant",
					CredentialConfigurationID: "identity",
					ConsumedAt:                timeutil.TimestampNow(),
				}); err != nil {
					t.Fatalf("VCSaveDeferral() error = %v", err)
				}
				return ctx
			},
			req:      deferredRequest{TransactionID: "txn_id"},
			wantCode: goidc.ErrorCodeInvalidTransactionID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newDeferredContext(t, nil)
			if test.setup != nil {
				ctx = test.setup(t, ctx)
			}

			_, err := deferredCredential(ctx, test.req)
			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantCode {
				t.Fatalf("error = %v, want code %q", err, test.wantCode)
			}
		})
	}
}

func TestDeferredCredential_Poll(t *testing.T) {
	tests := []struct {
		name        string
		isDeferred  goidc.VCIsDeferredFunc
		wantPending bool
		check       func(t *testing.T, ctx oidc.Context, resp response)
	}{
		{
			name: "still pending",
			isDeferred: func(_ context.Context, _ *goidc.Grant, deferral *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
				deferral.Store = map[string]any{"review_id": "123"}
				return goidc.VCDeferralResult{Pending: true}, nil
			},
			wantPending: true,
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.TransactionID != "txn_id" {
					t.Fatalf("transaction_id = %q, want %q", resp.TransactionID, "txn_id")
				}
				if resp.Interval != 5 {
					t.Fatalf("interval = %d, want 5", resp.Interval)
				}
				if len(resp.Credentials) != 0 {
					t.Fatal("credentials must be empty while pending")
				}

				deferral, err := ctx.VCDeferral("txn_id")
				if err != nil {
					t.Fatalf("VCDeferral() error = %v", err)
				}
				if deferral.ConsumedAt != 0 {
					t.Fatal("deferral must not be consumed while pending")
				}
				if deferral.Store["review_id"] != "123" {
					t.Fatalf("store = %+v, want review_id = 123", deferral.Store)
				}
			},
		},
		{
			name: "resolved",
			isDeferred: func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
				return goidc.VCDeferralResult{Pending: false}, nil
			},
			check: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.TransactionID != "" {
					t.Fatalf("transaction_id = %q, want empty", resp.TransactionID)
				}
				if len(resp.Credentials) != 1 || resp.Credentials[0].Credential != "credential" {
					t.Fatalf("credentials = %+v, want one credential", resp.Credentials)
				}

				deferral, err := ctx.VCDeferral("txn_id")
				if err != nil {
					t.Fatalf("VCDeferral() error = %v", err)
				}
				if deferral.ConsumedAt == 0 {
					t.Fatal("deferral must be consumed once resolved")
				}

				// Polling again after resolution must fail, since the deferral was consumed.
				_, err = deferredCredential(ctx, deferredRequest{TransactionID: "txn_id"})
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeInvalidTransactionID {
					t.Fatalf("error = %v, want code %q", err, goidc.ErrorCodeInvalidTransactionID)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newDeferredContext(t, test.isDeferred)
			if err := ctx.VCSaveDeferral(&goidc.VCDeferral{
				ID:                        "txn_id",
				GrantID:                   "grant",
				CredentialConfigurationID: "identity",
			}); err != nil {
				t.Fatalf("VCSaveDeferral() error = %v", err)
			}

			resp, err := deferredCredential(ctx, deferredRequest{TransactionID: "txn_id"})
			if err != nil {
				t.Fatalf("deferredCredential() error = %v", err)
			}
			if resp.Deferred != test.wantPending {
				t.Fatalf("resp.Deferred = %t, want %t", resp.Deferred, test.wantPending)
			}
			test.check(t, ctx, resp)
		})
	}
}

func TestDeferredCredential_ResponseEncryptionValidation(t *testing.T) {
	encJWK := oidctest.PrivateRSAOAEPJWK(t, "wallet_key")

	tests := []struct {
		name  string
		setup func(oidc.Context) oidc.Context
		req   deferredRequest
	}{
		{
			name: "required encryption missing",
			setup: func(ctx oidc.Context) oidc.Context {
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncRequired = true
				return ctx
			},
			req: deferredRequest{TransactionID: "txn_id"},
		},
		{
			name: "private jwk",
			setup: func(ctx oidc.Context) oidc.Context {
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return ctx
			},
			req: deferredRequest{
				TransactionID: "txn_id",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK,
					ContentEncAlg: goidc.A128GCM,
				},
			},
		},
		{
			name: "unsupported key algorithm",
			setup: func(ctx oidc.Context) oidc.Context {
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
				return ctx
			},
			req: deferredRequest{
				TransactionID: "txn_id",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			},
		},
		{
			name: "unsupported content algorithm",
			setup: func(ctx oidc.Context) oidc.Context {
				ctx.VCISelfResponseEncEnabled = true
				ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A256GCM}
				return ctx
			},
			req: deferredRequest{
				TransactionID: "txn_id",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newDeferredContext(t, func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
				return goidc.VCDeferralResult{Pending: true}, nil
			})
			if test.setup != nil {
				ctx = test.setup(ctx)
			}
			if err := ctx.VCSaveDeferral(&goidc.VCDeferral{
				ID:                        "txn_id",
				GrantID:                   "grant",
				CredentialConfigurationID: "identity",
			}); err != nil {
				t.Fatalf("VCSaveDeferral() error = %v", err)
			}

			_, err := deferredCredential(ctx, test.req)
			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeInvalidRequest {
				t.Fatalf("error = %v, want code %q", err, goidc.ErrorCodeInvalidRequest)
			}
		})
	}
}

func TestDeferredCredential_ResponseEncryption(t *testing.T) {
	encJWK := oidctest.PrivateRSAOAEPJWK(t, "wallet_key")

	tests := []struct {
		name        string
		isDeferred  goidc.VCIsDeferredFunc
		wantPending bool
	}{
		{
			name: "pending response is encrypted",
			isDeferred: func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
				return goidc.VCDeferralResult{Pending: true}, nil
			},
			wantPending: true,
		},
		{
			name: "resolved response is encrypted",
			isDeferred: func(context.Context, *goidc.Grant, *goidc.VCDeferral) (goidc.VCDeferralResult, error) {
				return goidc.VCDeferralResult{Pending: false}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newDeferredContext(t, test.isDeferred)
			ctx.VCISelfResponseEncEnabled = true
			ctx.VCISelfResponseEncKeyAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
			ctx.VCISelfResponseEncContentAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128GCM}
			if err := ctx.VCSaveDeferral(&goidc.VCDeferral{
				ID:                        "txn_id",
				GrantID:                   "grant",
				CredentialConfigurationID: "identity",
			}); err != nil {
				t.Fatalf("VCSaveDeferral() error = %v", err)
			}

			resp, err := deferredCredential(ctx, deferredRequest{
				TransactionID: "txn_id",
				CredentialResponseEncryption: &credentialResponseEncryption{
					JWK:           encJWK.Public(),
					ContentEncAlg: goidc.A128GCM,
				},
			})
			if err != nil {
				t.Fatalf("deferredCredential() error = %v", err)
			}
			if resp.Deferred != test.wantPending {
				t.Fatalf("resp.Deferred = %t, want %t", resp.Deferred, test.wantPending)
			}
			if resp.JWT == "" {
				t.Fatal("encrypted deferred credential response is empty")
			}

			jwe, err := jose.ParseEncrypted(
				resp.JWT,
				[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
				[]goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
			)
			if err != nil {
				t.Fatalf("ParseEncrypted() error = %v", err)
			}
			payload, err := jwe.Decrypt(encJWK.Key)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			var decrypted response
			if err := json.Unmarshal(payload, &decrypted); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if test.wantPending {
				if decrypted.TransactionID != "txn_id" {
					t.Fatalf("transaction_id = %q, want %q", decrypted.TransactionID, "txn_id")
				}
			} else if len(decrypted.Credentials) != 1 || decrypted.Credentials[0].Credential != "credential" {
				t.Fatalf("credentials = %+v, want one credential", decrypted.Credentials)
			}
		})
	}
}

func TestResolve_AuthDetailsOnly_SingleIssuer(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1"},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_AuthDetailsOnly_UnknownConfigID(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer:         "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "unknown_cred",
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown credential_configuration_id")
	}
}

func TestResolve_AuthDetailsOnly_MultipleIssuers_WithLocations(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1"},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred2"},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_AuthDetails_ConflictingLocations(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1"},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred2"},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred2",
				"locations":                   []any{"https://issuer2.example.com"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for conflicting locations")
	}
}

func TestResolve_ScopesOnly(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{Scopes: "vc_scope1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_ScopesConflictIssuers(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred2", Scope: goidc.NewScope("vc_scope2")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{Scopes: "vc_scope1 vc_scope2"})
	if err == nil {
		t.Fatal("expected error for scopes referencing different issuers")
	}
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidScope {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidScope)
	}
}

func TestResolve_ResourcesOnly(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1"},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Resources: goidc.Resources{"https://issuer1.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_CrossSignalConflict_AuthDetailsVsScopes(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1"},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred2", Scope: goidc.NewScope("vc_scope2")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes: "vc_scope2",
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for cross-signal issuer conflict")
	}
}

func TestResolve_CrossSignalConflict_AuthDetailsVsResources(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1"},
			},
		},
		{
			Issuer:         "https://issuer2.example.com",
			Configurations: []goidc.VCConfiguration{},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
				"locations":                   []any{"https://issuer1.example.com"},
			},
		},
		Resources: goidc.Resources{"https://issuer2.example.com"},
	})
	if err == nil {
		t.Fatal("expected error for cross-signal issuer conflict between auth details and resources")
	}
}

func TestResolve_AllThreeSignals_Consistent(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
			},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes: "vc_scope1",
		Details: []goidc.AuthDetail{
			{
				"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
				"credential_configuration_id": "cred1",
			},
		},
		Resources: goidc.Resources{"https://issuer1.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_MissingConfigID(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.RAREnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer:         "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{},
		},
	}

	_, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Details: []goidc.AuthDetail{
			{
				"type": string(goidc.AuthDetailTypeOpenIDCredential),
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing credential_configuration_id")
	}
}

func TestResolve_WithResources(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.VCIEnabled = true
	ctx.ResourceIndicatorsEnabled = true
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: "https://issuer1.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
			},
		},
		{
			Issuer: "https://issuer2.example.com",
			Configurations: []goidc.VCConfiguration{
				{ID: "cred2", Scope: goidc.NewScope("vc_scope2")},
			},
		},
	}

	// Scopes resolve config but no issuer (multiple issuers); resources resolve issuer.
	issuer, configIDs, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes:    "vc_scope1",
		Resources: goidc.Resources{"https://issuer1.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issuer.Issuer != "https://issuer1.example.com" {
		t.Errorf("issuer.ID = %s, want https://issuer1.example.com", issuer.Issuer)
	}
	if len(configIDs) != 1 {
		t.Fatalf("len(configIDs) = %d, want 1", len(configIDs))
	}
	if configIDs[0] != "cred1" {
		t.Errorf("configIDs[0] = %s, want cred1", configIDs[0])
	}
}
