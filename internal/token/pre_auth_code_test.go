package token

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGeneratePreAuthCodeTokenValidatesDPoPNonceOnce(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
	ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
	ctx.VCIEnabled = true
	ctx.VCISelfEnabled = true
	ctx.VCISelfPreAuthCodeGrantEnabled = true
	ctx.VCISelfPreAuthCodeGrantManager = oidctest.Manager(t, ctx)
	ctx.VCISelfHost = "https://issuer.example.com"
	ctx.Scopes = []goidc.Scope{goidc.NewScope("vc_scope1")}
	ctx.VCIIssuers = []goidc.VCIssuer{
		{
			Issuer: ctx.VCISelfHost,
			Configurations: []goidc.VCConfiguration{
				{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
			},
		},
	}

	nonceManager := &singleUseDPoPNonceManager{nonce: "current_nonce"}
	ctx.DPoPEnabled = true
	ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
	ctx.DPoPNonceManager = nonceManager
	proof, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    "https://example.com/token",
		Nonce:  "current_nonce",
	})
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Header.Set(goidc.HeaderDPoP, proof)
	ctx = oidc.NewHTTPContext(httptest.NewRecorder(), req, ctx.Configuration)

	grant := &goidc.Grant{
		ID:                   "grant_id",
		Subject:              "subject",
		Scopes:               "vc_scope1",
		PreAuthCode:          "pre_auth_code",
		PreAuthCodeExpiresAt: timeutil.TimestampNow() + 60,
		JWKThumbprint:        thumbprint,
	}
	if err := ctx.SaveGrant(grant); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}

	resp, err := generatePreAuthCodeToken(ctx, request{
		preAuthCode: "pre_auth_code",
		scopes:      "vc_scope1",
	})

	if err != nil {
		t.Fatalf("generatePreAuthCodeToken() error = %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("AccessToken is empty")
	}
	if nonceManager.validateCalls != 1 {
		t.Fatalf("ValidateNonce() calls = %d, want 1", nonceManager.validateCalls)
	}
}

type singleUseDPoPNonceManager struct {
	nonce         string
	validateCalls int
}

func (*singleUseDPoPNonceManager) IssueNonce(context.Context, goidc.DPoPNonceScope) (string, error) {
	return "fresh_nonce", nil
}

func (m *singleUseDPoPNonceManager) ValidateNonce(_ context.Context, _ goidc.DPoPNonceScope, nonce string) (goidc.DPoPNonceValidation, error) {
	m.validateCalls++
	if nonce != m.nonce {
		return goidc.DPoPNonceValidation{}, goidc.ErrNotFound
	}
	m.nonce = ""
	return goidc.DPoPNonceValidation{}, nil
}

func TestGeneratePreAuthCodeToken(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, request)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "missing pre-authorized code",
			setup: func(t *testing.T) (oidc.Context, request) {
				return oidctest.NewContext(t), request{}
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "anonymous access success",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
				ctx.VCIEnabled = true
				ctx.VCIExternalPreAuthCodeGrantEnabled = true
				ctx.Scopes = []goidc.Scope{goidc.NewScope("vc_scope1")}
				ctx.VCIIssuers = []goidc.VCIssuer{
					{
						Issuer: "https://issuer.example.com",
						Configurations: []goidc.VCConfiguration{
							{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.VCIExternalPreAuthCodeHandleFunc = func(_ context.Context, code string, opts goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					if code != "pre_auth_code" {
						t.Fatalf("code = %q, want %q", code, "pre_auth_code")
					}
					if opts.Issuer != "https://issuer.example.com" {
						t.Fatalf("Issuer = %q, want %q", opts.Issuer, "https://issuer.example.com")
					}
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCIdentifier{
							"cred1": {"credential_1"},
						},
					}, nil
				}
				return ctx, request{
					preAuthCode: "pre_auth_code",
					scopes:      "vc_scope1",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.AccessToken == "" {
					t.Fatal("expected access token")
				}
				if resp.Scopes != "vc_scope1" {
					t.Fatalf("Scopes = %q, want %q", resp.Scopes, "vc_scope1")
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(Grants) = %d, want 1", len(grants))
				}
				if grants[0].PreAuthCode != "pre_auth_code" {
					t.Fatalf("PreAuthCode = %q, want %q", grants[0].PreAuthCode, "pre_auth_code")
				}
			},
		},
		{
			name: "self issuer success without transaction code",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
				ctx.VCIEnabled = true
				ctx.VCISelfEnabled = true
				ctx.VCISelfPreAuthCodeGrantEnabled = true
				ctx.VCISelfPreAuthCodeGrantManager = oidctest.Manager(t, ctx)
				ctx.VCISelfHost = "https://issuer.example.com"
				ctx.Scopes = []goidc.Scope{goidc.NewScope("vc_scope1")}
				ctx.VCIIssuers = []goidc.VCIssuer{
					{
						Issuer: ctx.VCISelfHost,
						Configurations: []goidc.VCConfiguration{
							{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				grant := &goidc.Grant{
					ID:                   "grant_id",
					Subject:              "subject",
					Scopes:               "vc_scope1",
					PreAuthCode:          "pre_auth_code",
					PreAuthCodeExpiresAt: timeutil.TimestampNow() + 60,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}
				return ctx, request{
					preAuthCode: "pre_auth_code",
					scopes:      "vc_scope1",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.AccessToken == "" {
					t.Fatal("expected access token")
				}
				grant, err := ctx.VCISelfGrantByPreAuthCode("pre_auth_code")
				if err != nil {
					t.Fatalf("VCISelfGrantByPreAuthCode() error = %v", err)
				}
				if grant.PreAuthCodeConsumedAt == 0 {
					t.Fatal("PreAuthCodeConsumedAt = 0, want non-zero")
				}
			},
		},
		{
			name: "self issuer rejects invalid transaction code",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
				ctx.VCIEnabled = true
				ctx.VCISelfEnabled = true
				ctx.VCISelfPreAuthCodeGrantEnabled = true
				ctx.VCISelfPreAuthCodeGrantManager = oidctest.Manager(t, ctx)
				ctx.VCISelfHost = "https://issuer.example.com"
				ctx.VCIIssuers = []goidc.VCIssuer{
					{
						Issuer:         ctx.VCISelfHost,
						Configurations: []goidc.VCConfiguration{},
					},
				}
				grant := &goidc.Grant{
					ID:                   "grant_id",
					Subject:              "subject",
					PreAuthCode:          "pre_auth_code",
					PreAuthCodeExpiresAt: timeutil.TimestampNow() + 60,
					TransactionCode:      "123456",
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}
				return ctx, request{
					preAuthCode: "pre_auth_code",
					txCode:      "wrong",
				}
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
		},
		{
			name: "non-openid-credential auth detail rejected",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
				ctx.VCIEnabled = true
				ctx.VCIExternalPreAuthCodeGrantEnabled = true
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{goidc.AuthDetailTypeOpenIDCredential, "other_type"}
				ctx.VCIIssuers = []goidc.VCIssuer{
					{
						Issuer: "https://issuer.example.com",
						Configurations: []goidc.VCConfiguration{
							{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.VCIExternalPreAuthCodeHandleFunc = func(_ context.Context, _ string, _ goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCIdentifier{
							"cred1": {"credential_1"},
						},
					}, nil
				}
				return ctx, request{
					preAuthCode: "pre_auth_code",
					authDetails: []goidc.AuthDetail{
						{"type": "other_type"},
						{
							"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
							"credential_configuration_id": "cred1",
							"locations":                   []any{"https://issuer.example.com"},
						},
					},
				}
			},
			wantErr: goidc.ErrorCodeInvalidAuthDetails,
		},
		{
			name: "unknown configuration returned by handler",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
				ctx.VCIEnabled = true
				ctx.VCIExternalPreAuthCodeGrantEnabled = true
				ctx.VCIIssuers = []goidc.VCIssuer{
					{
						Issuer: "https://issuer.example.com",
						Configurations: []goidc.VCConfiguration{
							{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.VCIExternalPreAuthCodeHandleFunc = func(_ context.Context, _ string, _ goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCIdentifier{
							"unknown": {"credential_1"},
						},
					}, nil
				}
				return ctx, request{
					preAuthCode: "pre_auth_code",
				}
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "scope not authorized by pre-authorized code",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCIPreAuthCodeAnonymousAccessEnabled = true
				ctx.VCIEnabled = true
				ctx.VCIExternalPreAuthCodeGrantEnabled = true
				ctx.Scopes = []goidc.Scope{goidc.NewScope("vc_scope1"), goidc.NewScope("vc_scope2")}
				ctx.VCIIssuers = []goidc.VCIssuer{
					{
						Issuer: "https://issuer.example.com",
						Configurations: []goidc.VCConfiguration{
							{ID: "cred1", Scope: goidc.NewScope("vc_scope1")},
							{ID: "cred2", Scope: goidc.NewScope("vc_scope2")},
						},
					},
				}
				ctx.VCIExternalPreAuthCodeHandleFunc = func(_ context.Context, _ string, _ goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCIdentifier{
							"cred1": {"credential_1"},
						},
					}, nil
				}
				return ctx, request{
					preAuthCode: "pre_auth_code",
					scopes:      "vc_scope2",
				}
			},
			wantErr: goidc.ErrorCodeInvalidScope,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req := test.setup(t)

			resp, err := generatePreAuthCodeToken(ctx, req)

			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("Code = %s, want %s, err = %v", oidcErr.Code, test.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.validate != nil {
				test.validate(t, ctx, resp)
			}
		})
	}
}
