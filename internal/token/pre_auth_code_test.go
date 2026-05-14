package token

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGeneratePreAuthCodeGrant(t *testing.T) {
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
				ctx.VCPreAuthCodeAnonymousAccessIsEnabled = true
				ctx.VCIsEnabled = true
				ctx.Scopes = []goidc.Scope{goidc.NewScope("vc_scope1")}
				ctx.VCIssuers = []goidc.VCIssuer{
					{
						ID: "https://issuer.example.com",
						Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
							"cred1": {Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.VCHandlePreAuthCodeFunc = func(_ context.Context, code string, opts goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					if code != "pre_auth_code" {
						t.Fatalf("code = %q, want %q", code, "pre_auth_code")
					}
					if opts.Issuer != "https://issuer.example.com" {
						t.Fatalf("Issuer = %q, want %q", opts.Issuer, "https://issuer.example.com")
					}
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCCredentialID{
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
			name: "non-openid-credential auth detail rejected",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx := oidctest.NewContext(t)
				ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantPreAuthorizedCode)
				ctx.VCPreAuthCodeAnonymousAccessIsEnabled = true
				ctx.VCIsEnabled = true
				ctx.RARIsEnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{goidc.AuthDetailTypeOpenIDCredential, "other_type"}
				ctx.VCIssuers = []goidc.VCIssuer{
					{
						ID: "https://issuer.example.com",
						Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
							"cred1": {Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.VCHandlePreAuthCodeFunc = func(_ context.Context, _ string, _ goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCCredentialID{
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
				ctx.VCPreAuthCodeAnonymousAccessIsEnabled = true
				ctx.VCIsEnabled = true
				ctx.VCIssuers = []goidc.VCIssuer{
					{
						ID: "https://issuer.example.com",
						Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
							"cred1": {Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.VCHandlePreAuthCodeFunc = func(_ context.Context, _ string, _ goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
					return goidc.VCPreAuthCodeResult{
						Subject: "subject",
						ConfigurationIDs: map[goidc.VCConfigurationID][]goidc.VCCredentialID{
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req := test.setup(t)

			resp, err := generatePreAuthCodeGrant(ctx, req)

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
