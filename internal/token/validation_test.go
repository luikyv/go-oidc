package token

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidatePKCE(t *testing.T) {
	plainVerifier := "0123456789abcdef0123456789abcdef0123456789a"
	shaVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	tests := []struct {
		name    string
		setup   func(*testing.T) (request, *goidc.Grant)
		wantErr goidc.ErrorCode
	}{
		{
			name: "disabled",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: "anything"}, &goidc.Grant{}
			},
		},
		{
			name: "missing previous challenge with verifier",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: shaVerifier}, &goidc.Grant{}
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
		},
		{
			name: "plain valid",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: plainVerifier}, &goidc.Grant{
					AuthParams: goidc.AuthorizationParameters{
						CodeChallenge:       plainVerifier,
						CodeChallengeMethod: goidc.CodeChallengeMethodPlain,
					},
				}
			},
		},
		{
			name: "plain invalid",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: "0123456789abcdef0123456789abcdef0123456789b"}, &goidc.Grant{
					AuthParams: goidc.AuthorizationParameters{
						CodeChallenge:       plainVerifier,
						CodeChallengeMethod: goidc.CodeChallengeMethodPlain,
					},
				}
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
		},
		{
			name: "sha256 valid",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: shaVerifier}, &goidc.Grant{
					AuthParams: goidc.AuthorizationParameters{
						CodeChallenge:       hashutil.Thumbprint(shaVerifier),
						CodeChallengeMethod: goidc.CodeChallengeMethodSHA256,
					},
				}
			},
		},
		{
			name: "sha256 invalid",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: "wrong_verifier_value_here_0000000000000000000"}, &goidc.Grant{
					AuthParams: goidc.AuthorizationParameters{
						CodeChallenge:       hashutil.Thumbprint(shaVerifier),
						CodeChallengeMethod: goidc.CodeChallengeMethodSHA256,
					},
				}
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
		},
		{
			name: "too short",
			setup: func(*testing.T) (request, *goidc.Grant) {
				return request{codeVerifier: "short"}, &goidc.Grant{
					AuthParams: goidc.AuthorizationParameters{
						CodeChallenge:       "some_challenge",
						CodeChallengeMethod: goidc.CodeChallengeMethodSHA256,
					},
				}
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.PKCEIsEnabled = test.name != "disabled"
			ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
			ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{
				goidc.CodeChallengeMethodPlain,
				goidc.CodeChallengeMethodSHA256,
			}

			req, grant := test.setup(t)
			err := validatePKCE(ctx, req, grant)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %q", test.wantErr)
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("expected goidc.Error, got %v", err)
			}
			if oidcErr.Code != test.wantErr {
				t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
			}
		})
	}
}

func TestValidateBindingRequirement(t *testing.T) {
	tests := []struct {
		name    string
		config  func(*oidc.Context)
		wantErr goidc.ErrorCode
	}{
		{
			name:   "not required",
			config: func(*oidc.Context) {},
		},
		{
			name: "required without binding",
			config: func(ctx *oidc.Context) {
				ctx.TokenBindingIsRequired = true
				ctx.DPoPIsEnabled = false
				ctx.MTLSTokenBindingIsEnabled = false
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			test.config(&ctx)

			err := validateBindingRequirement(ctx)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %q", test.wantErr)
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("expected goidc.Error, got %v", err)
			}
			if oidcErr.Code != test.wantErr {
				t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
			}
		})
	}
}

func TestValidateBinding_DisabledFeatureForBoundGrant(t *testing.T) {
	tests := []struct {
		name    string
		config  func(*oidc.Context, *goidc.Client) bindindValidationOptions
		wantErr goidc.ErrorCode
	}{
		{
			name: "dpop bound grant with dpop disabled",
			config: func(ctx *oidc.Context, c *goidc.Client) bindindValidationOptions {
				ctx.DPoPIsEnabled = false
				return bindindValidationOptions{
					dpopIsRequired:    true,
					dpopJWKThumbprint: "bound_thumbprint",
				}
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "mtls bound grant with mtls disabled",
			config: func(ctx *oidc.Context, c *goidc.Client) bindindValidationOptions {
				ctx.MTLSTokenBindingIsEnabled = false
				return bindindValidationOptions{
					tlsIsRequired:     true,
					tlsCertThumbprint: "bound_thumbprint",
				}
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, _ := oidctest.NewClient(t)

			err := ValidateBinding(ctx, client, func() *bindindValidationOptions {
				opts := test.config(&ctx, client)
				return &opts
			}())

			if err == nil {
				t.Fatalf("expected error %q", test.wantErr)
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("expected goidc.Error, got %v", err)
			}
			if oidcErr.Code != test.wantErr {
				t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		req     request
		granted string
		wantErr goidc.ErrorCode
	}{
		{
			name: "empty request scopes",
			req:  request{},
		},
		{
			name:    "invalid requested scope",
			req:     request{scopes: "openid scope_not_granted"},
			granted: "openid scope1",
			wantErr: goidc.ErrorCodeInvalidScope,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, _ := oidctest.NewClient(t)

			err := validateScopes(ctx, test.req, client, test.granted)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %q", test.wantErr)
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("expected goidc.Error, got %v", err)
			}
			if oidcErr.Code != test.wantErr {
				t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
			}
		})
	}
}

func TestValidateResources(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*oidc.Context) (request, goidc.Resources)
		wantErr goidc.ErrorCode
	}{
		{
			name: "disabled",
			setup: func(ctx *oidc.Context) (request, goidc.Resources) {
				ctx.ResourceIndicatorsIsEnabled = false
				return request{resources: []string{"https://resource.com"}}, nil
			},
		},
		{
			name: "valid resource",
			setup: func(ctx *oidc.Context) (request, goidc.Resources) {
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com", "https://other.com"}
				return request{resources: []string{"https://resource.com"}}, goidc.Resources{"https://resource.com", "https://other.com"}
			},
		},
		{
			name: "invalid resource",
			setup: func(ctx *oidc.Context) (request, goidc.Resources) {
				ctx.ResourceIndicatorsIsEnabled = true
				return request{resources: []string{"https://unknown.com"}}, goidc.Resources{"https://resource.com"}
			},
			wantErr: goidc.ErrorCodeInvalidTarget,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			req, granted := test.setup(&ctx)

			err := validateResources(ctx, req, granted)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %q", test.wantErr)
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("expected goidc.Error, got %v", err)
			}
			if oidcErr.Code != test.wantErr {
				t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
			}
		})
	}
}
