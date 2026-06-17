package token

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateExchangeToken(t *testing.T) {
	setup := func(tb testing.TB) (oidc.Context, request, *goidc.Client) {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantTokenExchange)
		ctx.TokenExchangeHandleFunc = func(_ context.Context, req goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
			return goidc.TokenExchangeResult{
				Subject: "token_subject",
			}, nil
		}

		c, secret := oidctest.NewClient(tb)
		c.GrantTypes = append(c.GrantTypes, goidc.GrantTokenExchange)
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		req := request{
			grantType:        goidc.GrantTokenExchange,
			scopes:           oidctest.Scope1.ID,
			subjectToken:     "subject_token_value",
			subjectTokenType: goidc.TokenTypeIdentifierAccessToken,
		}

		return ctx, req, c
	}

	tests := []struct {
		name        string
		setup       func() (oidc.Context, request, *goidc.Client)
		wantErr     error
		wantErrCode goidc.ErrorCode
		validate    func(*testing.T, oidc.Context, response, *goidc.Client)
	}{
		{
			name: "happy path - default to access token",
			setup: func() (oidc.Context, request, *goidc.Client) {
				return setup(t)
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.Subject != "token_subject" {
					t.Errorf("grant.Subject = %q, want %q", grant.Subject, "token_subject")
				}
				if grant.ClientID != c.ID {
					t.Errorf("grant.ClientID = %q, want %q", grant.ClientID, c.ID)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       "token_subject",
					"client_id": c.ID,
					"scope":     grant.Scopes,
					"grant_id":  grant.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}

				if resp.IssuedTokenType != goidc.TokenTypeIdentifierAccessToken {
					t.Errorf("resp.IssuedTokenType = %q, want %q", resp.IssuedTokenType, goidc.TokenTypeIdentifierAccessToken)
				}
			},
		},
		{
			name: "access token explicitly requested",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.requestedTokenType = goidc.TokenTypeIdentifierAccessToken
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				if resp.IssuedTokenType != goidc.TokenTypeIdentifierAccessToken {
					t.Errorf("resp.IssuedTokenType = %q, want %q", resp.IssuedTokenType, goidc.TokenTypeIdentifierAccessToken)
				}
				if resp.AccessToken == "" {
					t.Error("resp.AccessToken is empty")
				}
			},
		},
		{
			name: "id token requested",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.requestedTokenType = goidc.TokenTypeIdentifierIDToken
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client) {
				if resp.IssuedTokenType != goidc.TokenTypeIdentifierIDToken {
					t.Errorf("resp.IssuedTokenType = %q, want %q", resp.IssuedTokenType, goidc.TokenTypeIdentifierIDToken)
				}
				if resp.TokenType != goidc.TokenTypeNotApplicable {
					t.Errorf("resp.TokenType = %q, want %q", resp.TokenType, goidc.TokenTypeNotApplicable)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing id token claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss": ctx.Issuer(),
					"sub": "token_subject",
					"aud": c.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "refresh token requested",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.requestedTokenType = goidc.TokenTypeIdentifierRefreshToken
				return ctx, req, c
			},
			validate: func(t *testing.T, _ oidc.Context, resp response, _ *goidc.Client) {
				if resp.IssuedTokenType != goidc.TokenTypeIdentifierRefreshToken {
					t.Errorf("resp.IssuedTokenType = %q, want %q", resp.IssuedTokenType, goidc.TokenTypeIdentifierRefreshToken)
				}
				if resp.TokenType != goidc.TokenTypeNotApplicable {
					t.Errorf("resp.TokenType = %q, want %q", resp.TokenType, goidc.TokenTypeNotApplicable)
				}
				if resp.AccessToken == "" {
					t.Error("resp.AccessToken is empty, expected refresh token value")
				}
			},
		},
		{
			name: "actor passed through to grant and jwt",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.TokenExchangeHandleFunc = func(_ context.Context, _ goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
					return goidc.TokenExchangeResult{
						Subject: "token_subject",
						Actor: &goidc.Actor{
							Subject: "actor_sub",
							Issuer:  "https://actor-issuer.com",
						},
					}, nil
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.Actor == nil {
					t.Fatal("grant.Actor is nil")
				}
				if grant.Actor.Subject != "actor_sub" {
					t.Errorf("grant.Actor.Subject = %q, want %q", grant.Actor.Subject, "actor_sub")
				}
				if grant.Actor.Issuer != "https://actor-issuer.com" {
					t.Errorf("grant.Actor.Issuer = %q, want %q", grant.Actor.Issuer, "https://actor-issuer.com")
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       "token_subject",
					"client_id": c.ID,
					"scope":     grant.Scopes,
					"grant_id":  grant.ID,
					"act": map[string]any{
						"sub": "actor_sub",
						"iss": "https://actor-issuer.com",
					},
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "nested actor chain",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.TokenExchangeHandleFunc = func(_ context.Context, _ goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
					return goidc.TokenExchangeResult{
						Subject: "token_subject",
						Actor: &goidc.Actor{
							Subject: "actor_b",
							Actor: &goidc.Actor{
								Subject: "actor_a",
							},
						},
					}, nil
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.Actor == nil || grant.Actor.Actor == nil {
					t.Fatal("expected nested actor chain")
				}
				if grant.Actor.Subject != "actor_b" {
					t.Errorf("grant.Actor.Subject = %q, want %q", grant.Actor.Subject, "actor_b")
				}
				if grant.Actor.Actor.Subject != "actor_a" {
					t.Errorf("grant.Actor.Actor.Subject = %q, want %q", grant.Actor.Actor.Subject, "actor_a")
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				actClaim, ok := claims["act"]
				if !ok {
					t.Fatal("act claim missing from JWT")
				}
				actMap, ok := actClaim.(map[string]any)
				if !ok {
					t.Fatal("act claim is not a map")
				}
				if actMap["sub"] != "actor_b" {
					t.Errorf("act.sub = %q, want %q", actMap["sub"], "actor_b")
				}
				innerAct, ok := actMap["act"].(map[string]any)
				if !ok {
					t.Fatal("act.act is not a map")
				}
				if innerAct["sub"] != "actor_a" {
					t.Errorf("act.act.sub = %q, want %q", innerAct["sub"], "actor_a")
				}
			},
		},
		{
			name: "with actor token",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.actorToken = "actor_token_value"
				req.actorTokenType = goidc.TokenTypeIdentifierAccessToken
				ctx.TokenExchangeHandleFunc = func(_ context.Context, req goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
					if req.ActorToken != "actor_token_value" {
						return goidc.TokenExchangeResult{}, errors.New("expected actor token")
					}
					if req.ActorTokenType != goidc.TokenTypeIdentifierAccessToken {
						return goidc.TokenExchangeResult{}, errors.New("expected actor token type")
					}
					return goidc.TokenExchangeResult{
						Subject: "token_subject",
						Actor:   &goidc.Actor{Subject: "the_actor"},
					}, nil
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				if resp.AccessToken == "" {
					t.Error("resp.AccessToken is empty")
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].Actor == nil || grants[0].Actor.Subject != "the_actor" {
					t.Errorf("grant.Actor = %v, want actor with sub 'the_actor'", grants[0].Actor)
				}
			},
		},
		{
			name: "handler receives request fields",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.Resources = []string{"https://resource.com"}
				req.resources = []string{"https://resource.com"}
				req.audience = []string{"audience1"}
				req.requestedTokenType = goidc.TokenTypeIdentifierAccessToken
				ctx.TokenExchangeHandleFunc = func(_ context.Context, r goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
					if r.SubjectToken != "subject_token_value" {
						return goidc.TokenExchangeResult{}, errors.New("wrong subject token")
					}
					if r.SubjectTokenType != goidc.TokenTypeIdentifierAccessToken {
						return goidc.TokenExchangeResult{}, errors.New("wrong subject token type")
					}
					if r.RequestedTokenType != goidc.TokenTypeIdentifierAccessToken {
						return goidc.TokenExchangeResult{}, errors.New("wrong requested token type")
					}
					if len(r.Audience) != 1 || r.Audience[0] != "audience1" {
						return goidc.TokenExchangeResult{}, errors.New("wrong audience")
					}
					if len(r.Resource) != 1 || r.Resource[0] != "https://resource.com" {
						return goidc.TokenExchangeResult{}, errors.New("wrong resource")
					}
					return goidc.TokenExchangeResult{Subject: "token_subject"}, nil
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				if resp.AccessToken == "" {
					t.Error("resp.AccessToken is empty")
				}
			},
		},
		{
			name: "no client identified",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.Request.PostForm = map[string][]string{}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].ClientID != "" {
					t.Errorf("grant.ClientID = %q, want empty", grants[0].ClientID)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":   ctx.Issuer(),
					"sub":   "token_subject",
					"scope": grants[0].Scopes,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat" || k == "grant_id"
				})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "client auth required",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.TokenExchangeClientAuthnIsRequired = true
				ctx.Request.PostForm = map[string][]string{}
				return ctx, req, c
			},
			wantErr: client.ErrClientNotIdentified,
		},
		{
			name: "invalid client auth",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "client lacks grant type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeUnauthorizedClient,
		},
		{
			name: "missing subject_token",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.subjectToken = ""
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing subject_token_type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.subjectTokenType = ""
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid subject_token_type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.subjectTokenType = "invalid_type"
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "actor_token without actor_token_type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.actorToken = "actor_token_value"
				req.actorTokenType = ""
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid actor_token_type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.actorToken = "actor_token_value"
				req.actorTokenType = "invalid_type"
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid requested_token_type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.requestedTokenType = "invalid_type"
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "requested_token_type SAML not issuable",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.requestedTokenType = goidc.TokenTypeIdentifierSAML2
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid scope",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.scopes = "unknown_scope"
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidScope,
		},
		{
			name: "handler error",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.TokenExchangeHandleFunc = func(context.Context, goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
					return goidc.TokenExchangeResult{}, goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid subject token")
				}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidGrant,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, c := test.setup()

			// When.
			resp, err := generateToken(ctx, req)

			// Then.
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("got %v, want %v", err, test.wantErr)
				}
				return
			}

			if test.wantErrCode != "" {
				if err == nil {
					t.Fatalf("got no error, wantErrCode=%v", test.wantErrCode)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErrCode {
					t.Fatalf("got %v, want error code %s", err, test.wantErrCode)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c)
			}
		})
	}
}
