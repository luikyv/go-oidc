package authorize

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestPushAuth(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, *goidc.Client) {
		t.Helper()

		ctx := oidctest.NewContext(t)
		manager := oidctest.Manager(t, ctx)
		ctx.AuthManager = manager
		ctx.PARManager = manager
		ctx.AuthSessionIDFunc = func(_ context.Context) string {
			return "random_authn_session_id"
		}
		ctx.PARIDFunc = func(_ context.Context) string {
			return "random_pushed_auth_req_id"
		}
		ctx.PARLifetimeSecs = 60
		c, secret := oidctest.NewClient(t)
		ctx.StaticClients = append(ctx.StaticClients, c)

		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		return ctx, c
	}

	type federationOptions struct {
		redirectURI       string
		registrationTypes []goidc.ClientRegistrationType
	}
	setupFederation := func(t *testing.T, opts federationOptions) (oidc.Context, string, int) {
		t.Helper()

		redirectURI := federationDefaultRedirectURI
		if opts.redirectURI != "" {
			redirectURI = opts.redirectURI
		}
		registrationTypes := []goidc.ClientRegistrationType{
			goidc.ClientRegistrationTypeAutomatic,
		}
		if len(opts.registrationTypes) > 0 {
			registrationTypes = opts.registrationTypes
		}

		ctx := oidctest.NewContext(t)
		manager := oidctest.Manager(t, ctx)
		ctx.AuthManager = manager
		ctx.PARManager = manager
		ctx.OpenIDFedIsEnabled = true
		ctx.OpenIDFedManager = manager
		ctx.OpenIDFedTrustedAnchors = []string{federationTrustAnchorID}
		ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeAutomatic}
		ctx.OpenIDFedSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
		ctx.OpenIDFedDefaultSigAlg = goidc.RS256
		ctx.OpenIDFedJWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{federationOPJWK}}, nil
		}
		ctx.JARIsEnabled = true
		ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
		ctx.AuthSessionIDFunc = func(_ context.Context) string {
			return "random_authn_session_id"
		}
		ctx.PARIDFunc = func(_ context.Context) string {
			return "random_pushed_auth_req_id"
		}
		ctx.PARLifetimeSecs = 60

		now := timeutil.TimestampNow()
		expiresAt := now + 500
		clientConfig := oidctest.SignWithOptions(t, map[string]any{
			"iss": federationClientID,
			"sub": federationClientID,
			"iat": now,
			"exp": now + 600,
			"jwks": jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{federationClientJWK.Public()},
			},
			"metadata": map[string]any{
				"openid_relying_party": map[string]any{
					"redirect_uris":              []string{redirectURI},
					"grant_types":                []string{"authorization_code"},
					"response_types":             []string{"code"},
					"scope":                      federationScopeIDs,
					"token_endpoint_auth_method": "private_key_jwt",
					"request_object_signing_alg": "RS256",
					"jwks": jose.JSONWebKeySet{
						Keys: []jose.JSONWebKey{federationClientJWK.Public()},
					},
					"client_registration_types": registrationTypes,
				},
			},
			"authority_hints": []string{federationTrustAnchorID},
		}, federationClientJWK, (&jose.SignerOptions{}).WithType("entity-statement+jwt"))
		subordinate := oidctest.SignWithOptions(t, map[string]any{
			"iss": federationTrustAnchorID,
			"sub": federationClientID,
			"iat": now,
			"exp": expiresAt,
			"jwks": jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{federationClientJWK.Public()},
			},
		}, federationTrustAnchorJWK, (&jose.SignerOptions{}).WithType("entity-statement+jwt"))
		trustChain := []string{clientConfig, subordinate}

		ctx.OpenIDFedHTTPClientFunc = func(context.Context) *http.Client {
			return &http.Client{
				Transport: federationRoundTripper{
					responses: map[string]func() *http.Response{
						federationTrustAnchorID + "/.well-known/openid-federation": func() *http.Response {
							anchorConfig := oidctest.SignWithOptions(t, map[string]any{
								"iss": federationTrustAnchorID,
								"sub": federationTrustAnchorID,
								"iat": now,
								"exp": now + 700,
								"jwks": jose.JSONWebKeySet{
									Keys: []jose.JSONWebKey{federationTrustAnchorJWK.Public()},
								},
								"metadata": map[string]any{
									"federation_entity": map[string]any{
										"federation_fetch_endpoint": federationTrustAnchorID + "/fetch",
									},
								},
							}, federationTrustAnchorJWK, (&jose.SignerOptions{}).WithType("entity-statement+jwt"))

							return &http.Response{
								StatusCode: http.StatusOK,
								Header: http.Header{
									"Content-Type": []string{"application/entity-statement+jwt"},
								},
								Body: io.NopCloser(bytes.NewBufferString(anchorConfig)),
							}
						},
					},
				},
			}
		}

		requestObject := oidctest.SignWithOptions(t, map[string]any{
			goidc.ClaimIssuer:   federationClientID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + 60,
			"client_id":         federationClientID,
			"redirect_uri":      redirectURI,
			"scope":             federationScopeIDs,
			"response_type":     goidc.ResponseTypeCode,
		}, federationClientJWK, (&jose.SignerOptions{}).WithHeader("trust_chain", trustChain))

		return ctx, requestObject, expiresAt
	}

	tests := []struct {
		name        string
		setup       func(*testing.T) (oidc.Context, request, *goidc.Client)
		wantErr     goidc.ErrorCode
		validate    func(*testing.T, oidc.Context, parResponse, *goidc.Client)
		validateErr func(*testing.T, error, oidc.Context, *goidc.Client)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				if session.ID == "" {
					t.Fatal("expected session id to be set")
				}
				if session.ClientID != client.ID {
					t.Errorf("ClientID = %q, want %q", session.ClientID, client.ID)
				}
				if session.ExpiresAt == 0 {
					t.Fatal("expected session expiration to be set")
				}
				if session.CreatedAt == 0 {
					t.Fatal("expected session creation time to be set")
				}

				wantSession := goidc.AuthnSession{
					ID:              session.ID,
					PushedAuthReqID: session.PushedAuthReqID,
					ClientID:        client.ID,
					ExpiresAt:       session.ExpiresAt,
					CreatedAt:       session.CreatedAt,
					Store:           session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := parResponse{
					RequestURI: parRequestURIPrefix + session.PushedAuthReqID,
					ExpiresIn:  ctx.PARLifetimeSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "with jar",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.JARIsEnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}

				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				client.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{privateJWK.Public()},
				}

				now := timeutil.TimestampNow()
				requestObject := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   client.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + 10,
					"client_id":         client.ID,
					"redirect_uri":      client.RedirectURIs[0],
					"scope":             client.ScopeIDs,
					"response_type":     goidc.ResponseTypeCode,
				}, privateJWK)

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:              session.ID,
					PushedAuthReqID: session.PushedAuthReqID,
					ClientID:        client.ID,
					ExpiresAt:       session.ExpiresAt,
					CreatedAt:       session.CreatedAt,
					Store:           session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := parResponse{
					RequestURI: parRequestURIPrefix + session.PushedAuthReqID,
					ExpiresIn:  ctx.PARLifetimeSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "jar required without request object",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.JARIsEnabled = true
				ctx.JARIsRequired = true
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				return ctx, req, client
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
			},
		},
		{
			name: "invalid jar request object",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.JARIsEnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				client.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{privateJWK.Public()},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: "not-a-jwt",
					},
				}
				return ctx, req, client
			},
			wantErr: goidc.ErrorCodeInvalidResquestObject,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
			},
		},
		{
			name: "jar validation error",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.JARIsEnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}

				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				client.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{privateJWK.Public()},
				}

				now := timeutil.TimestampNow()
				requestObject := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   client.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + 10,
					"client_id":         "other-client",
					"redirect_uri":      client.RedirectURIs[0],
					"scope":             client.ScopeIDs,
					"response_type":     goidc.ResponseTypeCode,
				}, privateJWK)

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, client
			},
			wantErr: goidc.ErrorCodeInvalidResquestObject,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
			},
		},
		{
			name: "unauthenticated client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {client.ID},
					"client_secret": {"invalid_secret"},
				}
				req := request{}
				return ctx, req, client
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 0 {
					t.Fatalf("len(sessions) = %d, want 0", len(sessions))
				}
			},
		},
		{
			name: "federation automatic registration",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, requestObject, expiresAt := setupFederation(t, federationOptions{})
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_federation_par_jti",
					}, federationClientJWK)},
				}

				expected := &goidc.Client{
					ID:        federationClientID,
					ExpiresAt: expiresAt,
					Federation: &struct {
						TrustAnchor string   `json:"trust_anchor"`
						TrustMarks  []string `json:"trust_marks,omitempty"`
					}{
						TrustAnchor: federationTrustAnchorID,
					},
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{federationDefaultRedirectURI},
					},
				}
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, expected
			},
			validate: func(t *testing.T, ctx oidc.Context, resp parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]
				if session.ClientID != client.ID {
					t.Fatalf("ClientID = %q, want %q", session.ClientID, client.ID)
				}
				if session.PushedAuthReqID == "" {
					t.Fatal("expected pushed auth request id to be set")
				}
				if session.RedirectURI != client.RedirectURIs[0] {
					t.Fatalf("RedirectURI = %q, want %q", session.RedirectURI, client.RedirectURIs[0])
				}

				saved, err := ctx.OpenIDFedClient(client.ID)
				if err != nil {
					t.Fatalf("could not load saved federation client: %v", err)
				}
				if saved.Federation == nil {
					t.Fatal("expected federation metadata to be populated")
				}
				if saved.Federation.TrustAnchor != client.Federation.TrustAnchor {
					t.Fatalf("TrustAnchor = %q, want %q", saved.Federation.TrustAnchor, client.Federation.TrustAnchor)
				}
				if saved.ExpiresAt != client.ExpiresAt {
					t.Fatalf("ExpiresAt = %d, want %d", saved.ExpiresAt, client.ExpiresAt)
				}

				wantResp := parResponse{
					RequestURI: parRequestURIPrefix + session.PushedAuthReqID,
					ExpiresIn:  ctx.PARLifetimeSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "federation expired cached client refresh",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				redirectURI := "https://client.example.com/updated-callback"
				ctx, requestObject, expiresAt := setupFederation(t, federationOptions{
					redirectURI: redirectURI,
				})
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_federation_par_jti",
					}, federationClientJWK)},
				}
				if err := ctx.OpenIDFedSaveClient(&goidc.Client{
					ID:        federationClientID,
					CreatedAt: timeutil.TimestampNow() - 120,
					ExpiresAt: timeutil.TimestampNow() - 60,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{"https://client.example.com/stale-callback"},
						ScopeIDs:     federationScopeIDs,
						GrantTypes:   []goidc.GrantType{goidc.GrantAuthorizationCode},
						ResponseTypes: []goidc.ResponseType{
							goidc.ResponseTypeCode,
						},
						JWKS:             &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{federationClientJWK.Public()}},
						TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
					},
				}); err != nil {
					t.Fatalf("could not save expired federation client: %v", err)
				}

				expected := &goidc.Client{
					ID:        federationClientID,
					ExpiresAt: expiresAt,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{redirectURI},
					},
				}
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, expected
			},
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].RedirectURI != client.RedirectURIs[0] {
					t.Fatalf("RedirectURI = %q, want %q", sessions[0].RedirectURI, client.RedirectURIs[0])
				}

				saved, err := ctx.OpenIDFedClient(client.ID)
				if err != nil {
					t.Fatalf("could not load refreshed federation client: %v", err)
				}
				if diff := cmp.Diff(saved.RedirectURIs, client.RedirectURIs); diff != "" {
					t.Fatal(diff)
				}
				if saved.ExpiresAt != client.ExpiresAt {
					t.Fatalf("ExpiresAt = %d, want %d", saved.ExpiresAt, client.ExpiresAt)
				}
			},
		},
		{
			name: "federation valid cached client reuse",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, requestObject, _ := setupFederation(t, federationOptions{})
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.OpenIDFedHTTPClientFunc = func(context.Context) *http.Client {
					return &http.Client{Transport: federationRoundTripper{responses: map[string]func() *http.Response{}}}
				}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_federation_par_jti",
					}, federationClientJWK)},
				}
				cached := &goidc.Client{
					ID:        federationClientID,
					CreatedAt: timeutil.TimestampNow() - 60,
					ExpiresAt: timeutil.TimestampNow() + 600,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{federationDefaultRedirectURI},
						ScopeIDs:     federationScopeIDs,
						GrantTypes:   []goidc.GrantType{goidc.GrantAuthorizationCode},
						ResponseTypes: []goidc.ResponseType{
							goidc.ResponseTypeCode,
						},
						JWKS:             &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{federationClientJWK.Public()}},
						TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
						ClientRegistrationTypes: []goidc.ClientRegistrationType{
							goidc.ClientRegistrationTypeAutomatic,
						},
					},
					Federation: &struct {
						TrustAnchor string   `json:"trust_anchor"`
						TrustMarks  []string `json:"trust_marks,omitempty"`
					}{
						TrustAnchor: federationTrustAnchorID,
					},
				}
				if err := ctx.OpenIDFedSaveClient(cached); err != nil {
					t.Fatalf("could not save cached federation client: %v", err)
				}

				expected := &goidc.Client{
					ID: federationClientID,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{federationDefaultRedirectURI},
					},
				}
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, expected
			},
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].ClientID != client.ID {
					t.Fatalf("ClientID = %q, want %q", sessions[0].ClientID, client.ID)
				}

				clients := oidctest.Clients(t, ctx)
				if len(clients) != 1 {
					t.Fatalf("len(clients) = %d, want 1", len(clients))
				}
				if clients[0].RedirectURIs[0] != client.RedirectURIs[0] {
					t.Fatalf("RedirectURI = %q, want %q", clients[0].RedirectURIs[0], client.RedirectURIs[0])
				}
			},
		},
		{
			name: "federation automatic registration disabled does not resolve unknown url client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				manager := oidctest.Manager(t, ctx)
				ctx.AuthManager = manager
				ctx.PARManager = manager
				ctx.PARIDFunc = func(_ context.Context) string {
					return "random_pushed_auth_req_id"
				}
				ctx.OpenIDFedIsEnabled = true
				ctx.OpenIDFedManager = manager
				ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeExplicit}
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_federation_par_jti",
					}, federationClientJWK)},
				}
				return ctx, request{}, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validateErr: func(t *testing.T, err error, ctx oidc.Context, _ *goidc.Client) {
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("expected wrapped not found error, got %v", err)
				}
				if got := err.Error(); got != "invalid_client invalid client: not found" {
					t.Fatalf("error = %q, want %q", got, "invalid_client invalid client: not found")
				}
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
			},
		},
		{
			name: "federation automatic registration ignores unknown non url client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				manager := oidctest.Manager(t, ctx)
				ctx.AuthManager = manager
				ctx.PARManager = manager
				ctx.PARIDFunc = func(_ context.Context) string {
					return "random_pushed_auth_req_id"
				}
				ctx.OpenIDFedIsEnabled = true
				ctx.OpenIDFedManager = manager
				ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeAutomatic}
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {"unknown-client"},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   "unknown-client",
						goidc.ClaimSubject:  "unknown-client",
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_unknown_federation_par_jti",
					}, oidctest.PrivateRS256JWK(t, "unknown_client_key", goidc.KeyUsageSignature))},
				}
				return ctx, request{}, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validateErr: func(t *testing.T, err error, ctx oidc.Context, _ *goidc.Client) {
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("expected wrapped not found error, got %v", err)
				}
				if got := err.Error(); got != "invalid_client invalid client: not found" {
					t.Fatalf("error = %q, want %q", got, "invalid_client invalid client: not found")
				}
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
			},
		},
		{
			name: "federation automatic registration rejects entity without automatic type",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, requestObject, _ := setupFederation(t, federationOptions{
					registrationTypes: []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeExplicit},
				})
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_federation_par_jti",
					}, federationClientJWK)},
				}
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, nil
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
			},
		},
		{
			name: "federation automatic registration rejects invalid private key jwt",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, requestObject, _ := setupFederation(t, federationOptions{})
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_invalid_federation_par_jti",
					}, oidctest.PrivateRS256JWK(t, "invalid_federation_client_key", goidc.KeyUsageSignature))},
				}
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
				if len(oidctest.Clients(t, ctx)) != 0 {
					t.Fatal("expected no federation client to be persisted")
				}
			},
		},
		{
			name: "federation automatic registration rejects invalid jar request object",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, _, _ := setupFederation(t, federationOptions{})
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {federationClientID},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   federationClientID,
						goidc.ClaimSubject:  federationClientID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: timeutil.TimestampNow(),
						goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
						"jti":               "random_federation_par_jti",
					}, federationClientJWK)},
				}
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: "not-a-jwt",
					},
				}
				return ctx, req, nil
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
				if len(oidctest.AuthnSessions(t, ctx)) != 0 {
					t.Fatal("expected no sessions to be created")
				}
				if len(oidctest.Clients(t, ctx)) != 0 {
					t.Fatal("expected no federation client to be persisted")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, client := test.setup(t)

			// When.
			resp, err := pushAuth(ctx, req)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				if test.validateErr != nil {
					test.validateErr(t, err, ctx, client)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, client)
			}
		})
	}
}
