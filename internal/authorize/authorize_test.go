package authorize

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	federationClientID           = "https://client.example.com"
	federationTrustAnchorID      = "https://trust-anchor.example.com"
	federationDefaultRedirectURI = "https://client.example.com/callback"
	federationScopeIDs           = "openid scope1 scope2"
)

var (
	federationClientKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	federationClientJWK    = goidc.JSONWebKey{
		KeyID:     "fed_client_key",
		Key:       federationClientKey,
		Algorithm: "RS256",
	}

	federationTrustAnchorKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	federationTrustAnchorJWK    = goidc.JSONWebKey{
		KeyID:     "fed_anchor_key",
		Key:       federationTrustAnchorKey,
		Algorithm: "RS256",
	}

	federationOPKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	federationOPJWK    = goidc.JSONWebKey{
		KeyID:     "fed_op_key",
		Key:       federationOPKey,
		Algorithm: "RS256",
	}
)

func TestInitAuth(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, *goidc.Client) {
		t.Helper()
		return setUpAuth(t)
	}

	type federationAuthOptions struct {
		redirectURI       string
		registrationTypes []goidc.ClientRegistrationType
	}
	setUpFederationAuth := func(t *testing.T, opts federationAuthOptions) (oidc.Context, string, int) {
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
		ctx.AuthManager = oidctest.Manager(t, ctx)
		ctx.OpenIDFedIsEnabled = true
		ctx.OpenIDFedManager = oidctest.Manager(t, ctx)
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
		ctx.AuthCodeFunc = func(_ context.Context) string {
			return "random_auth_code"
		}

		ctx.Policies = []goidc.AuthnPolicy{
			goidc.NewPolicy(
				"random_policy_id",
				func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
					return true
				},
				func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					as.Subject = "random_subject"
					as.Username = "random_username"
					as.GrantedScopes = as.Scopes
					as.GrantedAuthDetails = as.AuthDetails
					as.GrantedResources = as.Resources
					return goidc.StatusSuccess, nil
				},
			),
		}

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
		setup       func(*testing.T) (oidc.Context, *goidc.Client, request)
		wantErr     goidc.ErrorCode
		validate    func(*testing.T, oidc.Context, *goidc.Client, request)
		validateErr func(*testing.T, error, oidc.Context, *goidc.Client, request)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
						ResponseMode: goidc.ResponseModeFragment,
						Nonce:        "random_nonce",
						State:        "random_state",
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, req request) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusSuccess {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				grant := grants[0]
				if grant.AuthCode == "" {
					t.Fatal("expected authorization code to be persisted in the grant")
				}
				if grant.Subject != "random_subject" {
					t.Errorf("Subject = %q, want %q", grant.Subject, "random_subject")
				}
				if grant.Username != "random_username" {
					t.Errorf("Username = %q, want %q", grant.Username, "random_username")
				}
				if diff := cmp.Diff(grant.AuthParams, req.AuthorizationParameters, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}

				redirectParams, err := url.ParseQuery(redirectURL.Fragment)
				if err != nil {
					t.Fatalf("could not parse redirect params: %v", err)
				}
				if redirectParams.Get("code") != grant.AuthCode {
					t.Errorf("code = %q, want %q", redirectParams.Get("code"), grant.AuthCode)
				}
				if redirectParams.Get("state") != req.State {
					t.Errorf("state = %q, want %q", redirectParams.Get("state"), req.State)
				}

				idToken := redirectParams.Get("id_token")
				if idToken == "" {
					t.Fatal("expected id_token in redirect response")
				}

				claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				now := timeutil.TimestampNow()
				wantClaims := map[string]any{
					"iss":    ctx.Issuer(),
					"sub":    grant.Subject,
					"aud":    client.ID,
					"exp":    float64(now + ctx.IDTokenLifetimeSecs),
					"iat":    float64(now),
					"nonce":  req.Nonce,
					"c_hash": halfHash(grant.AuthCode),
					"s_hash": halfHash(req.State),
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "jar",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.JARIsEnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}

				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				client.JWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{privateJWK.Public()}}

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
						Scopes:        client.ScopeIDs,
						ResponseType:  goidc.ResponseTypeCode,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ request) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusSuccess {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				grant := grants[0]
				if grant.AuthCode == "" {
					t.Fatal("expected authorization code to be persisted in the grant")
				}
				wantParams := goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					Scopes:       client.ScopeIDs,
					ResponseType: goidc.ResponseTypeCode,
				}
				if diff := cmp.Diff(grant.AuthParams, wantParams, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				if redirectURL.Query().Get("code") != grant.AuthCode {
					t.Errorf("code = %q, want %q", redirectURL.Query().Get("code"), grant.AuthCode)
				}
			},
		},
		{
			name: "jarm",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.JARMIsEnabled = true
				ctx.JARMLifetimeSecs = 60
				ctx.JARMSigAlgDefault = goidc.SignatureAlgorithm(oidctest.PrivateJWKS(t, ctx).Keys[0].Algorithm)
				ctx.ResponseModes = append(ctx.ResponseModes, goidc.ResponseModeJWT)

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeJWT,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ request) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				grant := grants[0]
				if grant.AuthCode == "" {
					t.Fatal("expected authorization code to be persisted in the grant")
				}

				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}

				responseObject := redirectURL.Query().Get("response")
				if responseObject == "" {
					t.Fatal("expected response object in redirect response")
				}

				claims, err := oidctest.SafeClaims(responseObject, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				now := timeutil.TimestampNow()
				wantClaims := map[string]any{
					"iss":  ctx.Issuer(),
					"aud":  client.ID,
					"exp":  float64(now + ctx.JARMLifetimeSecs),
					"iat":  float64(now),
					"code": grant.AuthCode,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "resource indicators",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.Resources = []string{"https://resource1.com", "https://resource2.com"}
				ctx.Policies[0].Authenticate = func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					as.Subject = "random_subject"
					as.Username = "random_username"
					as.GrantedScopes = as.Scopes
					as.GrantedResources = []string{"https://resource1.com"}
					return goidc.StatusSuccess, nil
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
						ResponseMode: goidc.ResponseModeFragment,
						Nonce:        "random_nonce",
						State:        "random_state",
					},
				}
				req.Resources = []string{"https://resource1.com", "https://resource2.com"}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, req request) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				grant := grants[0]
				wantResources := goidc.Resources{"https://resource1.com"}
				if diff := cmp.Diff(grant.Resources, wantResources); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(grant.AuthParams.Resources, req.Resources); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "id token hint",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.Policies[0].Authenticate = func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					return goidc.StatusPending, nil
				}

				idToken, err := ctx.Sign(map[string]any{
					goidc.ClaimIssuer:   ctx.Issuer(),
					goidc.ClaimAudience: client.ID,
					goidc.ClaimSubject:  "random_user",
				}, ctx.IDTokenDefaultSigAlg, nil)
				if err != nil {
					t.Fatalf("could not sign id token hint: %v", err)
				}

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
						Nonce:        "random_nonce",
						IDTokenHint:  idToken,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, req request) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}

				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}

				session := sessions[0]
				if session.ID == "" {
					t.Fatal("expected session id to be set")
				}
				if session.PolicyID != ctx.Policies[0].ID {
					t.Errorf("PolicyID = %q, want %q", session.PolicyID, ctx.Policies[0].ID)
				}
				if session.ExpiresAt == 0 {
					t.Fatal("expected session expiration to be set")
				}
				if session.CreatedAt == 0 {
					t.Fatal("expected session creation time to be set")
				}
				if session.ClientID != client.ID {
					t.Errorf("ClientID = %q, want %q", session.ClientID, client.ID)
				}
				if diff := cmp.Diff(session.AuthorizationParameters, req.AuthorizationParameters, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantClaims := map[string]any{
					"sub": "random_user",
					"iss": ctx.Issuer(),
					"aud": client.ID,
				}
				if diff := cmp.Diff(session.IDTokenHintClaims, wantClaims); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				t.Helper()
				ctx := oidctest.NewContext(t)
				return ctx, nil, request{ClientID: "invalid_client_id"}
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "federation automatic registration disabled does not resolve unknown url client",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				t.Helper()
				ctx := oidctest.NewContext(t)
				ctx.OpenIDFedIsEnabled = true
				ctx.OpenIDFedManager = oidctest.Manager(t, ctx)
				ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeExplicit}
				return ctx, nil, request{ClientID: "https://unknown-client.example.com"}
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validateErr: func(t *testing.T, err error, _ oidc.Context, _ *goidc.Client, _ request) {
				t.Helper()
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("expected wrapped not found error, got %v", err)
				}
				if got := err.Error(); got != "invalid_client invalid client_id: could not load the client: not found" {
					t.Fatalf("error = %q, want %q", got, "invalid_client invalid client_id: could not load the client: not found")
				}
			},
		},
		{
			name: "federation automatic registration ignores unknown non url client",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				t.Helper()
				ctx := oidctest.NewContext(t)
				ctx.OpenIDFedIsEnabled = true
				ctx.OpenIDFedManager = oidctest.Manager(t, ctx)
				ctx.OpenIDFedClientRegTypes = []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeAutomatic}
				return ctx, nil, request{ClientID: "unknown-client"}
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validateErr: func(t *testing.T, err error, _ oidc.Context, _ *goidc.Client, _ request) {
				t.Helper()
				if !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("expected wrapped not found error, got %v", err)
				}
				if got := err.Error(); got != "invalid_client invalid client_id: could not load the client: not found" {
					t.Fatalf("error = %q, want %q", got, "invalid_client invalid client_id: could not load the client: not found")
				}
			},
		},
		{
			name: "invalid redirect uri",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  "https://invalid.com",
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCodeAndIDToken,
						ResponseMode: goidc.ResponseModeFragment,
						Nonce:        "random_nonce",
						State:        "random_state",
					},
				}
				return ctx, client, req
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid scope",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       "invalid_scope",
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				if redirectURL.Query().Get("error") != string(goidc.ErrorCodeInvalidScope) {
					t.Errorf("error = %q, want %q", redirectURL.Query().Get("error"), goidc.ErrorCodeInvalidScope)
				}
			},
		},
		{
			name: "invalid response type",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeIDToken,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				redirectParams, err := url.ParseQuery(redirectURL.Fragment)
				if err != nil {
					t.Fatalf("could not parse redirect params: %v", err)
				}
				if redirectParams.Get("error") != string(goidc.ErrorCodeInvalidRequest) {
					t.Errorf("error = %q, want %q", redirectParams.Get("error"), goidc.ErrorCodeInvalidRequest)
				}
			},
		},
		{
			name: "no policy available",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.Policies = nil
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				if redirectURL.Query().Get("error") != string(goidc.ErrorCodeInvalidRequest) {
					t.Errorf("error = %q, want %q", redirectURL.Query().Get("error"), goidc.ErrorCodeInvalidRequest)
				}
			},
		},
		{
			name: "authn failed",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.Policies = []goidc.AuthnPolicy{
					goidc.NewPolicy(
						"policy_id",
						func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
							return true
						},
						func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
							return goidc.StatusFailure, nil
						},
					),
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				if redirectURL.Query().Get("error") != string(goidc.ErrorCodeAccessDenied) {
					t.Errorf("error = %q, want %q", redirectURL.Query().Get("error"), goidc.ErrorCodeAccessDenied)
				}

				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusFailure {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusFailure)
				}
			},
		},
		{
			name: "authn in progress",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.Policies = []goidc.AuthnPolicy{
					goidc.NewPolicy(
						"policy_id",
						func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
							return true
						},
						func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
							return goidc.StatusPending, nil
						},
					),
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, req request) {
				statusCode := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
				if statusCode != http.StatusOK {
					t.Errorf("statusCode = %d, want %d", statusCode, http.StatusOK)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}

				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}

				session := sessions[0]
				if session.ID == "" {
					t.Fatal("expected session id to be set")
				}
				if session.PolicyID != "policy_id" {
					t.Errorf("PolicyID = %q, want %q", session.PolicyID, "policy_id")
				}
				if session.ExpiresAt == 0 {
					t.Fatal("expected session expiration to be set")
				}
				if session.CreatedAt == 0 {
					t.Fatal("expected session creation time to be set")
				}
				if session.ClientID != client.ID {
					t.Errorf("ClientID = %q, want %q", session.ClientID, client.ID)
				}
				if diff := cmp.Diff(session.AuthorizationParameters, req.AuthorizationParameters, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "verifiable credentials populate session vc info",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.VCIsEnabled = true
				ctx.Policies = []goidc.AuthnPolicy{
					goidc.NewPolicy(
						"policy_id",
						func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
							return true
						},
						func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
							return goidc.StatusPending, nil
						},
					),
				}
				ctx.VCIssuers = []goidc.VCIssuer{
					{
						ID: "https://issuer.example.com",
						Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
							"cred1": {Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				ctx.Scopes = append(ctx.Scopes, goidc.NewScope("vc_scope1"))
				client.ScopeIDs = "openid vc_scope1"
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       "openid vc_scope1",
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, req request) {
				statusCode := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
				if statusCode != http.StatusOK {
					t.Errorf("statusCode = %d, want %d", statusCode, http.StatusOK)
				}

				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}

				session := sessions[0]
				if session.ClientID != client.ID {
					t.Errorf("ClientID = %q, want %q", session.ClientID, client.ID)
				}
				if diff := cmp.Diff(session.AuthorizationParameters, req.AuthorizationParameters, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}
				if session.VCInfo == nil {
					t.Fatal("expected VCInfo to be populated")
				}
				if session.VCInfo.Issuer != "https://issuer.example.com" {
					t.Fatalf("VCInfo.Issuer = %q, want %q", session.VCInfo.Issuer, "https://issuer.example.com")
				}
				if diff := cmp.Diff(session.VCInfo.ConfigurationIDs, []goidc.VCConfigurationID{"cred1"}); diff != "" {
					t.Fatal(diff)
				}
			},
		},
		{
			name: "verifiable credentials validation error redirects",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.VCIsEnabled = true
				ctx.RARIsEnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{goidc.AuthDetailTypeOpenIDCredential}
				ctx.VCIssuers = []goidc.VCIssuer{
					{
						ID: "https://issuer.example.com",
						Configurations: map[goidc.VCConfigurationID]goidc.VCConfiguration{
							"cred1": {Scope: goidc.NewScope("vc_scope1")},
						},
					},
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       "openid",
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
						AuthDetails: []goidc.AuthDetail{
							{
								"type":                        string(goidc.AuthDetailTypeOpenIDCredential),
								"credential_configuration_id": "unknown_cred",
								"locations":                   []any{"https://issuer.example.com"},
							},
						},
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				if redirectURL.Query().Get("error") != string(goidc.ErrorCodeInvalidRequest) {
					t.Errorf("error = %q, want %q", redirectURL.Query().Get("error"), goidc.ErrorCodeInvalidRequest)
				}
				if redirectURL.Query().Get("error_description") != "invalid verifiable credentials request" {
					t.Errorf("error_description = %q, want %q", redirectURL.Query().Get("error_description"), "invalid verifiable credentials request")
				}

				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 0 {
					t.Fatalf("len(sessions) = %d, want 0", len(sessions))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "par",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, client := setup(t)
				ctx.PARIsEnabled = true
				ctx.PARManager = ctx.AuthManager.(goidc.PARManager)

				session := &goidc.AuthnSession{
					ID:              "random_par_session",
					PushedAuthReqID: "random_pushed_auth_req_id",
					ClientID:        client.ID,
					CreatedAt:       timeutil.TimestampNow(),
					ExpiresAt:       timeutil.TimestampNow() + 60,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
					},
					Store: make(map[string]any),
				}
				if err := ctx.AuthSaveSession(session); err != nil {
					t.Fatalf("could not save par session: %v", err)
				}

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestURI:   parRequestURIPrefix + session.PushedAuthReqID,
						ResponseType: goidc.ResponseTypeCode,
						Scopes:       client.ScopeIDs,
						State:        "random_state",
					},
				}
				return ctx, client, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ request) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusSuccess {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				grant := grants[0]
				if grant.AuthCode == "" {
					t.Fatal("expected authorization code to be persisted in the grant")
				}
				wantParams := goidc.AuthorizationParameters{
					RedirectURI:  client.RedirectURIs[0],
					Scopes:       client.ScopeIDs,
					ResponseType: goidc.ResponseTypeCode,
					State:        "random_state",
				}
				if diff := cmp.Diff(grant.AuthParams, wantParams, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				redirectURL, err := url.Parse(ctx.Response.Header().Get("Location"))
				if err != nil {
					t.Fatalf("could not parse redirect url: %v", err)
				}
				if redirectURL.Query().Get("code") != grant.AuthCode {
					t.Errorf("code = %q, want %q", redirectURL.Query().Get("code"), grant.AuthCode)
				}
			},
		},
		{
			name: "federation automatic registration",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, requestObject, expiresAt := setUpFederationAuth(t, federationAuthOptions{})
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
						Scopes:        federationScopeIDs,
						ResponseType:  goidc.ResponseTypeCode,
					},
				}
				return ctx, expected, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ request) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].ClientID != client.ID {
					t.Fatalf("ClientID = %q, want %q", grants[0].ClientID, client.ID)
				}
				if grants[0].AuthParams.RedirectURI != client.RedirectURIs[0] {
					t.Fatalf("RedirectURI = %q, want %q", grants[0].AuthParams.RedirectURI, client.RedirectURIs[0])
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
				if diff := cmp.Diff(saved.RedirectURIs, client.RedirectURIs); diff != "" {
					t.Fatal(diff)
				}
			},
		},
		{
			name: "federation expired cached client refresh",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				redirectURI := "https://client.example.com/updated-callback"
				ctx, requestObject, expiresAt := setUpFederationAuth(t, federationAuthOptions{
					redirectURI: "https://client.example.com/updated-callback",
				})
				expected := &goidc.Client{
					ID:        federationClientID,
					ExpiresAt: expiresAt,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{redirectURI},
					},
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

				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
						Scopes:        federationScopeIDs,
						ResponseType:  goidc.ResponseTypeCode,
					},
				}
				return ctx, expected, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ request) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].AuthParams.RedirectURI != client.RedirectURIs[0] {
					t.Fatalf("RedirectURI = %q, want %q", grants[0].AuthParams.RedirectURI, client.RedirectURIs[0])
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
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, _, _ := setUpFederationAuth(t, federationAuthOptions{})
				redirectURI := federationDefaultRedirectURI
				ctx.OpenIDFedHTTPClientFunc = func(context.Context) *http.Client {
					return &http.Client{Transport: federationRoundTripper{responses: map[string]func() *http.Response{}}}
				}

				expected := &goidc.Client{
					ID: federationClientID,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{redirectURI},
					},
				}
				cached := &goidc.Client{
					ID:        federationClientID,
					CreatedAt: timeutil.TimestampNow() - 60,
					ExpiresAt: timeutil.TimestampNow() + 600,
					ClientMeta: goidc.ClientMeta{
						RedirectURIs: []string{redirectURI},
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

				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  redirectURI,
						Scopes:       federationScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						State:        "state",
					},
				}
				return ctx, expected, req
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ request) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].ClientID != client.ID {
					t.Fatalf("ClientID = %q, want %q", grants[0].ClientID, client.ID)
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
			name: "federation automatic registration requires signed request authentication",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, _, _ := setUpFederationAuth(t, federationAuthOptions{})
				redirectURI := federationDefaultRedirectURI
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  redirectURI,
						Scopes:       federationScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				return ctx, nil, req
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				clients := oidctest.Clients(t, ctx)
				if len(clients) != 0 {
					t.Fatalf("len(clients) = %d, want 0", len(clients))
				}
			},
		},
		{
			name: "federation automatic registration rejects entity without automatic type",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, request) {
				ctx, requestObject, _ := setUpFederationAuth(t, federationAuthOptions{
					registrationTypes: []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeExplicit},
				})
				req := request{
					ClientID: federationClientID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
						Scopes:        federationScopeIDs,
						ResponseType:  goidc.ResponseTypeCode,
					},
				}
				return ctx, nil, req
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, _ request) {
				clients := oidctest.Clients(t, ctx)
				if len(clients) != 0 {
					t.Fatalf("len(clients) = %d, want 0", len(clients))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			ctx, c, req := tc.setup(t)

			// When.
			err := initAuth(ctx, req)

			// Then.
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", tc.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != tc.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, tc.wantErr)
				}
				if tc.validateErr != nil {
					tc.validateErr(t, err, ctx, c, req)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tc.validate(t, ctx, c, req)
		})
	}
}

func TestContinueAuthentication(t *testing.T) {
	ctx, client := setUpAuth(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
			return true
		},
		func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
			return goidc.StatusPending, nil
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	session := &goidc.AuthnSession{
		ID:        "random_session_id",
		PolicyID:  policy.ID,
		ClientID:  client.ID,
		CreatedAt: timeutil.TimestampNow(),
		ExpiresAt: timeutil.TimestampNow() + 60,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
		},
		Store: make(map[string]any),
	}
	if err := ctx.AuthSaveSession(session); err != nil {
		t.Fatalf("could not save auth session: %v", err)
	}

	err := continueAuth(ctx, session.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statusCode := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
	if statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want %d", statusCode, http.StatusOK)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	if sessions[0].ID != session.ID {
		t.Errorf("session ID = %q, want %q", sessions[0].ID, session.ID)
	}
}

func setUpAuth(t *testing.T) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.AuthManager = oidctest.Manager(t, ctx)
	client, _ := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	ctx.AuthSessionIDFunc = func(_ context.Context) string {
		return "random_authn_session_id"
	}
	ctx.AuthCodeFunc = func(_ context.Context) string {
		return "random_auth_code"
	}

	policy := goidc.NewPolicy(
		"random_policy_id",
		func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
			return true
		},
		func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
			as.Subject = "random_subject"
			as.Username = "random_username"
			as.GrantedScopes = as.Scopes
			as.GrantedAuthDetails = as.AuthDetails
			as.GrantedResources = as.Resources
			return goidc.StatusSuccess, nil
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	return ctx, client
}

func halfHash(claim string) string {
	hash := sha256.New()
	hash.Write([]byte(claim))
	halfHashedClaim := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}

type federationRoundTripper struct {
	responses map[string]func() *http.Response
}

func (m federationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if f := m.responses[req.URL.String()]; f != nil {
		return f(), nil
	}
	return nil, errors.ErrUnsupported
}
