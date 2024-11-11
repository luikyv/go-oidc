package authorize

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestPushAuth(t *testing.T) {
	// Given.
	ctx, client := setUpPAR(t)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	}

	// When.
	resp, err := pushAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	session := sessions[0]

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		PushedAuthReqID:    resp.RequestURI,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	wantedResp := pushedResponse{
		RequestURI: session.PushedAuthReqID,
		ExpiresIn:  ctx.PARLifetimeSecs,
	}
	if diff := cmp.Diff(resp, wantedResp); diff != "" {
		t.Error(diff)
	}
}

func TestPushAuth_WithJAR(t *testing.T) {
	// Given.
	ctx, client := setUpPAR(t)
	ctx.JARIsEnabled = true
	ctx.JARSigAlgs = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JARLifetimeSecs = 60

	privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJWK.Public()}})
	client.PublicJWKS = jwks

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      client.RedirectURIs[0],
		"scope":             client.ScopeIDs,
		"response_type":     goidc.ResponseTypeCode,
	}
	requestObject, err := jwtutil.Sign(
		claims,
		privateJWK,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
		},
	}

	// When.
	resp, err := pushAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	session := sessions[0]

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		PushedAuthReqID:    resp.RequestURI,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	wantedResp := pushedResponse{
		RequestURI: session.PushedAuthReqID,
		ExpiresIn:  ctx.PARLifetimeSecs,
	}
	if diff := cmp.Diff(resp, wantedResp); diff != "" {
		t.Error(diff)
	}
}

func TestPushAuth_UnauthenticatedClient(t *testing.T) {
	// Given.
	ctx, client := setUpPAR(t)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {"invalid_secret"},
	}

	req := request{}

	// When.
	_, err := pushAuth(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func setUpPAR(t *testing.T) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.PARLifetimeSecs = 60
	client, secret := oidctest.NewClient(t)
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error creating the client: %v", err)
	}

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
