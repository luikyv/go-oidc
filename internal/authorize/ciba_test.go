package authorize

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestInitBackAuth_PingMode(t *testing.T) {
	// Given.
	ctx, client := setUpBackAuth(t)
	client.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePing

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			LoginHint:               "random_hint",
			ClientNotificationToken: "random_token",
		},
	}

	// When.
	resp, err := initBackAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.CIBAAuthID == "" {
		t.Fatalf("auth req id cannot be null")
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		CIBAAuthID:         session.CIBAAuthID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			ClientNotificationToken: "random_token",
			LoginHint:               "random_hint",
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	wantedResp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
		ExpiresIn: ctx.CIBADefaultSessionLifetimeSecs,
		Interval:  ctx.CIBAPollingIntervalSecs,
	}
	if diff := cmp.Diff(resp, wantedResp); diff != "" {
		t.Error(diff)
	}
}

func TestInitBackAuth_PollMode(t *testing.T) {
	// Given.
	ctx, client := setUpBackAuth(t)
	client.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePoll

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			LoginHint: "random_hint",
		},
	}

	// When.
	resp, err := initBackAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.CIBAAuthID == "" {
		t.Fatalf("auth req id cannot be null")
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		CIBAAuthID:         session.CIBAAuthID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			LoginHint: "random_hint",
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	wantedResp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
		ExpiresIn: ctx.CIBADefaultSessionLifetimeSecs,
		Interval:  ctx.CIBAPollingIntervalSecs,
	}
	if diff := cmp.Diff(resp, wantedResp); diff != "" {
		t.Error(diff)
	}
}

func TestInitBackAuth_PushMode(t *testing.T) {
	// Given.
	ctx, client := setUpBackAuth(t)
	client.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePush

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			ClientNotificationToken: "random_token",
			LoginHint:               "random_hint",
		},
	}

	// When.
	resp, err := initBackAuth(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessions := oidctest.AuthnSessions(t, ctx)
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}

	session := sessions[0]
	if session.CIBAAuthID == "" {
		t.Fatalf("auth req id cannot be null")
	}

	wantedSession := goidc.AuthnSession{
		ID:                 session.ID,
		CIBAAuthID:         session.CIBAAuthID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			ClientNotificationToken: "random_token",
			LoginHint:               "random_hint",
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	wantedResp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
		ExpiresIn: ctx.CIBADefaultSessionLifetimeSecs,
	}
	if diff := cmp.Diff(resp, wantedResp); diff != "" {
		t.Error(diff)
	}
}

func TestInitBackAuth_WithJAR(t *testing.T) {
	// Given.
	ctx, client := setUpBackAuth(t)
	ctx.CIBAJARIsEnabled = true
	ctx.CIBAJARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}

	privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
	client.PublicJWKS = goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{privateJWK.Public()},
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:           client.ID,
		goidc.ClaimAudience:         ctx.Host,
		goidc.ClaimIssuedAt:         now,
		goidc.ClaimExpiry:           now + 10,
		goidc.ClaimNotBefore:        now - 10,
		goidc.ClaimTokenID:          "random_id",
		"client_id":                 client.ID,
		"client_notification_token": "random_token",
		"login_hint":                "random_hint",
		goidc.ClaimScope:            client.ScopeIDs,
	}
	requestObject := oidctest.Sign(t, claims, privateJWK)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
		},
	}

	// When.
	resp, err := initBackAuth(ctx, req)

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
		CIBAAuthID:         resp.AuthReqID,
		ExpiresAtTimestamp: session.ExpiresAtTimestamp,
		CreatedAtTimestamp: session.CreatedAtTimestamp,
		ClientID:           client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes:                  client.ScopeIDs,
			ClientNotificationToken: "random_token",
			LoginHint:               "random_hint",
		},
	}
	if diff := cmp.Diff(*session, wantedSession, cmpopts.EquateEmpty()); diff != "" {
		t.Error(diff)
	}

	wantedResp := cibaResponse{
		AuthReqID: session.CIBAAuthID,
		ExpiresIn: ctx.CIBADefaultSessionLifetimeSecs,
		Interval:  ctx.CIBAPollingIntervalSecs,
	}
	if diff := cmp.Diff(resp, wantedResp); diff != "" {
		t.Error(diff)
	}
}

func TestInitBackAuth_Rejected(t *testing.T) {
	// Given.
	ctx, client := setUpBackAuth(t)
	ctx.InitBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
	}

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			LoginHint:               "random_hint",
			ClientNotificationToken: "random_token",
		},
	}

	// When.
	_, err := initBackAuth(ctx, req)

	// Then.
	if err == nil {
		t.Fatalf("error did not happen")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func TestInitBackAuth_UnauthenticatedClient(t *testing.T) {
	// Given.
	ctx, client := setUpBackAuth(t)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {"invalid_secret"},
	}

	req := request{}

	// When.
	_, err := initBackAuth(ctx, req)

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

func setUpBackAuth(t *testing.T) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.CIBAIsEnabled = true
	ctx.CIBATokenDeliveryModels = []goidc.CIBATokenDeliveryMode{
		goidc.CIBATokenDeliveryModePoll, goidc.CIBATokenDeliveryModePing,
		goidc.CIBATokenDeliveryModePush,
	}
	ctx.InitBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return nil
	}
	ctx.ValidateBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return nil
	}
	ctx.CIBAUserCodeIsEnabled = true
	ctx.CIBADefaultSessionLifetimeSecs = 60
	ctx.CIBAPollingIntervalSecs = 5

	client, secret := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
	client.CIBATokenDeliveryMode = goidc.CIBATokenDeliveryModePing
	client.CIBANotificationEndpoint = "https://example.client.com/ciba"
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up auth: %v", err)
	}

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
