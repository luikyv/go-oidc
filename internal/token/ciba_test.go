package token

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateGrant_CIBAGrant(t *testing.T) {

	// Given.
	ctx, client, session := setUpCIBAGrant(t)

	req := request{
		grantType: goidc.GrantCIBA,
		authReqID: session.CIBAAuthID,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]
	wantedSession := goidc.GrantSession{
		ID:                          grantSession.ID,
		TokenID:                     grantSession.TokenID,
		LastTokenExpiresAtTimestamp: grantSession.LastTokenExpiresAtTimestamp,
		CreatedAtTimestamp:          grantSession.CreatedAtTimestamp,
		ExpiresAtTimestamp:          grantSession.ExpiresAtTimestamp,
		GrantInfo: goidc.GrantInfo{
			GrantType:     goidc.GrantCIBA,
			Subject:       session.Subject,
			ClientID:      session.ClientID,
			ActiveScopes:  session.GrantedScopes,
			GrantedScopes: session.GrantedScopes,
		},
	}
	if diff := cmp.Diff(
		*grantSession,
		wantedSession,
		cmpopts.EquateApprox(0, 1),
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       session.Subject,
		"client_id": client.ID,
		"scope":     session.GrantedScopes,
		"exp":       float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       grantSession.TokenID,
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

	authnSessions := oidctest.AuthnSessions(t, ctx)
	if len(authnSessions) != 0 {
		t.Errorf("len(authnSessions) = %d, want 0", len(authnSessions))
	}
}

func TestGenerateGrant_CIBAGrant_AuthPending(t *testing.T) {

	// Given.
	ctx, _, session := setUpCIBAGrant(t)
	ctx.ValidateBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return goidc.NewError(goidc.ErrorCodeAuthPending, "auth pending")
	}

	req := request{
		grantType: goidc.GrantCIBA,
		authReqID: session.CIBAAuthID,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("error did not happen", err)
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeAuthPending {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAuthPending)
	}

	authnSessions := oidctest.AuthnSessions(t, ctx)
	if len(authnSessions) != 1 {
		t.Errorf("len(authnSessions) = %d, want 1", len(authnSessions))
	}
}

func TestGenerateGrant_CIBAGrant_InvalidAuthSession(t *testing.T) {

	// Given.
	ctx, _, session := setUpCIBAGrant(t)
	ctx.ValidateBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "access denied")
	}

	req := request{
		grantType: goidc.GrantCIBA,
		authReqID: session.CIBAAuthID,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("error did not happen", err)
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}

	authnSessions := oidctest.AuthnSessions(t, ctx)
	if len(authnSessions) != 0 {
		t.Errorf("len(authnSessions) = %d, want 0", len(authnSessions))
	}
}

func TestGenerateGrant_CIBAGrant_MTLSBinding(t *testing.T) {

	// Given.
	ctx, client, session := setUpCIBAGrant(t)
	ctx.MTLSTokenBindingIsEnabled = true
	ctx.ClientCertFunc = func(r *http.Request) (*x509.Certificate, error) {
		return &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName: "random",
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}, nil
	}

	req := request{
		grantType: goidc.GrantCIBA,
		authReqID: session.CIBAAuthID,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]

	if grantSession.ClientCertThumbprint == "" {
		t.Fatalf("invalid certificate thumbprint")
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       session.Subject,
		"client_id": client.ID,
		"scope":     session.GrantedScopes,
		"exp":       float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       grantSession.TokenID,
		"cnf": map[string]any{
			"x5t#S256": grantSession.ClientCertThumbprint,
		},
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

	authnSessions := oidctest.AuthnSessions(t, ctx)
	if len(authnSessions) != 0 {
		t.Errorf("len(authnSessions) = %d, want 0", len(authnSessions))
	}
}

func setUpCIBAGrant(t testing.TB) (
	ctx oidc.Context,
	client *goidc.Client,
	session *goidc.AuthnSession,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.CIBAIsEnabled = true
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
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
		t.Errorf("error while creating the client: %v", err)
	}
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	now := timeutil.TimestampNow()
	authReqID := "random_auth_req_id"
	session = &goidc.AuthnSession{
		ClientID:      client.ID,
		GrantedScopes: goidc.ScopeOpenID.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes: goidc.ScopeOpenID.ID,
		},
		CIBAAuthID:         authReqID,
		Subject:            "user_id",
		CreatedAtTimestamp: now,
		ExpiresAtTimestamp: now + 60,
	}
	if err := ctx.SaveAuthnSession(session); err != nil {
		t.Errorf("error while creating the session: %v", err)
	}

	return ctx, client, session
}
