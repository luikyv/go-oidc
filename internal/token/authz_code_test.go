package token

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
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

func TestGenerateGrant_AuthorizationCodeGrant(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
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
		AuthCode:                    session.AuthCode,
		GrantInfo: goidc.GrantInfo{
			GrantType:     goidc.GrantAuthorizationCode,
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

func TestGenerateGrant_AuthorizationCodeGrant_AuthDetails(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	ctx.AuthDetailsIsEnabled = true
	ctx.AuthDetailTypes = []string{"type1", "type2"}
	ctx.CompareAuthDetailsFunc = func(granted, requested []goidc.AuthorizationDetail) error {
		return nil
	}
	authDetails := []goidc.AuthorizationDetail{
		{
			"type":         "type1",
			"random_claim": "random_value",
		},
		{
			"type":         "type2",
			"random_claim": "random_value",
		},
	}
	session.GrantedAuthDetails = authDetails

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
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
		AuthCode:                    session.AuthCode,
		GrantInfo: goidc.GrantInfo{
			GrantType:          goidc.GrantAuthorizationCode,
			Subject:            session.Subject,
			ClientID:           session.ClientID,
			ActiveScopes:       session.GrantedScopes,
			GrantedScopes:      session.GrantedScopes,
			ActiveAuthDetails:  authDetails,
			GrantedAuthDetails: authDetails,
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
		"authorization_details": []any{
			map[string]any{
				"type":         "type1",
				"random_claim": "random_value",
			},
			map[string]any{
				"type":         "type2",
				"random_claim": "random_value",
			},
		},
		"exp": float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat": float64(now),
		"jti": grantSession.TokenID,
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "jti"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

	authnSessions := oidctest.AuthnSessions(t, ctx)
	if len(authnSessions) != 0 {
		t.Errorf("len(authnSessions) = %d, want 0", len(authnSessions))
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_AuthDetails_ClientRequestsSubset(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	ctx.AuthDetailsIsEnabled = true
	ctx.AuthDetailTypes = []string{"type1", "type2"}
	ctx.CompareAuthDetailsFunc = func(granted, requested []goidc.AuthorizationDetail) error {
		return nil
	}
	session.GrantedAuthDetails = []goidc.AuthorizationDetail{
		{
			"type":         "type1",
			"random_claim": "random_value",
		},
		{
			"type":         "type2",
			"random_claim": "random_value",
		},
	}

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
		authDetails: []goidc.AuthorizationDetail{
			map[string]any{
				"type":         "type1",
				"random_claim": "random_value",
			},
		},
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]

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
		"authorization_details": []any{
			map[string]any{
				"type":         "type1",
				"random_claim": "random_value",
			},
		},
		"exp": float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat": float64(now),
		"jti": grantSession.TokenID,
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

func TestGenerateGrant_AuthorizationCodeGrant_ResourceIndicators(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	ctx.ResourceIndicatorsIsEnabled = true
	ctx.Resources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
	session.GrantedResources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
		resources:         []string{"https://resource1.com", "https://resource2.com"},
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       session.Subject,
		"aud":       []any{"https://resource1.com", "https://resource2.com"},
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

func TestGenerateGrant_AuthorizationCodeGrant_CodeReuseInvalidatesGrant(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	_ = ctx.DeleteAuthnSession(session.ID)
	_ = ctx.SaveGrantSession(&goidc.GrantSession{
		ID:       "random_id",
		AuthCode: session.AuthCode,
	})

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("the session should not be found")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Error("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidGrant {
		t.Errorf("ErrorCode = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidGrant)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 0 {
		t.Errorf("len(grantSessions) = %d, want 0", len(grantSessions))
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_PKCE(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
	session.CodeChallenge = "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ"
	if err := ctx.SaveAuthnSession(session); err != nil {
		t.Errorf("error while saving the session: %v", err)
	}

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
		codeVerifier:      "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

// TestGenerateGrant_AuthorizationCodeGrant_PKCEDowngradeIsMitigated verifies that an
// authorization code grant request fails when a code_verifier is provided, but no
// code_challenge was used during authorization. This ensures that a PKCE downgrade attack
// is properly mitigated.
func TestGenerateGrant_AuthorizationCodeGrant_PKCEDowngradeIsMitigated(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256

	req := request{
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
		codeVerifier:      "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatalf("informing a code_verifier should result in failure if the session was not created with a code_challenge: %v", err)
	}

	authnSessions := oidctest.AuthnSessions(t, ctx)
	if len(authnSessions) != 0 {
		t.Errorf("len(authnSessions) = %d, want 0", len(authnSessions))
	}
}

func TestIsPkceValid(t *testing.T) {
	testCases := []struct {
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod goidc.CodeChallengeMethod
		isValid             bool
	}{
		{"4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", goidc.CodeChallengeMethodSHA256, true},
		{"42d92ec716da149b8c0a553d5cbbdc5fd474625cdffe7335d643105b", "yQ0Wg2MXS83nBOaS3yit-n-xEaEw5LQ8TlhtX_2NkLw", goidc.CodeChallengeMethodSHA256, true},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", goidc.CodeChallengeMethodSHA256, false},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", goidc.CodeChallengeMethodSHA256, false},
		{"", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", goidc.CodeChallengeMethodSHA256, false},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "", goidc.CodeChallengeMethodSHA256, false},
		{"random_string", "random_string", goidc.CodeChallengeMethodPlain, true},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				// When.
				got := isPKCEValid(testCase.codeVerifier, testCase.codeChallenge, testCase.codeChallengeMethod)

				// Then.
				if got != testCase.isValid {
					t.Errorf("isPKCEValid() = %t, want %t", got, testCase.isValid)
				}
			},
		)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_MTLSBinding(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
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
		grantType:         goidc.GrantAuthorizationCode,
		redirectURI:       client.RedirectURIs[0],
		authorizationCode: session.AuthCode,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
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

func setUpAuthzCodeGrant(t testing.TB) (ctx oidc.Context, client *goidc.Client, session *goidc.AuthnSession) {
	t.Helper()

	ctx = oidctest.NewContext(t)

	client, secret := oidctest.NewClient(t)
	if err := ctx.SaveClient(client); err != nil {
		t.Errorf("error while creating the client: %v", err)
	}
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	now := timeutil.TimestampNow()
	authorizationCode := "random_authz_code"
	session = &goidc.AuthnSession{
		ClientID:      client.ID,
		GrantedScopes: goidc.ScopeOpenID.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes:      goidc.ScopeOpenID.ID,
			RedirectURI: client.RedirectURIs[0],
		},
		AuthCode:              authorizationCode,
		Subject:               "user_id",
		CreatedAtTimestamp:    now,
		ExpiresAtTimestamp:    now + 60,
		Storage:               make(map[string]any),
		AdditionalTokenClaims: make(map[string]any),
	}
	if err := ctx.SaveAuthnSession(session); err != nil {
		t.Errorf("error while creating the session: %v", err)
	}

	return ctx, client, session
}
