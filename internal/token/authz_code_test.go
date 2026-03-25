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

func TestGenerateGrant_AuthorizationCodeGrant(t *testing.T) {

	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]
	wantedSession := goidc.Grant{
		ID:                 grantSession.ID,
		CreatedAtTimestamp: grantSession.CreatedAtTimestamp,
		ExpiresAtTimestamp: grantSession.ExpiresAtTimestamp,
		AuthCode:           session.AuthCode,
		RefreshToken:       grantSession.RefreshToken,
		Type:               goidc.GrantAuthorizationCode,
		Subject:            session.Subject,
		ClientID:           session.ClientID,
		Scopes:             session.GrantedScopes,
	}
	if diff := cmp.Diff(
		*grantSession,
		wantedSession,
		cmpopts.EquateApprox(0, 1),
		cmpopts.EquateEmpty(),
	); diff != "" {
		t.Error(diff)
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	tokenEntity := tokens[0]

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       session.Subject,
		"client_id": client.ID,
		"scope":     session.GrantedScopes,
		"exp":       float64(tokenEntity.ExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       tokenEntity.ID,
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
	ctx.RARIsEnabled = true
	ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
	ctx.RARCompareDetailsFunc = func(_ context.Context, granted, requested []goidc.AuthDetail) error {
		return nil
	}
	authDetails := []goidc.AuthDetail{
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
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]
	wantedSession := goidc.Grant{
		ID:                 grantSession.ID,
		CreatedAtTimestamp: grantSession.CreatedAtTimestamp,
		ExpiresAtTimestamp: grantSession.ExpiresAtTimestamp,
		AuthCode:           session.AuthCode,
		RefreshToken:       grantSession.RefreshToken,
		Type:               goidc.GrantAuthorizationCode,
		Subject:            session.Subject,
		ClientID:           session.ClientID,
		Scopes:             session.GrantedScopes,
		AuthDetails:        authDetails,
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
		"iss":       ctx.Issuer(),
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
		"exp": float64(now + 60),
		"iat": float64(now),
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
	ctx.RARIsEnabled = true
	ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
	ctx.RARCompareDetailsFunc = func(_ context.Context, granted, requested []goidc.AuthDetail) error {
		return nil
	}
	session.GrantedAuthDetails = []goidc.AuthDetail{
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
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
		authDetails: []goidc.AuthDetail{
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

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	tokenEntity := tokens[0]

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       session.Subject,
		"client_id": client.ID,
		"scope":     session.GrantedScopes,
		"authorization_details": []any{
			map[string]any{
				"type":         "type1",
				"random_claim": "random_value",
			},
		},
		"exp": float64(tokenEntity.ExpiresAtTimestamp),
		"iat": float64(now),
		"jti": tokenEntity.ID,
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
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
		resources:   []string{"https://resource1.com", "https://resource2.com"},
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	tokenEntity := tokens[0]

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       session.Subject,
		"aud":       []any{"https://resource1.com", "https://resource2.com"},
		"client_id": client.ID,
		"scope":     session.GrantedScopes,
		"exp":       float64(tokenEntity.ExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       tokenEntity.ID,
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
	_ = ctx.SaveGrant(&goidc.Grant{
		ID:       "random_id",
		AuthCode: session.AuthCode,
	})

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
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

	grantSessions := oidctest.Grants(t, ctx)
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
		grantType:    goidc.GrantAuthorizationCode,
		redirectURI:  client.RedirectURIs[0],
		code:         session.AuthCode,
		codeVerifier: "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
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
		grantType:    goidc.GrantAuthorizationCode,
		redirectURI:  client.RedirectURIs[0],
		code:         session.AuthCode,
		codeVerifier: "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98",
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

func TestValidatePKCE(t *testing.T) {
	testCases := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod goidc.CodeChallengeMethod
		wantErr             bool
	}{
		{
			name:                "sha256_valid_1",
			codeVerifier:        "4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98",
			codeChallenge:       "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ",
			codeChallengeMethod: goidc.CodeChallengeMethodSHA256,
		},
		{
			name:                "sha256_valid_2",
			codeVerifier:        "42d92ec716da149b8c0a553d5cbbdc5fd474625cdffe7335d643105b",
			codeChallenge:       "yQ0Wg2MXS83nBOaS3yit-n-xEaEw5LQ8TlhtX_2NkLw",
			codeChallengeMethod: goidc.CodeChallengeMethodSHA256,
		},
		{
			name:                "sha256_wrong_verifier",
			codeVerifier:        "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a",
			codeChallenge:       "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ",
			codeChallengeMethod: goidc.CodeChallengeMethodSHA256,
			wantErr:             true,
		},
		{
			name:                "sha256_verifier_as_challenge",
			codeVerifier:        "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a",
			codeChallenge:       "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a",
			codeChallengeMethod: goidc.CodeChallengeMethodSHA256,
			wantErr:             true,
		},
		{
			name:                "sha256_empty_verifier",
			codeVerifier:        "",
			codeChallenge:       "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ",
			codeChallengeMethod: goidc.CodeChallengeMethodSHA256,
			wantErr:             true,
		},
		{
			name:                "sha256_empty_challenge_with_verifier",
			codeVerifier:        "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a",
			codeChallenge:       "",
			codeChallengeMethod: goidc.CodeChallengeMethodSHA256,
			wantErr:             true,
		},
		{
			name:                "plain_valid",
			codeVerifier:        "0123456789abcdef0123456789abcdef0123456789a",
			codeChallenge:       "0123456789abcdef0123456789abcdef0123456789a",
			codeChallengeMethod: goidc.CodeChallengeMethodPlain,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			ctx := oidctest.NewContext(t)
			ctx.PKCEIsEnabled = true
			ctx.PKCEDefaultChallengeMethod = tc.codeChallengeMethod
			ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{tc.codeChallengeMethod}

			session := &goidc.AuthnSession{}
			session.CodeChallenge = tc.codeChallenge
			session.CodeChallengeMethod = tc.codeChallengeMethod
			req := request{codeVerifier: tc.codeVerifier}

			// When.
			err := validatePKCE(ctx, req, nil, session)

			// Then.
			if (err != nil) != tc.wantErr {
				t.Errorf("validatePKCE() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
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
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]

	if grantSession.ClientCertThumbprint == "" {
		t.Fatalf("invalid certificate thumbprint")
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	tokenEntity := tokens[0]

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       session.Subject,
		"client_id": client.ID,
		"scope":     session.GrantedScopes,
		"exp":       float64(tokenEntity.ExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       tokenEntity.ID,
		"cnf": map[string]any{
			"x5t#S256": tokenEntity.ClientCertThumbprint,
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

func TestGenerateGrant_AuthorizationCodeGrant_MissingCode(t *testing.T) {
	// Given.
	ctx, client, _ := setUpAuthzCodeGrant(t)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        "",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for missing authorization code")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_ExpiredSession(t *testing.T) {
	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	session.ExpiresAtTimestamp = timeutil.TimestampNow() - 10
	_ = ctx.SaveAuthnSession(session)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for expired authorization code")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidGrant {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidGrant)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_WrongRedirectURI(t *testing.T) {
	// Given.
	ctx, _, session := setUpAuthzCodeGrant(t)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: "https://wrong.example.com/callback",
		code:        session.AuthCode,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for wrong redirect URI")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidGrant {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidGrant)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_ClientMismatch(t *testing.T) {
	// Given.
	ctx, _, session := setUpAuthzCodeGrant(t)
	session.ClientID = "different_client"
	_ = ctx.SaveAuthnSession(session)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: session.RedirectURI,
		code:        session.AuthCode,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for client mismatch")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidGrant {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidGrant)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_ClientLacksGrantType(t *testing.T) {
	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	client.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
	_ = ctx.SaveClient(client)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error when client lacks authorization_code grant type")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeUnauthorizedClient {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeUnauthorizedClient)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_ScopeNarrowing(t *testing.T) {
	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)
	session.GrantedScopes = "openid " + oidctest.Scope1.ID
	_ = ctx.SaveAuthnSession(session)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
		scopes:      goidc.ScopeOpenID.ID,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenResp.Scopes != goidc.ScopeOpenID.ID {
		t.Errorf("Scopes = %s, want %s", tokenResp.Scopes, goidc.ScopeOpenID.ID)
	}
}

func TestGenerateGrant_AuthorizationCodeGrant_InvalidScopeNarrowing(t *testing.T) {
	// Given.
	ctx, client, session := setUpAuthzCodeGrant(t)

	req := request{
		grantType:   goidc.GrantAuthorizationCode,
		redirectURI: client.RedirectURIs[0],
		code:        session.AuthCode,
		scopes:      "scope_not_granted",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for scope not in granted set")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidScope {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidScope)
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
		AuthCode:           authorizationCode,
		Subject:            "user_id",
		CreatedAtTimestamp: now,
		ExpiresAtTimestamp: now + 60,
		Store:              make(map[string]any),
	}
	if err := ctx.SaveAuthnSession(session); err != nil {
		t.Errorf("error while creating the session: %v", err)
	}

	return ctx, client, session
}
