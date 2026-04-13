package token

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMakeIDToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	idTokenOptions := IDTokenOptions{
		Subject: "random_subject",
		Claims:  map[string]any{"random_claim": "random_value"},
	}

	// When.
	idToken, err := MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
		"sub":          idTokenOptions.Subject,
		"aud":          client.ID,
		"random_claim": "random_value",
		"iat":          float64(now),
		"exp":          float64(now + ctx.IDTokenLifetimeSecs),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMakeIDToken_Unsigned(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.IDTokenSigAlgs = append(ctx.IDTokenSigAlgs, goidc.None)

	c, _ := oidctest.NewClient(t)
	c.IDTokenSigAlg = goidc.None
	idTokenOptions := IDTokenOptions{
		Subject: "random_subject",
		Claims:  map[string]any{"random_claim": "random_value"},
	}

	// When.
	idToken, err := MakeIDToken(ctx, c, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.UnsafeClaims(idToken, goidc.None)
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
		"sub":          idTokenOptions.Subject,
		"aud":          c.ID,
		"random_claim": "random_value",
		"iat":          float64(now),
		"exp":          float64(now + ctx.IDTokenLifetimeSecs),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMakeIDToken_PairwiseSub(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	ctx.PairwiseSubjectFunc = func(ctx context.Context, sub string, client *goidc.Client) string {
		parseURL, _ := url.Parse(client.SectorIdentifierURI)
		return parseURL.Hostname() + "_" + sub
	}

	client, _ := oidctest.NewClient(t)
	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.SectorIdentifierURI = "https://example.com/redirect_uris.json"

	idTokenOptions := IDTokenOptions{
		Subject: "random_subject",
	}

	// When.
	idToken, err := MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss": ctx.Issuer(),
		"sub": "example.com_random_subject",
		"aud": client.ID,
		"iat": float64(now),
		"exp": float64(now + ctx.IDTokenLifetimeSecs),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMakeToken_JWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenClaimsFunc = func(_ context.Context, _ *goidc.Token, _ *goidc.Grant) map[string]any {
		return map[string]any{"random_claim": "random_value"}
	}
	c, _ := oidctest.NewClient(t)
	grant := goidc.Grant{
		Subject:  "random_subject",
		ClientID: c.ID,
	}
	opts := ctx.TokenOptions(&grant, c)
	now2 := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID: func() string {
			if opts.Format == goidc.TokenFormatJWT {
				return ctx.JWTID()
			}
			return ctx.OpaqueToken()
		}(),
		GrantID:            grant.ID,
		Subject:            grant.Subject,
		ClientID:           grant.ClientID,
		Scopes:             grant.Scopes,
		AuthDetails:        grant.AuthDetails,
		Resources:          grant.Resources,
		JWKThumbprint:      grant.JWKThumbprint,
		CreatedAtTimestamp: now2,
		ExpiresAtTimestamp: now2 + opts.LifetimeSecs,
		Format:             opts.Format,
		SigAlg:             opts.JWTSigAlg,
	}

	// When.
	tokenValue, err := MakeAccessToken(ctx, tkn, &grant)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tkn.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", tkn.Format, goidc.TokenFormatJWT)
	}

	claims, err := oidctest.SafeClaims(tokenValue, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
		"sub":          grant.Subject,
		"client_id":    c.ID,
		"scope":        grant.Scopes,
		"exp":          float64(now + 60),
		"iat":          float64(now),
		"random_claim": "random_value",
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

}

func TestMakeToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenOptionsFunc = func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(60)
	}
	grant := goidc.Grant{
		Subject: "random_subject",
	}
	client := &goidc.Client{}
	opaqueOpts := ctx.TokenOptions(&grant, client)
	opaqueNow := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID:                 ctx.OpaqueToken(),
		GrantID:            grant.ID,
		Subject:            grant.Subject,
		CreatedAtTimestamp: opaqueNow,
		ExpiresAtTimestamp: opaqueNow + opaqueOpts.LifetimeSecs,
		Format:             opaqueOpts.Format,
		SigAlg:             opaqueOpts.JWTSigAlg,
	}

	// When.
	tokenValue, err := MakeAccessToken(ctx, tkn, &grant)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tkn.Format != goidc.TokenFormatOpaque {
		t.Errorf("Format = %s, want %s", tkn.Format, goidc.TokenFormatOpaque)
	}

	if tkn.ID != tokenValue {
		t.Errorf("ID = %s, want %s", tkn.ID, tokenValue)
	}
}

func TestMakeIDToken_Encrypted(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.IDTokenEncIsEnabled = true
	ctx.IDTokenKeyEncAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256}
	ctx.IDTokenDefaultContentEncAlg = goidc.A128CBC_HS256
	ctx.IDTokenContentEncAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256}

	encJWK := oidctest.PrivateRSAOAEP256JWK(t, "enc_key")
	client, _ := oidctest.NewClient(t)
	client.IDTokenKeyEncAlg = goidc.RSA_OAEP_256
	client.JWKS = &goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{encJWK.Public()},
	}

	idTokenOptions := IDTokenOptions{
		Subject: "random_subject",
	}

	// When.
	idToken, err := MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// JWE compact serialization has 5 dot-separated parts.
	parts := strings.Split(idToken, ".")
	if len(parts) != 5 {
		t.Fatalf("expected JWE with 5 parts, got %d", len(parts))
	}

	// Decrypt and verify inner claims.
	jwe, err := jose.ParseEncrypted(
		idToken,
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)
	if err != nil {
		t.Fatalf("error parsing JWE: %v", err)
	}

	innerBytes, err := jwe.Decrypt(encJWK.Key)
	if err != nil {
		t.Fatalf("error decrypting JWE: %v", err)
	}

	// The inner content is a signed JWT; parse its claims.
	claims, err := oidctest.SafeClaims(string(innerBytes), oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing inner claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss": ctx.Issuer(),
		"sub": "random_subject",
		"aud": client.ID,
		"iat": float64(now),
		"exp": float64(now + ctx.IDTokenLifetimeSecs),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMakeToken_JWTToken_WithConfirmation(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	c, _ := oidctest.NewClient(t)
	grant := goidc.Grant{
		Subject:        "random_subject",
		ClientID:       c.ID,
		JWKThumbprint:  "dpop_thumbprint",
		CertThumbprint: "tls_thumbprint",
	}
	opts := ctx.TokenOptions(&grant, c)
	now2 := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID: func() string {
			if opts.Format == goidc.TokenFormatJWT {
				return ctx.JWTID()
			}
			return ctx.OpaqueToken()
		}(),
		GrantID:            grant.ID,
		Subject:            grant.Subject,
		ClientID:           grant.ClientID,
		Scopes:             grant.Scopes,
		JWKThumbprint:      grant.JWKThumbprint,
		CertThumbprint:     grant.CertThumbprint,
		CreatedAtTimestamp: now2,
		ExpiresAtTimestamp: now2 + opts.LifetimeSecs,
		Format:             opts.Format,
		SigAlg:             opts.JWTSigAlg,
	}

	// When.
	tokenValue, err := MakeAccessToken(ctx, tkn, &grant)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(tokenValue, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatal("expected cnf claim in token")
	}

	if cnf["jkt"] != "dpop_thumbprint" {
		t.Errorf("cnf.jkt = %v, want dpop_thumbprint", cnf["jkt"])
	}

	if cnf["x5t#S256"] != "tls_thumbprint" {
		t.Errorf("cnf.x5t#S256 = %v, want tls_thumbprint", cnf["x5t#S256"])
	}
}

func TestMakeToken_UnsignedJWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenOptionsFunc = func(
		_ context.Context,
		_ *goidc.Grant,
		_ *goidc.Client,
	) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(goidc.None, 60)
	}
	ctx.TokenClaimsFunc = func(_ context.Context, _ *goidc.Token, _ *goidc.Grant) map[string]any {
		return map[string]any{"random_claim": "random_value"}
	}
	client, _ := oidctest.NewClient(t)
	grant := goidc.Grant{
		Subject:  "random_subject",
		ClientID: client.ID,
	}
	unsignedOpts := ctx.TokenOptions(&grant, client)
	unsignedNow := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID:                 ctx.JWTID(),
		GrantID:            grant.ID,
		Subject:            grant.Subject,
		ClientID:           grant.ClientID,
		Scopes:             grant.Scopes,
		CreatedAtTimestamp: unsignedNow,
		ExpiresAtTimestamp: unsignedNow + unsignedOpts.LifetimeSecs,
		Format:             unsignedOpts.Format,
		SigAlg:             unsignedOpts.JWTSigAlg,
	}

	// When.
	tokenValue, err := MakeAccessToken(ctx, tkn, &grant)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tkn.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", tkn.Format, goidc.TokenFormatJWT)
	}

	if !joseutil.IsUnsignedJWT(tokenValue) {
		t.Errorf("got %s, want unsigned", tokenValue)
	}
}

func TestExtractID_OpaqueToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)

	// When.
	id, err := ExtractID(ctx, "opaque_token_value")

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "opaque_token_value" {
		t.Errorf("ID = %s, want opaque_token_value", id)
	}
}

func TestExtractID_JWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	c, _ := oidctest.NewClient(t)
	_ = ctx.SaveClient(c)

	grant := &goidc.Grant{
		ID:       "grant_id",
		ClientID: c.ID,
		Subject:  "user",
	}
	tkn, tokenValue, err := Issue(ctx, grant, c, nil)
	if err != nil {
		t.Fatalf("error issuing token: %v", err)
	}

	// When.
	id, err := ExtractID(ctx, tokenValue)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != tkn.ID {
		t.Errorf("ID = %s, want %s", id, tkn.ID)
	}
}

func TestGenerateGrant_UnsupportedGrantType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	_ = ctx.SaveClient(client)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	// When.
	_, err := generateGrant(ctx, request{
		grantType: "urn:unsupported",
	})

	// Then.
	if err == nil {
		t.Fatal("expected error for unsupported grant type")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeUnsupportedGrantType {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeUnsupportedGrantType)
	}
}

func TestGenerateGrant_ClientNotFound(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Request.PostForm = map[string][]string{
		"client_id": {"invalid_client_id"},
	}

	// When.
	_, err := generateGrant(ctx, request{
		grantType: goidc.GrantClientCredentials,
		scopes:    "scope1",
	})

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestGenerateGrant_UnauthenticatedClient(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)

	ctx := oidctest.NewContext(t)
	_ = ctx.SaveClient(client)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {"invalid_secret"},
	}

	// When.
	_, err := generateGrant(ctx, request{
		grantType: goidc.GrantClientCredentials,
		scopes:    client.ScopeIDs,
	})

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestGenerateGrantWithDPoP(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	_ = ctx.SaveClient(client)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	ctx.Host = "https://example.com"
	ctx.DPoPIsEnabled = true
	ctx.JWTLifetimeSecs = 9999999999999
	ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
	ctx.Request.Header.Set(goidc.HeaderDPoP, "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ")
	ctx.Request.Method = http.MethodPost
	ctx.Request.RequestURI = "/token"

	req := request{
		grantType: goidc.GrantClientCredentials,
		scopes:    "scope1",
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       client.ID,
		"client_id": client.ID,
		"scope":     "scope1",
		"exp":       float64(now + 60),
		"iat":       float64(now),
		"cnf": map[string]any{
			"jkt": "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ",
		},
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
}
