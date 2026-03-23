package token_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMakeIDToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
		Claims:  map[string]any{"random_claim": "random_value"},
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

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
	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
		Claims:  map[string]any{"random_claim": "random_value"},
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, c, idTokenOptions)

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

	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

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
	ctx.TokenClaimsFunc = func(_ context.Context, _ *goidc.Grant) map[string]any {
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
	tokenValue, err := token.MakeAccessToken(ctx, tkn, &grant)

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
	tokenValue, err := token.MakeAccessToken(ctx, tkn, &grant)

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

	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

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
		Subject:              "random_subject",
		ClientID:             c.ID,
		JWKThumbprint:        "dpop_thumbprint",
		ClientCertThumbprint: "tls_thumbprint",
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
		GrantID:              grant.ID,
		Subject:              grant.Subject,
		ClientID:             grant.ClientID,
		Scopes:               grant.Scopes,
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now2,
		ExpiresAtTimestamp:   now2 + opts.LifetimeSecs,
		Format:               opts.Format,
		SigAlg:               opts.JWTSigAlg,
	}

	// When.
	tokenValue, err := token.MakeAccessToken(ctx, tkn, &grant)

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
	ctx.TokenClaimsFunc = func(_ context.Context, _ *goidc.Grant) map[string]any {
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
	tokenValue, err := token.MakeAccessToken(ctx, tkn, &grant)

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
