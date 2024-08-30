package token_test

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
		AdditionalIDTokenClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims := oidctest.SafeClaims(t, idToken, ctx.PrivateJWKS.Keys[0])
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Host,
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

func TestMakeToken_JWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	tokenOptions := goidc.NewJWTTokenOptions(ctx.PrivateJWKS.Keys[0].KeyID, 60)
	tokenOptions = tokenOptions.WithClaims(map[string]any{"random_claim": "random_value"})
	grantOptions := token.GrantOptions{
		Subject:      "random_subject",
		TokenOptions: tokenOptions,
	}

	// When.
	token, err := token.Make(ctx, client, grantOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", token.Format, goidc.TokenFormatJWT)
	}

	claims := oidctest.SafeClaims(t, token.Value, ctx.PrivateJWKS.Keys[0])
	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Host,
		"sub":          grantOptions.Subject,
		"client_id":    client.ID,
		"scope":        grantOptions.GrantedScopes,
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
	client, _ := oidctest.NewClient(t)
	grantOptions := token.GrantOptions{
		Subject:      "random_subject",
		TokenOptions: goidc.NewOpaqueTokenOptions(10, 60),
	}

	// When.
	token, err := token.Make(ctx, client, grantOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Format != goidc.TokenFormatOpaque {
		t.Errorf("Format = %s, want %s", token.Format, goidc.TokenFormatOpaque)
	}

	if token.ID != token.Value {
		t.Errorf("ID = %s, want %s", token.ID, token.Value)
	}
}

func TestGenerateJWKThumbprint(t *testing.T) {
	// Given.
	dpopSigningAlgorithms := []jose.SignatureAlgorithm{jose.ES256}
	testCases := []struct {
		dpopJWT  string
		expected string
	}{
		{
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				// When.
				got := token.JWKThumbprint(testCase.dpopJWT, dpopSigningAlgorithms)

				// Then.
				if got != testCase.expected {
					t.Errorf("JWKThumbprint() = %s, want %s", got, testCase.expected)
				}
			},
		)
	}
}
