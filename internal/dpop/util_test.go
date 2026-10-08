package dpop_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidateJWT(t *testing.T) {

	var testCases = []struct {
		name          string
		dpopJWT       string
		opts          dpop.ValidationOptions
		ctx           oidc.Context
		shouldBeValid bool
	}{
		{
			"valid_dpop_jwt",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			dpop.ValidationOptions{},
			oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgRS256, goidc.SigAlgPS256, goidc.SigAlgES256},
					ConsumeJTIFunc:  func(_ context.Context, _ string) error { return nil },
					JWTLifetimeSecs: 99999999999,
				},
				Request: httptest.NewRequest(http.MethodPost, "/token", nil),
			},
			true,
		},
		{
			"valid_dpop_jwt_with_ath",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
			dpop.ValidationOptions{
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			},
			oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://resource.example.org",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgRS256, goidc.SigAlgPS256, goidc.SigAlgES256},
					ConsumeJTIFunc:  func(_ context.Context, _ string) error { return nil },
					JWTLifetimeSecs: 99999999999,
				},
				Request: httptest.NewRequest(http.MethodGet, "/protectedresource", nil),
			},
			true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				// When.
				err := dpop.ValidateJWT(testCase.ctx, testCase.dpopJWT, testCase.opts)

				// Then.
				isValid := err == nil
				if isValid != testCase.shouldBeValid {
					t.Errorf("isValid = %t, want %t", isValid, testCase.shouldBeValid)
				}
			},
		)
	}
}

func TestValidateJWTConsumesTypedJTIOnlyAfterProofValidation(t *testing.T) {
	const lifetime = 60
	proof, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    "https://server.example.com/token",
	})
	request := httptest.NewRequest(http.MethodPost, "/token", nil)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:            "https://server.example.com",
			DPoPEnabled:     true,
			DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
			JWTLifetimeSecs: lifetime,
		},
		Request: request,
	}

	before := time.Now().UTC().Add(lifetime * time.Second)
	var got goidc.JTIUse
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		got = use
		return nil
	}
	if err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{}); err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	after := time.Now().UTC().Add(lifetime * time.Second)

	if got.ID == "" {
		t.Fatal("typed JTI consumer was not called")
	}
	if got.Issuer != thumbprint {
		t.Errorf("JTI issuer = %q, want DPoP key thumbprint %q", got.Issuer, thumbprint)
	}
	if got.Purpose != goidc.JTIUsePurposeDPoPProof {
		t.Errorf("JTI purpose = %q, want %q", got.Purpose, goidc.JTIUsePurposeDPoPProof)
	}
	if got.ExpiresAt.Before(before.Add(-time.Second)) || got.ExpiresAt.After(after) {
		t.Errorf("JTI expiry = %v, want between %v and %v", got.ExpiresAt, before, after)
	}

	ctx.Request = httptest.NewRequest(http.MethodGet, "/token", nil)
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called before HTTP method validation")
		return nil
	}
	if err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{}); err == nil {
		t.Fatal("ValidateJWT() error = nil for invalid HTTP method")
	}
}

func TestValidateJWTTypedJTIConsumerErrors(t *testing.T) {
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    "https://server.example.com/token",
	})
	for _, tc := range []struct {
		name     string
		consume  error
		wantCode goidc.ErrorCode
	}{
		{name: "replay", consume: goidc.ErrJTIReplay, wantCode: goidc.ErrorCodeInvalidRequest},
		{name: "operational failure", consume: errors.New("store unavailable"), wantCode: goidc.ErrorCodeInternalError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs: 60,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
						return tc.consume
					},
				},
				Request: httptest.NewRequest(http.MethodPost, "/token", nil),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{})
			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("error = %v, want goidc.Error", err)
			}
			if oidcErr.Code != tc.wantCode {
				t.Fatalf("error code = %q, want %q (error: %v)", oidcErr.Code, tc.wantCode, err)
			}
			if oidcErr.StatusCode() != tc.wantCode.StatusCode() {
				t.Fatalf("HTTP status = %d, want %d", oidcErr.StatusCode(), tc.wantCode.StatusCode())
			}
		})
	}
}

func TestValidateJWTRejectsProofAtReservationExpiryBoundary(t *testing.T) {
	const lifetime = 60
	issuedAt := time.Now().UTC().Truncate(time.Second).Add(-lifetime * time.Second)
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method:   http.MethodPost,
		URI:      "https://server.example.com/token",
		IssuedAt: issuedAt,
	})
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:            "https://server.example.com",
			DPoPEnabled:     true,
			DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
			JWTLifetimeSecs: lifetime,
			ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
				t.Fatal("expired DPoP proof was reserved")
				return nil
			},
		},
		Request: httptest.NewRequest(http.MethodPost, "/token", nil),
	}

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{})
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error = %v, want goidc.Error", err)
	}
	if oidcErr.Code != goidc.ErrorCodeUnauthorizedClient {
		t.Fatalf("error code = %q, want %q", oidcErr.Code, goidc.ErrorCodeUnauthorizedClient)
	}
}

func TestJWKThumbprint(t *testing.T) {
	// Given.
	dpopSigningAlgorithms := []goidc.SignatureAlgorithm{goidc.SigAlgES256}
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
				got := dpop.JWKThumbprint(testCase.dpopJWT, dpopSigningAlgorithms)

				// Then.
				if got != testCase.expected {
					t.Errorf("JWKThumbprint() = %s, want %s", got, testCase.expected)
				}
			},
		)
	}
}

func TestJWT(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}
	ctx.Request.Header.Set(goidc.HeaderDPoP, "dpop_jwt")

	// When.
	dpopJWT, ok := dpop.JWT(ctx)

	// Then.
	if !ok {
		t.Fatal("the dpop header should be valid")
	}

	if dpopJWT != "dpop_jwt" {
		t.Errorf("JWT() = %s, want dpop_jwt", dpopJWT)
	}
}

func TestJWT_NonCanonical(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}
	ctx.Request.Header.Set("dpOp", "dpop_jwt")

	// When.
	dpopJWT, ok := dpop.JWT(ctx)

	// Then.
	if !ok {
		t.Fatal("the dpop header should be valid")
	}

	if dpopJWT != "dpop_jwt" {
		t.Errorf("JWT() = %s, want dpop_jwt", dpopJWT)
	}
}

func TestJWT_NoHeader(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}

	// When.
	_, ok := dpop.JWT(ctx)

	// Then.
	if ok {
		t.Fatal("the dpop header should not be valid")
	}
}

func TestJWT_MoreThanOneValue(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}
	ctx.Request.Header.Add(goidc.HeaderDPoP, "dpop_jwt")
	ctx.Request.Header.Add("dpOp", "dpop_jwt")

	// When.
	_, ok := dpop.JWT(ctx)

	// Then.
	if ok {
		t.Fatal("the dpop header should not be valid")
	}
}
