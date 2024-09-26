package dpop_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
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
					Host:             "https://server.example.com",
					DPoPIsEnabled:    true,
					DPoPSigAlgs:      []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256},
					DPoPLifetimeSecs: 99999999999,
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
					Host:             "https://resource.example.org",
					DPoPIsEnabled:    true,
					DPoPSigAlgs:      []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256},
					DPoPLifetimeSecs: 99999999999,
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

func TestJWKThumbprint(t *testing.T) {
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
