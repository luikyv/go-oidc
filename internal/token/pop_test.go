package token

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
)

func TestValidateDPoPJWT(t *testing.T) {

	var testCases = []struct {
		name          string
		dpopJWT       string
		opts          dpopValidationOptions
		ctx           *oidc.Context
		shouldBeValid bool
	}{
		{
			"valid_dpop_jwt",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			dpopValidationOptions{},
			&oidc.Context{
				Configuration: oidc.Configuration{
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
			dpopValidationOptions{
				accessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			},
			&oidc.Context{
				Configuration: oidc.Configuration{
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
				err := validateDPoPJWT(testCase.ctx, testCase.dpopJWT, testCase.opts)

				// Then.
				isValid := err == nil
				if isValid != testCase.shouldBeValid {
					t.Errorf("isValid = %t, want %t", isValid, testCase.shouldBeValid)
				}
			},
		)
	}
}