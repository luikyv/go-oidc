package utils_test

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestExtractJarFromRequestObject_SignedRequestObjectHappyPath(t *testing.T) {
	// When.
	privateJwk := unit.GetTestPrivateRs256Jwk("client_key_id")
	ctx := utils.GetTestInMemoryContext()
	ctx.JarIsEnabled = true
	ctx.JarSignatureAlgorithms = []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJwk.GetAlgorithm())}
	ctx.JarLifetimeSecs = 60
	client := models.Client{
		ClientMetaInfo: models.ClientMetaInfo{
			PublicJwks: &goidc.JsonWebKeySet{
				Keys: []goidc.JsonWebKey{privateJwk.GetPublic()},
			},
		},
	}

	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJwk.GetAlgorithm()), Key: privateJwk.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.GetKeyId()),
	)
	claims := map[string]any{
		string(goidc.IssuerClaim):   client.Id,
		string(goidc.AudienceClaim): ctx.Host,
		string(goidc.IssuedAtClaim): createdAtTimestamp,
		string(goidc.ExpiryClaim):   createdAtTimestamp + ctx.JarLifetimeSecs - 1,
		"client_id":                 client.Id,
		"redirect_uri":              "https://example.com",
		"response_type":             goidc.CodeResponse,
		"scope":                     "scope scope2",
		"max_age":                   600,
		"acr_values":                "0 1",
		"claims": map[string]any{
			"userinfo": map[string]any{
				"acr": map[string]any{
					"value": "0",
				},
			},
		},
	}
	request, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// Then.
	jar, err := utils.ExtractJarFromRequestObject(ctx, request, client)

	// Assert.
	if err != nil {
		t.Errorf("error extracting JAR. Error: %s", err.Error())
		return
	}

	if jar.ClientId != client.Id {
		t.Errorf("Invalid JAR client_id. JAR: %v", jar)
		return
	}

	if jar.ResponseType != goidc.CodeResponse {
		t.Errorf("Invalid JAR response_type. JAR: %v", jar)
		return
	}
}

func TestValidateDpopJwt(t *testing.T) {

	var testCases = []struct {
		Name           string
		DpopJwt        string
		ExpectedClaims models.DpopJwtValidationOptions
		Context        utils.Context
		ShouldBeValid  bool
	}{
		{
			"valid_dpop_jwt",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			models.DpopJwtValidationOptions{},
			utils.Context{
				Configuration: utils.Configuration{
					Host:                    "https://server.example.com",
					DpopIsEnabled:           true,
					DpopSignatureAlgorithms: []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256},
					DpopLifetimeSecs:        99999999999,
				},
				Request: &http.Request{
					Method: http.MethodPost,
				},
				Logger: slog.Default(),
			},
			true,
		},
		{
			"valid_dpop_jwt_with_ath",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
			models.DpopJwtValidationOptions{
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			},
			utils.Context{
				Configuration: utils.Configuration{
					Host:                    "https://resource.example.org/protectedresource",
					DpopIsEnabled:           true,
					DpopSignatureAlgorithms: []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256},
					DpopLifetimeSecs:        99999999999,
				},
				Request: &http.Request{
					Method: http.MethodGet,
				},
				Logger: slog.Default(),
			},
			true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				// When.
				// ctx.Request.Method = testCase.ExpectedClaims

				// Then.
				err := utils.ValidateDpopJwt(testCase.Context, testCase.DpopJwt, testCase.ExpectedClaims)

				// Assert.
				isValid := err == nil
				if isValid != testCase.ShouldBeValid {
					t.Errorf("expected: %v - actual: %v - error: %s", testCase.ShouldBeValid, isValid, err)
					return
				}
			},
		)
	}
}
