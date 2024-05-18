package utils_test

import (
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestExtractJarFromRequestObject(t *testing.T) {
	// When
	privateJwk := unit.GetTestPrivateRs256Jwk("rsa256_key")
	ctx := utils.GetDummyTestContext()
	ctx.JarAlgorithms = []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJwk.Algorithm)}
	client := models.GetNoneAuthTestClient()
	client.PublicJwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJwk.Public()}}

	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJwk.Algorithm), Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	claims := map[string]any{
		string(constants.IssuerClaim):   client.Id,
		string(constants.AudienceClaim): ctx.Host,
		string(constants.IssuedAtClaim): createdAtTimestamp,
		string(constants.ExpiryClaim):   createdAtTimestamp + 60, // TODO: When the jar expires?
		"client_id":                     client.Id,
		"response_type":                 constants.CodeResponse,
	}
	request, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// Then
	jar, err := utils.ExtractJarFromRequestObject(ctx, request, client)

	// Assert
	if err != nil {
		t.Errorf("error extracting JAR. Error: %s", err.Error())
		return
	}

	if jar.ClientId != client.Id {
		t.Errorf("Invalid JAR client_id. JAR: %v", jar)
		return
	}

	if jar.ResponseType != constants.CodeResponse {
		t.Errorf("Invalid JAR response_type. JAR: %v", jar)
		return
	}
}

func TestValidateDpopJwt(t *testing.T) {
	ctx := utils.GetDummyTestContext()
	ctx.DpopSigningAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256}

	var testCases = []struct {
		Name           string
		DpopJwt        string
		ExpectedClaims models.DpopClaims
		ShouldBeValid  bool
	}{
		{
			"valid_dpop_jwt",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			models.DpopClaims{
				HttpMethod: http.MethodPost,
				HttpUri:    "https://server.example.com/token",
			},
			true,
		},
		{
			"valid_dpop_jwt_with_ath",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
			models.DpopClaims{
				HttpMethod:  http.MethodGet,
				HttpUri:     "https://resource.example.org/protectedresource",
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			},
			true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				// Then.
				err := utils.ValidateDpopJwt(ctx, testCase.DpopJwt, testCase.ExpectedClaims)

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
