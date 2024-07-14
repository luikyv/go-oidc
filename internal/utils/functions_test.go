package utils_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractJARFromRequestObject_SignedRequestObjectHappyPath(t *testing.T) {
	// Given.
	privateJWK := utils.PrivateRS256JWK(t, "client_key_id")
	ctx := &utils.Context{
		Configuration: utils.Configuration{
			Host:                   "https://server.example.com",
			JARIsEnabled:           true,
			JARSignatureAlgorithms: []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJWK.Algorithm())},
			JARLifetimeSecs:        60,
		},
		Request: &http.Request{
			Method: http.MethodPost,
		},
	}

	client := &goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			PublicJWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.Public()},
			},
		},
	}

	createdAtTimestamp := goidc.TimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm()), Key: privateJWK.Key()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID()),
	)
	claims := map[string]any{
		string(goidc.ClaimIssuer):   client.ID,
		string(goidc.ClaimAudience): ctx.Host,
		string(goidc.ClaimIssuedAt): createdAtTimestamp,
		string(goidc.ClaimExpiry):   createdAtTimestamp + ctx.JARLifetimeSecs - 1,
		"client_id":                 client.ID,
		"redirect_uri":              "https://example.com",
		"response_type":             goidc.ResponseTypeCode,
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

	// When.
	jar, err := utils.JARFromRequestObject(ctx, request, client)

	// Then.
	require.Nil(t, err, "error extracting JAR")
	assert.Equal(t, client.ID, jar.ClientID, "invalid JAR client_id")
	assert.Equal(t, goidc.ResponseTypeCode, jar.ResponseType, "invalid JAR response_type")
}

func TestValidateDPOPJWT(t *testing.T) {

	var testCases = []struct {
		Name           string
		DPOPJWT        string
		ExpectedClaims utils.DPOPJWTValidationOptions
		Context        *utils.Context
		ShouldBeValid  bool
	}{
		{
			"valid_dpop_jwt",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			utils.DPOPJWTValidationOptions{},
			&utils.Context{
				Configuration: utils.Configuration{
					Host:                    "https://server.example.com",
					DPOPIsEnabled:           true,
					DPOPSignatureAlgorithms: []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256},
					DPOPLifetimeSecs:        99999999999,
				},
				Request: &http.Request{
					Method: http.MethodPost,
				},
			},
			true,
		},
		{
			"valid_dpop_jwt_with_ath",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
			utils.DPOPJWTValidationOptions{
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			},
			&utils.Context{
				Configuration: utils.Configuration{
					Host:                    "https://resource.example.org/protectedresource",
					DPOPIsEnabled:           true,
					DPOPSignatureAlgorithms: []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256},
					DPOPLifetimeSecs:        99999999999,
				},
				Request: &http.Request{
					Method: http.MethodGet,
				},
			},
			true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				// When.
				err := utils.ValidateDPOPJWT(testCase.Context, testCase.DPOPJWT, testCase.ExpectedClaims)

				// Then.
				assert.Equal(t, testCase.ShouldBeValid, err == nil)
			},
		)
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	// When.
	token, err := utils.RefreshToken()

	// Then.
	assert.Nil(t, err)
	assert.Len(t, token, goidc.RefreshTokenLength)
}

func TestGetURLWithQueryParams(t *testing.T) {
	testCases := []struct {
		URL                      string
		params                   map[string]string
		ExpectedParameterizedURL string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example?param1=value1"},
		{"http://example?param=value", map[string]string{"param1": "value1"}, "http://example?param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example?param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.ExpectedParameterizedURL, utils.URLWithQueryParams(testCase.URL, testCase.params))
		})
	}

}

func TestGetURLWithFragmentParams(t *testing.T) {
	testCases := []struct {
		URL                      string
		params                   map[string]string
		ExpectedParameterizedURL string
	}{
		{"http://example", map[string]string{"param1": "value1"}, "http://example#param1=value1"},
		{"http://example#param=value", map[string]string{"param1": "value1"}, "http://example#param=value&param1=value1"},
		{"http://example", map[string]string{"param1": "value1", "param2": "value2"}, "http://example#param1=value1&param2=value2"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.ExpectedParameterizedURL, utils.URLWithFragmentParams(testCase.URL, testCase.params))
		})
	}

}

func TestGetURLWithoutParams(t *testing.T) {
	testCases := []struct {
		url         string
		expectedURL string
	}{
		{"http://example#param1=value1", "http://example"},
		{"http://example#param=value&param1=value1", "http://example"},
		{"http://example#param1=value1&param2=value2", "http://example"},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			// When.
			urlWithoutParams, err := utils.URLWithoutParams(testCase.url)
			// Assert.
			require.Nil(t, err)
			assert.Equal(t, testCase.expectedURL, urlWithoutParams)
		})
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
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.isValid, utils.IsPkceValid(testCase.codeVerifier, testCase.codeChallenge, testCase.codeChallengeMethod))
		})
	}
}

func TestAll(t *testing.T) {
	// When.
	ok := utils.All([]string{"a", "b", "c"}, func(s string) bool {
		return s == "b"
	})
	// Then.
	assert.False(t, ok, "not all the elements respect the condition")

	// When.
	ok = utils.All([]int{1, 2, 3}, func(i int) bool {
		return i > 0
	})
	// Then.
	assert.True(t, ok, "all the elements respect the condition")

	// When.
	ok = utils.All([]int{1, 2, 3}, func(i int) bool {
		return i == 4
	})
	// Then.
	assert.False(t, ok, "not all the elements respect the condition")
}

func TestAllEquals(t *testing.T) {
	testCases := []struct {
		values           []string
		allShouldBeEqual bool
	}{
		{[]string{"id1", "id1", "id1"}, true},
		{[]string{"id1"}, true},
		{[]string{}, true},
		{[]string{"id1", "id1", "id2"}, false},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i+1), func(t *testing.T) {
			assert.Equal(t, testCase.allShouldBeEqual, utils.AllEquals(testCase.values))
		})
	}
}

func TestGenerateJWKThumbprint(t *testing.T) {
	dpopSigningAlgorithms := []jose.SignatureAlgorithm{jose.ES256}
	testCases := []struct {
		DPOPJWT            string
		ExpectedThumbprint string
	}{
		{
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.ExpectedThumbprint, utils.JWKThumbprint(testCase.DPOPJWT, dpopSigningAlgorithms))
		})
	}
}

func TestIsJWS(t *testing.T) {
	testCases := []struct {
		jws         string
		shouldBeJWS bool
	}{
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		{"not a jwt", false},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i+1), func(t *testing.T) {
			assert.Equal(t, testCase.shouldBeJWS, utils.IsJWS(testCase.jws))
		})
	}
}

func TestIsJWE(t *testing.T) {
	testCases := []struct {
		jwe         string
		shouldBeJWE bool
	}{
		{"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_.XFBoMYUZodetZdvTiFvSkQ", true},
		{"not a jwt", false},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i+1), func(t *testing.T) {
			assert.Equal(t, testCase.shouldBeJWE, utils.IsJWE(testCase.jwe))
		})
	}
}
