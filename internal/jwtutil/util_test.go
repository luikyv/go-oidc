package jwtutil_test

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSign(t *testing.T) {
	// Given.
	jwk := oidctest.PrivatePS256JWK(t, "key_id", goidc.KeyUsageSignature)
	claims := map[string]any{
		"claim": "value",
	}

	// When.
	jws, err := jwtutil.Sign(claims, jwk,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID))

	// Then.
	if err != nil {
		t.Fatalf("unexpected error signing the claims: %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(
		jws,
		[]jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwk.Algorithm)},
	)
	if err != nil {
		t.Fatalf("the jws is not valid: %v", err)
	}

	var parsedClaims map[string]any
	err = parsedJWS.Claims(jwk.Public().Key, &parsedClaims)
	if err != nil {
		t.Fatalf("the jws is not valid: %v", err)
	}

	if parsedClaims["claim"] != "value" {
		t.Errorf("claim = %v, want %s", parsedClaims["claim"], "value")
	}
}

func TestUnsigned(t *testing.T) {
	// Given.
	claims := map[string]interface{}{
		"sub": "random_subject",
	}

	// When.
	unsignedJWT, err := jwtutil.Unsigned(claims)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "eyJhbGciOiJub25lIiwidHlwIjoiand0In0.eyJzdWIiOiJyYW5kb21fc3ViamVjdCJ9."
	if unsignedJWT != want {
		t.Errorf("unsignedJWT = %s, want %s", unsignedJWT, want)
	}
}

func TestEncrypt(t *testing.T) {
	// Given.
	jwk := oidctest.PrivateRSAOAEPJWK(t, "enc_key")

	// When.
	encryptedStr, err := jwtutil.Encrypt("test", jwk.Public(), jose.A128CBC_HS256)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jwe, err := jose.ParseEncrypted(
		encryptedStr,
		[]jose.KeyAlgorithm{jose.RSA_OAEP},
		[]jose.ContentEncryption{jose.A128CBC_HS256},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decryptedStr, err := jwe.Decrypt(jwk.Key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(decryptedStr) != "test" {
		t.Errorf("got = %s, want = %s", decryptedStr, "test")
	}
}

func TestIsJWS(t *testing.T) {
	testCases := []struct {
		jws      string
		expected bool
	}{
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		{"not a jwt", false},
		{"eyJhbGciOiJub25lIiwidHlwIjoiand0In0.eyJzdWIiOiJyYW5kb21fc3ViamVjdCJ9.", false},
		{"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_.XFBoMYUZodetZdvTiFvSkQ", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				got := jwtutil.IsJWS(testCase.jws)
				if got != testCase.expected {
					t.Errorf("IsJWS() = %t, want %t", got, testCase.expected)
				}
			},
		)
	}
}

func TestIsUnsignedJWT(t *testing.T) {
	testCases := []struct {
		jws      string
		expected bool
	}{
		{"eyJhbGciOiJub25lIiwidHlwIjoiand0In0.eyJzdWIiOiJyYW5kb21fc3ViamVjdCJ9.", true},
		{"not a jwt", false},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
		{"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_.XFBoMYUZodetZdvTiFvSkQ", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				got := jwtutil.IsUnsignedJWT(testCase.jws)
				if got != testCase.expected {
					t.Errorf("IsUnsignedJWT() = %t, want %t", got, testCase.expected)
				}
			},
		)
	}
}

func TestIsJWE(t *testing.T) {
	testCases := []struct {
		jwe      string
		expected bool
	}{
		{"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_.XFBoMYUZodetZdvTiFvSkQ", true},
		{"not a jwt", false},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				got := jwtutil.IsJWE(testCase.jwe)
				if got != testCase.expected {
					t.Errorf("IsJWE() = %t, want %t", got, testCase.expected)
				}
			},
		)
	}
}
