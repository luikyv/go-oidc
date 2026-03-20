package joseutil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestOpaqueSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer := joseutil.OpaqueSigner{
		ID:        "test-key",
		Algorithm: goidc.RS256,
		Signer:    key,
	}

	t.Run("public", func(t *testing.T) {
		pub := signer.Public()
		if pub.KeyID != "test-key" {
			t.Errorf("KeyID = %s, want test-key", pub.KeyID)
		}
		if pub.Algorithm != string(goidc.RS256) {
			t.Errorf("Algorithm = %s, want RS256", pub.Algorithm)
		}
	})

	t.Run("algs", func(t *testing.T) {
		algs := signer.Algs()
		if len(algs) != 1 || algs[0] != goidc.RS256 {
			t.Errorf("Algs() = %v, want [RS256]", algs)
		}
	})

	t.Run("sign_and_verify", func(t *testing.T) {
		claims := map[string]any{"sub": "test"}
		jws, err := joseutil.Sign(claims, jose.SigningKey{Algorithm: jose.RS256, Key: &joseutil.OpaqueSigner{
			ID:        "test-key",
			Algorithm: goidc.RS256,
			Signer:    key,
		}}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		parsed, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.RS256})
		if err != nil {
			t.Fatalf("unexpected error parsing JWS: %v", err)
		}

		var got map[string]any
		if err := parsed.Claims(&key.PublicKey, &got); err != nil {
			t.Fatalf("unexpected error extracting claims: %v", err)
		}
		if got["sub"] != "test" {
			t.Errorf("sub = %v, want test", got["sub"])
		}
	})
}

func TestOpaqueSigner_PS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{"sub": "test"}
	jws, err := joseutil.Sign(claims, jose.SigningKey{Algorithm: jose.PS256, Key: &joseutil.OpaqueSigner{
		ID:        "ps-key",
		Algorithm: goidc.PS256,
		Signer:    key,
	}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.PS256})
	if err != nil {
		t.Fatalf("unexpected error parsing JWS: %v", err)
	}

	var got map[string]any
	if err := parsed.Claims(&key.PublicKey, &got); err != nil {
		t.Fatalf("unexpected error extracting claims: %v", err)
	}
	if got["sub"] != "test" {
		t.Errorf("sub = %v, want test", got["sub"])
	}
}

func TestOpaqueDecrypter_RSA_OAEP(t *testing.T) {
	jwk := oidctest.PrivateRSAOAEPJWK(t, "dec-key")

	encrypted, err := joseutil.Encrypt("secret-payload", jwk.Public(), goidc.A128CBC_HS256)
	if err != nil {
		t.Fatalf("unexpected error encrypting: %v", err)
	}

	rsaKey := jwk.Key.(*rsa.PrivateKey)
	decrypter := &joseutil.OpaqueDecrypter{
		Algorithm: goidc.RSA_OAEP,
		Decrypter: rsaKey,
	}

	jwe, err := jose.ParseEncrypted(
		encrypted,
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)
	if err != nil {
		t.Fatalf("unexpected error parsing JWE: %v", err)
	}

	decrypted, err := jwe.Decrypt(decrypter)
	if err != nil {
		t.Fatalf("unexpected error decrypting: %v", err)
	}

	if string(decrypted) != "secret-payload" {
		t.Errorf("decrypted = %s, want secret-payload", decrypted)
	}
}

func TestOpaqueDecrypter_RSA_OAEP_256(t *testing.T) {
	jwk := oidctest.PrivateRSAOAEP256JWK(t, "dec-key-256")

	encrypted, err := joseutil.Encrypt("secret-256", jwk.Public(), goidc.A128CBC_HS256)
	if err != nil {
		t.Fatalf("unexpected error encrypting: %v", err)
	}

	rsaKey := jwk.Key.(*rsa.PrivateKey)
	decrypter := &joseutil.OpaqueDecrypter{
		Algorithm: goidc.RSA_OAEP_256,
		Decrypter: rsaKey,
	}

	jwe, err := jose.ParseEncrypted(
		encrypted,
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)
	if err != nil {
		t.Fatalf("unexpected error parsing JWE: %v", err)
	}

	decrypted, err := jwe.Decrypt(decrypter)
	if err != nil {
		t.Fatalf("unexpected error decrypting: %v", err)
	}

	if string(decrypted) != "secret-256" {
		t.Errorf("decrypted = %s, want secret-256", decrypted)
	}
}

func TestKeyByAlgorithms(t *testing.T) {
	jwk1 := oidctest.PrivateRS256JWK(t, "rs256-key", goidc.KeyUsageSignature)
	jwk2 := oidctest.PrivatePS256JWK(t, "ps256-key", goidc.KeyUsageSignature)
	jwks := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk1, jwk2}}

	t.Run("match_first", func(t *testing.T) {
		got, err := joseutil.KeyByAlgorithms(jwks, []goidc.SignatureAlgorithm{goidc.RS256})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.KeyID != "rs256-key" {
			t.Errorf("KeyID = %s, want rs256-key", got.KeyID)
		}
	})

	t.Run("match_second", func(t *testing.T) {
		got, err := joseutil.KeyByAlgorithms(jwks, []goidc.SignatureAlgorithm{goidc.PS256})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.KeyID != "ps256-key" {
			t.Errorf("KeyID = %s, want ps256-key", got.KeyID)
		}
	})

	t.Run("match_fallback", func(t *testing.T) {
		got, err := joseutil.KeyByAlgorithms(jwks, []goidc.SignatureAlgorithm{goidc.ES256, goidc.PS256})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.KeyID != "ps256-key" {
			t.Errorf("KeyID = %s, want ps256-key", got.KeyID)
		}
	})

	t.Run("no_match", func(t *testing.T) {
		_, err := joseutil.KeyByAlgorithms(jwks, []goidc.SignatureAlgorithm{goidc.ES256})
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestKeyUsage(t *testing.T) {
	testCases := []struct {
		name string
		key  goidc.JSONWebKey
		want goidc.KeyUsage
	}{
		{
			name: "explicit_sig_use",
			key:  goidc.JSONWebKey{Use: "sig"},
			want: goidc.KeyUsageSignature,
		},
		{
			name: "explicit_enc_use",
			key:  goidc.JSONWebKey{Use: "enc"},
			want: goidc.KeyUsageEncryption,
		},
		{
			name: "rs256_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.RS256)},
			want: goidc.KeyUsageSignature,
		},
		{
			name: "es256_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.ES256)},
			want: goidc.KeyUsageSignature,
		},
		{
			name: "ps256_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.PS256)},
			want: goidc.KeyUsageSignature,
		},
		{
			name: "hs256_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.HS256)},
			want: goidc.KeyUsageSignature,
		},
		{
			name: "rsa_oaep_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.RSA_OAEP)},
			want: goidc.KeyUsageEncryption,
		},
		{
			name: "rsa_oaep_256_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.RSA_OAEP_256)},
			want: goidc.KeyUsageEncryption,
		},
		{
			name: "rsa1_5_algorithm",
			key:  goidc.JSONWebKey{Algorithm: string(goidc.RSA1_5)},
			want: goidc.KeyUsageEncryption,
		},
		{
			name: "unknown_algorithm",
			key:  goidc.JSONWebKey{Algorithm: "unknown"},
			want: "",
		},
		{
			name: "explicit_use_overrides_algorithm",
			key:  goidc.JSONWebKey{Use: "enc", Algorithm: string(goidc.RS256)},
			want: goidc.KeyUsageEncryption,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := joseutil.KeyUsage(tc.key)
			if got != tc.want {
				t.Errorf("KeyUsage() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSign(t *testing.T) {
	// Given.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := goidc.JSONWebKey{
		KeyID:     "key_id",
		Key:       key.Public(),
		Algorithm: "RS256",
	}
	claims := map[string]any{
		"claim": "value",
	}

	// When.
	jws, err := joseutil.Sign(claims, jose.SigningKey{Algorithm: "RS256", Key: key}, nil)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error signing the claims: %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.RS256})
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
	unsignedJWT := joseutil.Unsigned(claims, nil)

	// Then.
	want := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJyYW5kb21fc3ViamVjdCJ9."
	if unsignedJWT != want {
		t.Errorf("unsignedJWT = %s, want %s", unsignedJWT, want)
	}
}

func TestEncrypt(t *testing.T) {
	// Given.
	jwk := oidctest.PrivateRSAOAEPJWK(t, "enc_key")

	// When.
	encryptedStr, err := joseutil.Encrypt("test", jwk.Public(), goidc.A128CBC_HS256)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jwe, err := jose.ParseEncrypted(
		encryptedStr,
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
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
				got := joseutil.IsJWS(testCase.jws)
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
				got := joseutil.IsUnsignedJWT(testCase.jws)
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
				got := joseutil.IsJWE(testCase.jwe)
				if got != testCase.expected {
					t.Errorf("IsJWE() = %t, want %t", got, testCase.expected)
				}
			},
		)
	}
}
