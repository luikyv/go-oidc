package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Sign(
	claims map[string]any,
	jwk jose.JSONWebKey,
	opts *jose.SignerOptions,
) (
	string,
	error,
) {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
			Key:       jwk.Key,
		},
		opts,
	)
	if err != nil {
		return "", err
	}

	jws, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", err
	}

	return jws, nil
}

func Encrypt(
	content string,
	jwk jose.JSONWebKey,
	alg jose.ContentEncryption,
) (
	string,
	error,
) {
	encrypter, err := jose.NewEncrypter(
		alg,
		jose.Recipient{
			Algorithm: jose.KeyAlgorithm(jwk.Algorithm),
			Key:       jwk.Key,
			KeyID:     jwk.KeyID,
		},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", err
	}

	encContent, err := encrypter.Encrypt([]byte(content))
	if err != nil {
		return "", err
	}

	encContentString, err := encContent.CompactSerialize()
	if err != nil {
		return "", err
	}

	return encContentString, nil
}

func Unsigned(claims map[string]any) (string, error) {
	header := map[string]any{
		"alg": goidc.NoneSignatureAlgorithm,
		"typ": "jwt",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return fmt.Sprintf("%s.%s.", encodedHeader, encodedClaims), nil
}

func IsUnsignedJWT(token string) bool {
	isJWS, _ := regexp.MatchString(
		"(^[\\w-]+\\.[\\w-]+\\.$)",
		token,
	)
	return isJWS
}

func IsJWS(token string) bool {
	isJWS, _ := regexp.MatchString(
		"(^[\\w-]+\\.[\\w-]+\\.[\\w-]+$)",
		token,
	)
	return isJWS
}

func IsJWE(token string) bool {
	isJWS, _ := regexp.MatchString(
		"(^[\\w-]+\\.[\\w-]+\\.[\\w-]+\\.[\\w-]+\\.[\\w-]+$)",
		token,
	)
	return isJWS
}
