package joseutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Sign(
	ctx oidc.Context,
	claims map[string]any,
	alg goidc.SignatureAlgorithm,
	opts *jose.SignerOptions,
) (
	string,
	error,
) {
	if ctx.SignerFunc == nil {
		jwk, err := ctx.JWKByAlg(alg)
		if err != nil {
			return "", fmt.Errorf("could not load the signing jwk: %w", err)
		}
		return SignWithJWK(claims, jwk, opts)
	}

	keyID, key, err := ctx.SignerFunc(ctx, alg)
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	opts = fillOptions(opts, keyID, string(alg))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", err
	}

	jws, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", err
	}

	return jws, nil
}

func SignWithJWK(
	claims any,
	jwk goidc.JSONWebKey,
	opts *jose.SignerOptions,
) (
	string,
	error,
) {
	opts = fillOptions(opts, jwk.KeyID, jwk.Algorithm)
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
			Key:       jwk,
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

func fillOptions(opts *jose.SignerOptions, kid, alg string) *jose.SignerOptions {
	if opts == nil {
		opts = &jose.SignerOptions{}
	}
	opts = opts.WithHeader("kid", kid).WithHeader("alg", alg)
	// If the "typ" header was not informed, default to JWT.
	if _, ok := opts.ExtraHeaders[jose.HeaderType]; !ok {
		opts = opts.WithType("JWT")
	}

	return opts
}

func Decrypt(
	ctx oidc.Context,
	jwe string,
	keyAlgs []goidc.KeyEncryptionAlgorithm,
	contentAlgs []goidc.ContentEncryptionAlgorithm,
) (
	string,
	error,
) {
	parseJWE, err := jose.ParseEncrypted(jwe, keyAlgs, contentAlgs)
	if err != nil {
		return "", fmt.Errorf("could not parse the jwe: %w", err)
	}

	keyID := parseJWE.Header.KeyID
	if keyID == "" {
		return "", errors.New("invalid jwe key ID")
	}

	var key any
	if ctx.DecrypterFunc != nil {
		alg := goidc.KeyEncryptionAlgorithm(parseJWE.Header.Algorithm)
		decrypter, err := ctx.DecrypterFunc(ctx, keyID, alg)
		if err != nil {
			return "", fmt.Errorf("could not load the decrypter: %w", err)
		}
		key = opaqueDecrypter{alg: alg, decrypter: decrypter}
	} else {
		jwk, err := ctx.JWK(keyID)
		if err != nil || jwk.Use != string(goidc.KeyUsageEncryption) {
			return "", errors.New("invalid jwk used for encryption")
		}
		key = jwk
	}

	jws, err := parseJWE.Decrypt(key)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the jwe: %w", err)
	}

	return string(jws), nil
}

type opaqueDecrypter struct {
	alg       goidc.KeyEncryptionAlgorithm
	decrypter crypto.Decrypter
}

func (o opaqueDecrypter) DecryptKey(encryptedKey []byte, _ jose.Header) ([]byte, error) {
	var opts crypto.DecrypterOpts
	switch o.alg {
	case goidc.RSA_OAEP:
		opts = &rsa.OAEPOptions{
			Hash: crypto.SHA1,
		}
	case goidc.RSA_OAEP_256:
		opts = &rsa.OAEPOptions{
			Hash: crypto.SHA256,
		}
	default:
	}
	return o.decrypter.Decrypt(rand.Reader, encryptedKey, opts)
}

func Encrypt(
	jws string,
	jwk goidc.JSONWebKey,
	cntAlg goidc.ContentEncryptionAlgorithm,
) (
	string,
	error,
) {
	encrypter, err := jose.NewEncrypter(
		cntAlg,
		jose.Recipient{
			Algorithm: goidc.KeyEncryptionAlgorithm(jwk.Algorithm),
			Key:       jwk.Key,
			KeyID:     jwk.KeyID,
		},
		(&jose.EncrypterOptions{}).WithType("jwt").WithContentType("jwt"),
	)
	if err != nil {
		return "", err
	}

	encContent, err := encrypter.Encrypt([]byte(jws))
	if err != nil {
		return "", err
	}

	encContentString, err := encContent.CompactSerialize()
	if err != nil {
		return "", err
	}

	return encContentString, nil
}

func Unsigned(claims map[string]any) string {
	header := map[string]any{
		"alg": goidc.None,
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64 + "."
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
