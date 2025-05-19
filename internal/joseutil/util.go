package joseutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Sign(claims any, signer jose.SigningKey, opts *jose.SignerOptions) (string, error) {
	if opts == nil {
		opts = &jose.SignerOptions{}
	}
	if _, ok := opts.ExtraHeaders[jose.HeaderType]; !ok {
		opts = opts.WithType("JWT")
	}

	joseSigner, err := jose.NewSigner(signer, opts)
	if err != nil {
		return "", err
	}

	jws, err := jwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		return "", err
	}

	return jws, nil
}

type OpaqueSigner struct {
	ID        string
	Algorithm goidc.SignatureAlgorithm
	Signer    crypto.Signer
}

func (s OpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID:     s.ID,
		Key:       s.Signer.Public(),
		Algorithm: string(s.Algorithm),
	}
}

func (s OpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{s.Algorithm}
}

func (s OpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	h := hashutil.HashAlg(alg)
	hasher := h.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	var opts crypto.SignerOpts = h
	if alg == jose.PS256 || alg == jose.PS384 || alg == jose.PS512 {
		opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       h,
		}
	}

	return s.Signer.Sign(rand.Reader, digest, opts)
}

type OpaqueDecrypter struct {
	Algorithm goidc.KeyEncryptionAlgorithm
	Decrypter crypto.Decrypter
}

func (o OpaqueDecrypter) DecryptKey(encryptedKey []byte, _ jose.Header) ([]byte, error) {
	var opts crypto.DecrypterOpts
	switch o.Algorithm {
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
	return o.Decrypter.Decrypt(rand.Reader, encryptedKey, opts)
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
