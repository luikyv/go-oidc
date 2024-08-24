package clientauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

// Authenticated fetches a client associated to the request and returns it
// if the client is authenticated according to its authentication method.
func Authenticated(
	ctx *oidc.Context,
) (
	*goidc.Client,
	error,
) {
	id, err := extractID(ctx)
	if err != nil {
		return nil, err
	}

	client, err := ctx.Client(id)
	if err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeInvalidClient, "client not found", err)
	}

	if err := authenticate(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

func authenticate(
	ctx *oidc.Context,
	client *goidc.Client,
) error {
	switch client.AuthnMethod {
	case goidc.ClientAuthnNone:
		return nil
	case goidc.ClientAuthnSecretPost:
		return authenticateSecretPost(ctx, client)
	case goidc.ClientAuthnSecretBasic:
		return authenticateSecretBasic(ctx, client)
	case goidc.ClientAuthnPrivateKeyJWT:
		return authenticatePrivateKeyJWT(ctx, client)
	case goidc.ClientAuthnSecretJWT:
		return authenticateSecretJWT(ctx, client)
	case goidc.ClientAuthnSelfSignedTLS:
		return authenticateSelfSignedTLSCert(ctx, client)
	case goidc.ClientAuthnTLS:
		return authenticateTLSCert(ctx, client)
	default:
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid authentication method")
	}
}

func authenticateSecretPost(
	ctx *oidc.Context,
	c *goidc.Client,
) error {

	if c.ID != ctx.Request().PostFormValue(idFormPostParam) {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid client id")
	}

	secret := ctx.Request().PostFormValue(secretFormPostParam)
	if secret == "" {
		return oidcerr.New(oidcerr.CodeInvalidClient, "client secret not informed")
	}
	return validateSecret(c, secret)
}

func authenticateSecretBasic(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	id, secret, ok := ctx.Request().BasicAuth()
	if !ok {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"client basic authentication not informed")
	}

	if c.ID != id {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid client id")
	}

	return validateSecret(c, secret)
}

func validateSecret(
	client *goidc.Client,
	secret string,
) error {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedSecret), []byte(secret))
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient, "invalid client secret", err)
	}
	return nil
}

func authenticatePrivateKeyJWT(
	ctx *oidc.Context,
	c *goidc.Client,
) error {

	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := ctx.ClientAuthn.PrivateKeyJWTSigAlgs
	if c.AuthnSignatureAlgorithm != "" {
		sigAlgs = []jose.SignatureAlgorithm{c.AuthnSignatureAlgorithm}
	}
	assertionJWT, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not parse the client assertion", err)
	}

	// Verify that the assertion has only one header.
	if len(assertionJWT.Headers) != 1 {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"invalid client assertion header")
	}

	// Try to find the jwk used to sign the assertion by key id or algorithm.
	var jwk jose.JSONWebKey
	if assertionJWT.Headers[0].KeyID != "" {
		jwk, err = c.PublicKey(assertionJWT.Headers[0].KeyID)
	} else {
		alg := jose.SignatureAlgorithm(assertionJWT.Headers[0].Algorithm)
		jwk, err = c.SignatureJWK(alg)
	}
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not identify the jwk used to sign the assertion", err)
	}

	claims := jwt.Claims{}
	if err := assertionJWT.Claims(jwk.Key, &claims); err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not parse the client assertion claims", err)
	}

	return areClaimsValid(ctx, c, claims)
}

func authenticateSecretJWT(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := ctx.ClientAuthn.ClientSecretJWTSigAlgs
	if c.AuthnSignatureAlgorithm != "" {
		sigAlgs = []jose.SignatureAlgorithm{c.AuthnSignatureAlgorithm}
	}
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not parse the client assertion", err)
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims([]byte(c.Secret), &claims); err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not parse the client assertion claims", err)
	}

	return areClaimsValid(ctx, c, claims)
}

func assertion(ctx *oidc.Context) (string, error) {
	if ctx.Request().PostFormValue(assertionFormPostParam) != string(goidc.AssertionTypeJWTBearer) {
		return "", oidcerr.New(oidcerr.CodeInvalidClient,
			"invalid assertion_type")
	}

	assertion := ctx.Request().PostFormValue(assertionFormPostParam)
	if assertion == "" {
		return "", oidcerr.New(oidcerr.CodeInvalidClient,
			"client_assertion not informed")
	}

	return assertion, nil
}

func areClaimsValid(
	ctx *oidc.Context,
	client *goidc.Client,
	claims jwt.Claims,
) error {

	if claims.Expiry == nil {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"claim 'exp' is missing in the client assertion")
	}

	if claims.IssuedAt == nil {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"claim 'iat' is missing in the client assertion")
	}

	// Validate that the difference between "iat" and "exp" is not too great.
	if int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > ctx.ClientAuthn.AssertionLifetimeSecs {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"the assertion has a life time more than allowed")
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		Subject:     client.ID,
		AnyAudience: ctx.Audiences(),
	}, time.Duration(0))
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInvalidClient, "invalid assertion", err)
	}
	return nil
}

func authenticateSelfSignedTLSCert(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	if c.ID != ctx.Request().PostFormValue(idFormPostParam) {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid client id")
	}

	cert, ok := ctx.ClientCertificate()
	if !ok {
		return oidcerr.New(oidcerr.CodeInvalidClient, "client certificate not informed")
	}

	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return oidcerr.Errorf(oidcerr.CodeInternalError, "could not load the client JWKS", err)
	}

	var jwk jose.JSONWebKey
	foundMatchingJWK := false
	for _, key := range jwks.Keys {
		if string(key.CertificateThumbprintSHA256) == hashSHA256(cert.Raw) ||
			string(key.CertificateThumbprintSHA1) == hashSHA1(cert.Raw) {
			foundMatchingJWK = true
			jwk = key
		}
	}

	if !foundMatchingJWK {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"could not find a JWK matching the client certificate")
	}

	if !comparePublicKeys(jwk.Key, cert.PublicKey) {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"the public key in the client certificate and ")
	}

	return nil
}

func authenticateTLSCert(
	ctx *oidc.Context,
	c *goidc.Client,
) error {
	if c.ID != ctx.Request().PostFormValue(idFormPostParam) {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid client id")
	}

	cert, ok := ctx.ClientCertificate()
	if !ok {
		return oidcerr.New(oidcerr.CodeInvalidClient,
			"client certificate not informed")
	}

	if c.TLSSubjectDistinguishedName != "" &&
		cert.Subject.String() != c.TLSSubjectDistinguishedName {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid distinguished name")
	}
	if c.TLSSubjectAlternativeName != "" &&
		!slices.Contains(cert.DNSNames, c.TLSSubjectAlternativeName) {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid alternative name")
	}

	return nil
}

// extractID extracts a client ID from the request.
//
// It looks to all places where an ID can be informed such as the basic
// authentication header and the post form field 'client_id'.
//
// If different client IDs are found in the request, it returns an error.
func extractID(
	ctx *oidc.Context,
) (
	string,
	error,
) {
	ids := []string{}

	postID := ctx.Request().PostFormValue(idFormPostParam)
	if postID != "" {
		ids = append(ids, postID)
	}

	basicID, _, _ := ctx.Request().BasicAuth()
	if basicID != "" {
		ids = append(ids, basicID)
	}

	assertion := ctx.Request().PostFormValue(assertionFormPostParam)
	if assertion != "" {
		var err error
		ids, err = appendAssertionClientID(ids, assertion, ctx.ClientSignatureAlgorithms())
		if err != nil {
			return "", err
		}
	}

	// All the client IDs present must be equal.
	if len(ids) == 0 || !allEquals(ids) {
		return "", oidcerr.New(oidcerr.CodeInvalidClient, "invalid client id")
	}

	return ids[0], nil
}

func appendAssertionClientID(
	ids []string,
	assertion string,
	sigAlgs []jose.SignatureAlgorithm,
) (
	[]string,
	error,
) {
	id, err := assertionClientID(assertion, sigAlgs)
	if err != nil {
		return nil, err
	}

	return append(ids, id), nil
}

func assertionClientID(
	assertion string,
	sigAlgs []jose.SignatureAlgorithm,
) (
	string,
	error,
) {
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not parse the client assertion", err)
	}

	var claims map[string]any
	if err := parsedAssertion.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidClient,
			"could not parse the client assertion claims", err)
	}

	// The issuer claim is supposed to be the client ID.
	clientID, ok := claims[goidc.ClaimIssuer]
	if !ok {
		return "", oidcerr.New(oidcerr.CodeInvalidClient,
			"invalid claim 'iss' in the client assertion")
	}

	clientIDAsString, ok := clientID.(string)
	if !ok {
		return "", oidcerr.New(oidcerr.CodeInvalidClient,
			"invalid claim 'iss' in the client assertion")
	}

	return clientIDAsString, nil
}

// Return true only if all the elements in values are equal.
func allEquals[T comparable](values []T) bool {
	if len(values) == 0 {
		return true
	}

	return all(
		values,
		func(value T) bool {
			return value == values[0]
		},
	)
}

// Return true if all the elements in the slice respect the condition.
func all[T interface{}](slice []T, condition func(T) bool) bool {
	for _, element := range slice {
		if !condition(element) {
			return false
		}
	}

	return true
}

func comparePublicKeys(k1 any, k2 any) bool {
	key2, ok := k2.(crypto.PublicKey)
	if !ok {
		return false
	}

	switch key1 := k1.(type) {
	case ed25519.PublicKey:
		return key1.Equal(key2)
	case *ecdsa.PublicKey:
		return key1.Equal(key2)
	case *rsa.PublicKey:
		return key1.Equal(key2)
	default:
		return false
	}
}

func hashSHA256(s []byte) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}

func hashSHA1(s []byte) string {
	hash := sha1.New()
	hash.Write([]byte(s))
	return string(hash.Sum(nil))
}
