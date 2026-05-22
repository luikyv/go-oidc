package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	formPostParamID            = "client_id"
	formPostParamSecret        = "client_secret"
	formPostParamAssertion     = "client_assertion"
	formPostParamAssertionType = "client_assertion_type"
)

type AuthnContext string

const (
	AuthnContextToken              AuthnContext = "token"
	AuthnContextTokenIntrospection AuthnContext = "token_introspection"
	AuthnContextTokenRevocation    AuthnContext = "token_revocation"
)

// Authenticated fetches a client associated to the request and returns it
// if the client is authenticated according to its authentication method.
func Authenticated(ctx oidc.Context, authnCtx AuthnContext) (*goidc.Client, error) {
	id, err := ExtractID(ctx)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	c, err := Client(ctx, id)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
		}
		return nil, fmt.Errorf("could not load the client: %w", err)
	}

	if err := Authenticate(ctx, c, authnCtx); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	return c, nil
}

func Authenticate(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	if !slices.Contains(ctx.TokenAuthnMethods, c.TokenAuthnMethod) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client's authentication method is not supported"))
	}

	switch c.TokenAuthnMethod {
	case goidc.AuthnMethodNone:
		return nil
	case goidc.AuthnMethodSecretPost:
		return authenticateSecretPost(ctx, c)
	case goidc.AuthnMethodSecretBasic:
		return authenticateSecretBasic(ctx, c)
	case goidc.AuthnMethodPrivateKeyJWT:
		return authenticatePrivateKeyJWT(ctx, c, authnCtx)
	case goidc.AuthnMethodSecretJWT:
		return authenticateSecretJWT(ctx, c, authnCtx)
	case goidc.AuthnMethodSelfSignedTLS:
		return authenticateSelfSignedTLSCert(ctx, c)
	case goidc.AuthnMethodTLS:
		return authenticateTLSCert(ctx, c)
	default:
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client's authentication method is not supported"))
	}
}

func authenticateSecretPost(ctx oidc.Context, c *goidc.Client) error {
	if c.ID != ctx.Request.PostFormValue(formPostParamID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	secret := ctx.Request.PostFormValue(formPostParamSecret)
	if secret == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client_secret is required"))
	}

	if err := ctx.VerifyClientSecret(c.Secret, secret); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client secret", err)
	}

	if c.SecretExpiresAt != 0 && timeutil.TimestampNow() >= c.SecretExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("client_secret is expired"))
	}

	return nil
}

func authenticateSecretBasic(ctx oidc.Context, c *goidc.Client) error {
	id, secret, ok := ctx.Request.BasicAuth()
	if !ok {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client basic authentication is required"))
	}

	if c.ID != id {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	if err := ctx.VerifyClientSecret(c.Secret, secret); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client secret", err)
	}

	if c.SecretExpiresAt != 0 && timeutil.TimestampNow() >= c.SecretExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("client_secret is expired"))
	}

	return nil
}

func authenticatePrivateKeyJWT(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := authnSigAlgs(c, authnCtx, ctx.TokenAuthnPrivateKeyJWTSigAlgs)
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if len(parsedAssertion.Headers) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client assertion must contain exactly one JOSE header"))
	}

	jwk, err := JWKMatchingHeader(ctx, c, parsedAssertion.Headers[0])
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if !jwk.IsPublic() {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client assertion key must be public"))
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims(jwk.Key, &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	return areClaimsValid(ctx, claims, c, authnCtx)
}

func JWKMatchingHeader(ctx oidc.Context, c *goidc.Client, header jose.Header) (goidc.JSONWebKey, error) {
	if header.KeyID != "" {
		jwk, err := JWKByKeyID(ctx, c, header.KeyID)
		if err != nil {
			return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk used to sign the assertion that matches the 'kid' header: %w", err)
		}
		return jwk, nil
	}

	jwk, err := JWKByAlg(ctx, c, header.Algorithm)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk used to sign the assertion that matches the 'alg' header: %w", err)
	}
	return jwk, nil
}

func authenticateSecretJWT(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := authnSigAlgs(c, authnCtx, ctx.TokenAuthnSecretJWTSigAlgs)
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims([]byte(c.Secret), &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if c.SecretExpiresAt != 0 && timeutil.TimestampNow() >= c.SecretExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("client_secret is expired"))
	}

	if err := areClaimsValid(ctx, claims, c, authnCtx); err != nil {
		return err
	}

	return nil
}

func authnSigAlgs(c *goidc.Client, authnCtx AuthnContext, algs []goidc.SignatureAlgorithm) []goidc.SignatureAlgorithm {
	switch {
	case authnCtx == AuthnContextToken && c.TokenAuthnSigAlg != "" && slices.Contains(algs, c.TokenAuthnSigAlg):
		return []goidc.SignatureAlgorithm{c.TokenAuthnSigAlg}
	case authnCtx == AuthnContextTokenIntrospection && c.TokenIntrospectionAuthnSigAlg != "" && slices.Contains(algs, c.TokenIntrospectionAuthnSigAlg):
		return []goidc.SignatureAlgorithm{c.TokenIntrospectionAuthnSigAlg}
	case authnCtx == AuthnContextTokenRevocation && c.TokenRevocationAuthnSigAlg != "" && slices.Contains(algs, c.TokenRevocationAuthnSigAlg):
		return []goidc.SignatureAlgorithm{c.TokenRevocationAuthnSigAlg}
	default:
		return algs
	}
}

func assertion(ctx oidc.Context) (string, error) {
	assertionType := ctx.Request.PostFormValue(formPostParamAssertionType)
	if assertionType != string(goidc.AssertionTypeJWTBearer) {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
	}

	assertion := ctx.Request.PostFormValue(formPostParamAssertion)
	if assertion == "" {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client_assertion is required"))
	}

	return assertion, nil
}

func areClaimsValid(ctx oidc.Context, claims jwt.Claims, client *goidc.Client, _ AuthnContext) error {
	if claims.Expiry == nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the exp claim is required in the client assertion"))
	}

	if claims.ID == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the jti claim is required in the client assertion"))
	}

	if ctx.Profile == goidc.ProfileFAPI2 && len(claims.Audience) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the audience claim is invalid"))
	}

	if err := ctx.ConsumeJTI(claims.ID); err != nil && !errors.Is(err, goidc.ErrNotFound) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	secsToExpiry := int(claims.Expiry.Time().Sub(timeutil.Now()).Seconds())
	if secsToExpiry > ctx.JWTLifetimeSecs {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client assertion lifetime exceeds the allowed maximum"))
	}

	audiences := []string{ctx.Issuer()}
	if ctx.Profile != goidc.ProfileFAPI2 {
		audiences = append(audiences, ctx.TokenURL(), ctx.RequestURL())
		if ctx.MTLSIsEnabled {
			audiences = append(audiences, ctx.TokenMTLSURL(), ctx.RequestMTLSURL())
		}
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		Subject:     client.ID,
		AnyAudience: audiences,
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}
	return nil
}

func authenticateSelfSignedTLSCert(ctx oidc.Context, c *goidc.Client) error {
	if c.ID != ctx.Request.PostFormValue(formPostParamID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	jwk, err := jwkMatchingCert(ctx, c, cert)
	if err != nil {
		return err
	}

	if !comparePublicKeys(jwk.Key, cert.PublicKey) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the public key in the client certificate does not match the client JWKS"))
	}

	return nil
}

func jwkMatchingCert(ctx oidc.Context, c *goidc.Client, cert *x509.Certificate) (goidc.JSONWebKey, error) {
	jwks, err := JWKS(ctx, c)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not load the client JWKS: %w", err)
	}

	for _, jwk := range jwks.Keys {
		if string(jwk.CertificateThumbprintSHA256) == hashSHA256(cert.Raw) || string(jwk.CertificateThumbprintSHA1) == hashSHA1(cert.Raw) {
			return jwk, nil
		}
	}

	return goidc.JSONWebKey{}, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
		errors.New("no client JWK matches the presented client certificate"))
}

func authenticateTLSCert(ctx oidc.Context, c *goidc.Client) error {
	if c.ID != ctx.Request.PostFormValue(formPostParamID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	switch {
	case c.TLSSubjectDistinguishedName != "":
		if c.TLSSubjectDistinguishedName != cert.Subject.String() {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the client certificate subject distinguished name does not match"))
		}
	case c.TLSSubjectAlternativeName != "":
		if !slices.Contains(cert.DNSNames, c.TLSSubjectAlternativeName) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the client certificate subject alternative name does not match"))
		}
	default:
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client is missing TLS authentication metadata"))
	}

	return nil
}

// ExtractID extracts a client ID from a authenticated request.
// It looks to all places where an ID can be informed such as the basic
// authentication header and the post form field 'client_id'.
// If different client IDs are found in the request, it returns an error.
func ExtractID(ctx oidc.Context) (string, error) {
	ids := []string{}

	postID := ctx.Request.PostFormValue(formPostParamID)
	if postID != "" {
		ids = append(ids, postID)
	}

	basicID, _, _ := ctx.Request.BasicAuth()
	if basicID != "" {
		ids = append(ids, basicID)
	}

	assertion := ctx.Request.PostFormValue(formPostParamAssertion)
	if assertion != "" {
		assertionID, err := assertionClientID(assertion, ctx.TokenAuthnSigAlgs())
		if err != nil {
			return "", err
		}
		ids = append(ids, assertionID)
	}

	if len(ids) == 0 {
		return "", ErrClientNotIdentified
	}

	// All the client IDs present must be equal.
	for _, id := range ids {
		if id != ids[0] {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the request contains conflicting client identifiers"))
		}
	}

	return ids[0], nil
}

func assertionClientID(assertion string, sigAlgs []goidc.SignatureAlgorithm) (string, error) {
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	var claims map[string]any
	if err := parsedAssertion.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	// The issuer claim is supposed to be the client ID.
	clientID, ok := claims[goidc.ClaimIssuer]
	if !ok {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the iss claim is required in the client assertion"))
	}

	clientIDAsString, ok := clientID.(string)
	if !ok {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the iss claim in the client assertion must be a string"))
	}

	return clientIDAsString, nil
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
	hash.Write(s)
	return string(hash.Sum(nil))
}

func hashSHA1(s []byte) string {
	hash := sha1.New() //nolint:gosec
	hash.Write(s)
	return string(hash.Sum(nil))
}
