package utils

import (
	"log/slog"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func GetAuthenticatedClient(
	ctx Context,
	req models.ClientAuthnRequest,
) (
	goidc.Client,
	goidc.OAuthError,
) {

	clientId, ok := getClientId(ctx, req)
	if !ok {
		return goidc.Client{}, goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}

	client, err := ctx.GetClient(clientId)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", clientId))
		return goidc.Client{}, goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}

	if err := authenticateClient(ctx, client, req); err != nil {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", req.ClientId))
		return goidc.Client{}, err
	}

	return client, nil
}

func authenticateClient(
	ctx Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {
	switch client.AuthnMethod {
	case goidc.NoneAuthn:
		ctx.Logger.Debug("authenticating the client with none authn")
		return authenticateWithNoneAuthn(ctx, client, req)
	case goidc.ClientSecretPostAuthn:
		ctx.Logger.Debug("authenticating the client with secret post")
		return authenticateWithClientSecretPost(ctx, client, req)
	case goidc.ClientSecretBasicAuthn:
		ctx.Logger.Debug("authenticating the client with basic secret")
		return authenticateWithClientSecretBasic(ctx, client, req)
	case goidc.PrivateKeyJwtAuthn:
		ctx.Logger.Debug("authenticating the client with private key jwt")
		return authenticateWithPrivateKeyJwt(ctx, client, req)
	case goidc.ClientSecretJwt:
		ctx.Logger.Debug("authenticating the client with client secret jwt")
		return authenticateWithClientSecretJwt(ctx, client, req)
	case goidc.SelfSignedTlsAuthn:
		ctx.Logger.Debug("authenticating the client with self signed tls certificate")
		return authenticateWithSelfSignedTlsCertificate(ctx, client, req)
	case goidc.TlsAuthn:
		ctx.Logger.Debug("authenticating the client with tls certificate")
		return authenticateWithTlsCertificate(ctx, client, req)
	default:
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid authentication method")
	}
}

func authenticateWithNoneAuthn(
	_ Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {
	if client.Id != req.ClientId {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}
	return nil
}

func authenticateWithClientSecretPost(
	ctx Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {
	if client.Id != req.ClientId || req.ClientSecret == "" {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}
	return validateSecret(ctx, client, req.ClientSecret)
}

func authenticateWithClientSecretBasic(
	ctx Context,
	client goidc.Client,
	_ models.ClientAuthnRequest,
) goidc.OAuthError {
	clientId, clientSecret, ok := ctx.Request.BasicAuth()
	if !ok || client.Id != clientId {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}
	return validateSecret(ctx, client, clientSecret)
}

func validateSecret(
	_ Context,
	client goidc.Client,
	clientSecret string,
) goidc.OAuthError {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedSecret), []byte(clientSecret))
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid secret")
	}
	return nil
}

func authenticateWithPrivateKeyJwt(
	ctx Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {

	if req.ClientAssertionType != goidc.JwtBearerAssertionType {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid assertion_type")
	}

	signatureAlgorithms := ctx.PrivateKeyJwtSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}

	// Verify that the assertion indicates the key ID.
	if len(assertion.Headers) != 1 && assertion.Headers[0].KeyID == "" {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.GetJwk(assertion.Headers[0].KeyID)
	if oauthErr != nil {
		return oauthErr
	}

	claims := jwt.Claims{}
	if err := assertion.Claims(jwk.GetKey(), &claims); err != nil {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}

	return areAssertionClaimsValid(ctx, client, claims, ctx.PrivateKeyJwtAssertionLifetimeSecs)
}

func authenticateWithClientSecretJwt(
	ctx Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {
	if req.ClientAssertionType != goidc.JwtBearerAssertionType {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid assertion_type")
	}

	signatureAlgorithms := ctx.ClientSecretJwtSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}

	claims := jwt.Claims{}
	if err := assertion.Claims([]byte(client.Secret), &claims); err != nil {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}

	return areAssertionClaimsValid(ctx, client, claims, ctx.ClientSecretJwtAssertionLifetimeSecs)
}

func areAssertionClaimsValid(
	ctx Context,
	client goidc.Client,
	claims jwt.Claims,
	maxLifetimeSecs int,
) goidc.OAuthError {
	// Validate that the "iat" and "exp" claims are present and their difference is not too great.
	if claims.Expiry == nil || claims.IssuedAt == nil || int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > maxLifetimeSecs {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		Subject:     client.Id,
		AnyAudience: ctx.GetAudiences(),
	}, time.Duration(0))
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid assertion")
	}
	return nil
}

func authenticateWithSelfSignedTlsCertificate(
	ctx Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {
	if client.Id != req.ClientId {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}

	clientCert, ok := ctx.GetClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.InvalidClient, "client certificate not informed")
	}

	jwks, err := client.GetPublicJwks()
	if err != nil {
		return goidc.NewOAuthError(goidc.InternalError, "could not load the client JWKS")
	}

	var jwk goidc.JsonWebKey
	foundMatchingJwk := false
	for _, key := range jwks.Keys {
		if string(key.GetCertificateThumbprintSha256()) == unit.GenerateSha256Hash(clientCert.Raw) ||
			string(key.GetCertificateThumbprintSha1()) == unit.GenerateSha1Hash(clientCert.Raw) {
			foundMatchingJwk = true
			jwk = key
		}
	}

	if !foundMatchingJwk {
		return goidc.NewOAuthError(goidc.InvalidClient, "could not find a JWK matching the client certificate")
	}

	if !unit.ComparePublicKeys(jwk.GetKey(), clientCert.PublicKey) {
		return goidc.NewOAuthError(goidc.InvalidClient, "the public key in the client certificate and ")
	}

	return nil
}

func authenticateWithTlsCertificate(
	ctx Context,
	client goidc.Client,
	req models.ClientAuthnRequest,
) goidc.OAuthError {
	if client.Id != req.ClientId {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid client")
	}

	clientCert, ok := ctx.GetSecureClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.InvalidClient, "client certificate not informed")
	}

	if client.TlsSubjectDistinguishedName != "" && clientCert.Subject.String() != client.TlsSubjectDistinguishedName {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid distinguished name")
	}
	if client.TlsSubjectAlternativeName != "" && !slices.Contains(clientCert.DNSNames, client.TlsSubjectAlternativeName) {
		return goidc.NewOAuthError(goidc.InvalidClient, "invalid alternative name")
	}

	return nil
}

func getClientId(
	ctx Context,
	req models.ClientAuthnRequest,
) (
	string,
	bool,
) {
	clientIds := []string{}

	if req.ClientId != "" {
		clientIds = append(clientIds, req.ClientId)
	}

	basicClientId, _, _ := ctx.Request.BasicAuth()
	if basicClientId != "" {
		clientIds = append(clientIds, basicClientId)
	}

	clientIds, ok := appendClientIdFromAssertion(ctx, clientIds, req)
	if !ok {
		return "", false
	}

	// All the client IDs present must be equal.
	if len(clientIds) == 0 || !unit.AllEquals(clientIds) {
		return "", false
	}

	return clientIds[0], true
}

func appendClientIdFromAssertion(
	ctx Context,
	clientIds []string,
	req models.ClientAuthnRequest,
) (
	[]string,
	bool,
) {
	if req.ClientAssertion == "" {
		return clientIds, true
	}

	assertionClientId, ok := getClientIdFromAssertion(ctx, req.ClientAssertion)
	if !ok {
		return []string{}, false
	}

	return append(clientIds, assertionClientId), true
}

func getClientIdFromAssertion(
	ctx Context,
	assertion string,
) (
	string,
	bool,
) {
	parsedAssertion, err := jwt.ParseSigned(assertion, ctx.GetClientSignatureAlgorithms())
	if err != nil {
		return "", false
	}

	var claims map[string]any
	if err := parsedAssertion.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", false
	}

	// The issuer claim is supposed to have the client ID.
	clientId, ok := claims[goidc.IssuerClaim]
	if !ok {
		return "", false
	}

	clientIdAsString, ok := clientId.(string)
	if !ok {
		return "", false
	}

	return clientIdAsString, true
}
