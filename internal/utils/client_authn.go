package utils

import (
	"crypto/x509"
	"log/slog"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

func GetAuthenticatedClient(
	ctx Context,
	req models.ClientAuthnRequest,
) (
	models.Client,
	models.OAuthError,
) {

	clientId, ok := getClientId(ctx, req)
	if !ok {
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client")
	}

	client, err := ctx.GetClient(clientId)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", clientId))
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client")
	}

	if err := AuthenticateClient(ctx, client, req); err != nil {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", req.ClientId))
		return models.Client{}, err
	}

	return client, nil
}

func AuthenticateClient(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	switch client.AuthnMethod {
	case constants.NoneAuthn:
		ctx.Logger.Debug("authenticating the client with none authn")
		return authenticateWithNoneAuthn(ctx, client, req)
	case constants.ClientSecretPostAuthn:
		ctx.Logger.Debug("authenticating the client with secret post")
		return authenticateWithClientSecretPost(ctx, client, req)
	case constants.ClientSecretBasicAuthn:
		ctx.Logger.Debug("authenticating the client with basic secret")
		return authenticateWithClientSecretBasic(ctx, client, req)
	case constants.PrivateKeyJwtAuthn:
		ctx.Logger.Debug("authenticating the client with private key jwt")
		return authenticateWithPrivateKeyJwt(ctx, client, req)
	case constants.ClientSecretJwt:
		ctx.Logger.Debug("authenticating the client with client secret jwt")
		return authenticateWithClientSecretJwt(ctx, client, req)
	case constants.SelfSignedTlsAuthn:
		ctx.Logger.Debug("authenticating the client with self signed tls certificate")
		return authenticateWithSelfSignedTlsCertificate(ctx, client, req)
	case constants.TlsAuthn:
		ctx.Logger.Debug("authenticating the client with tls certificate")
		return authenticateWithTlsCertificate(ctx, client, req)
	default:
		return models.NewOAuthError(constants.InvalidClient, "invalid authentication method")
	}
}

func authenticateWithNoneAuthn(
	_ Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	if client.Id != req.ClientId {
		return models.NewOAuthError(constants.InvalidClient, "invalid client")
	}
	return nil
}

func authenticateWithClientSecretPost(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	if client.Id != req.ClientId || req.ClientSecret == "" {
		return models.NewOAuthError(constants.InvalidClient, "invalid client")
	}
	return validateSecret(ctx, client, req.ClientSecret)
}

func authenticateWithClientSecretBasic(
	ctx Context,
	client models.Client,
	_ models.ClientAuthnRequest,
) models.OAuthError {
	clientId, clientSecret, ok := ctx.Request.BasicAuth()
	if !ok || client.Id != clientId {
		return models.NewOAuthError(constants.InvalidClient, "invalid client")
	}
	return validateSecret(ctx, client, clientSecret)
}

func validateSecret(
	_ Context,
	client models.Client,
	clientSecret string,
) models.OAuthError {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedSecret), []byte(clientSecret))
	if err != nil {
		return models.NewOAuthError(constants.InvalidClient, "invalid secret")
	}
	return nil
}

func authenticateWithPrivateKeyJwt(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {

	if req.ClientAssertionType != constants.JwtBearerAssertion {
		return models.NewOAuthError(constants.InvalidRequest, "invalid assertion_type")
	}

	signatureAlgorithms := ctx.PrivateKeyJwtSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	// Verify that the assertion indicates the key ID.
	if len(assertion.Headers) != 1 && assertion.Headers[0].KeyID == "" {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	// Verify that the key ID belongs to the client.
	jwks, oauthErr := client.GetPublicJwks()
	if oauthErr != nil {
		return oauthErr
	}

	keys := jwks.Key(assertion.Headers[0].KeyID)
	if len(keys) == 0 {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	jwk := keys[0]
	claims := jwt.Claims{}
	if err := assertion.Claims(jwk.Key, &claims); err != nil {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	return areAssertionClaimsValid(ctx, claims, ctx.PrivateKeyJwtAssertionLifetimeSecs)
}

func authenticateWithClientSecretJwt(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	if req.ClientAssertionType != constants.JwtBearerAssertion {
		return models.NewOAuthError(constants.InvalidRequest, "invalid assertion_type")
	}

	signatureAlgorithms := ctx.ClientSecretJwtSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	claims := jwt.Claims{}
	if err := assertion.Claims([]byte(client.Secret), &claims); err != nil {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	return areAssertionClaimsValid(ctx, claims, ctx.ClientSecretJwtAssertionLifetimeSecs)
}

func areAssertionClaimsValid(
	ctx Context,
	claims jwt.Claims,
	maxLifetimeSecs int,
) models.OAuthError {
	// Validate that the "iat" and "exp" claims are present and their difference is not too great.
	if claims.Expiry == nil || claims.IssuedAt == nil || int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > maxLifetimeSecs {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      claims.Subject,
		Subject:     claims.Subject,
		AnyAudience: []string{ctx.Host, ctx.GetRequestUrl()},
	}, time.Duration(0))
	if err != nil {
		return models.NewOAuthError(constants.InvalidClient, "invalid assertion")
	}
	return nil
}

func authenticateWithSelfSignedTlsCertificate(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	if client.Id != req.ClientId {
		return models.NewOAuthError(constants.InvalidClient, "invalid client")
	}

	rawClientCert, ok := ctx.GetHeader(string(constants.ClientCertificateHeader))
	if !ok {
		return models.NewOAuthError(constants.InvalidClient, "client certificate not informed")
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		return models.NewOAuthError(constants.InvalidClient, "could not parse the client certificate")
	}

	jwks, err := client.GetPublicJwks()
	if err != nil {
		return models.NewOAuthError(constants.InternalError, "could not load the client JWKS")
	}

	var jwk jose.JSONWebKey
	foundMatchingJwk := false
	for _, key := range jwks.Keys {
		if string(key.CertificateThumbprintSHA256) == unit.GenerateSha256Hash(clientCert.Raw) ||
			string(key.CertificateThumbprintSHA1) == unit.GenerateSha1Hash(clientCert.Raw) {
			foundMatchingJwk = true
			jwk = key
		}
	}

	if !foundMatchingJwk {
		return models.NewOAuthError(constants.InvalidClient, "could not find a JWK matching the client certificate")
	}

	if !unit.ComparePublicKeys(jwk.Key, clientCert.PublicKey) {
		return models.NewOAuthError(constants.InvalidClient, "the public key in the client certificate and ")
	}

	return nil
}

func authenticateWithTlsCertificate(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	if client.Id != req.ClientId {
		return models.NewOAuthError(constants.InvalidClient, "invalid client")
	}

	rawClientCert, ok := ctx.GetHeader(string(constants.ClientCertificateHeader))
	if !ok {
		return models.NewOAuthError(constants.InvalidClient, "client certificate not informed")
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		return models.NewOAuthError(constants.InvalidClient, "could not parse the client certificate")
	}

	opts := x509.VerifyOptions{
		Roots: ctx.CaCertificatePool,
	}
	if client.TlsSubjectAlternativeName != "" {
		opts.DNSName = client.TlsSubjectAlternativeName
	}
	if client.TlsSubjectAlternativeNameIp != "" {
		opts.DNSName = "[" + client.TlsSubjectAlternativeNameIp + "]"
	}

	_, err = clientCert.Verify(opts)
	if err != nil {
		ctx.Logger.Debug("could not verify the client certificate", slog.String("error", err.Error()))
		return models.NewOAuthError(constants.InvalidClient, "could not verify the client certificate")
	}

	if client.TlsSubjectDistinguishedName != "" && clientCert.Subject.String() != client.TlsSubjectDistinguishedName {
		return models.NewOAuthError(constants.InvalidClient, "invalid distinguished name")
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

	var claims map[constants.Claim]any
	parsedAssertion.UnsafeClaimsWithoutVerification(&claims)

	// The issuer claim is supposed to have the client ID.
	clientId, ok := claims[constants.IssuerClaim]
	if !ok {
		return "", false
	}

	clientIdAsString, ok := clientId.(string)
	if !ok {
		return "", false
	}

	return clientIdAsString, true
}
