package utils

import (
	"log/slog"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func GetAuthenticatedClient(
	ctx OAuthContext,
	req ClientAuthnRequest,
) (
	goidc.Client,
	goidc.OAuthError,
) {

	clientID, ok := getClientID(ctx, req)
	if !ok {
		return goidc.Client{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}

	client, err := ctx.GetClient(clientID)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", clientID))
		return goidc.Client{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}

	if err := authenticateClient(ctx, client, req); err != nil {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", req.ClientID))
		return goidc.Client{}, err
	}

	return client, nil
}

func authenticateClient(
	ctx OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {
	switch client.AuthnMethod {
	case goidc.ClientAuthnNone:
		ctx.Logger.Debug("authenticating the client with none authn")
		return authenticateWithNoneAuthn(ctx, client, req)
	case goidc.ClientAuthnSecretPost:
		ctx.Logger.Debug("authenticating the client with secret post")
		return authenticateWithClientSecretPost(ctx, client, req)
	case goidc.ClientAuthnSecretBasic:
		ctx.Logger.Debug("authenticating the client with basic secret")
		return authenticateWithClientSecretBasic(ctx, client, req)
	case goidc.ClientAuthnPrivateKeyJWT:
		ctx.Logger.Debug("authenticating the client with private key jwt")
		return authenticateWithPrivateKeyJWT(ctx, client, req)
	case goidc.ClientAuthnSecretJWT:
		ctx.Logger.Debug("authenticating the client with client secret jwt")
		return authenticateWithClientSecretJWT(ctx, client, req)
	case goidc.ClientAuthnSelfSignedTLS:
		ctx.Logger.Debug("authenticating the client with self signed tls certificate")
		return authenticateWithSelfSignedTLSCertificate(ctx, client, req)
	case goidc.ClientAuthnTLS:
		ctx.Logger.Debug("authenticating the client with tls certificate")
		return authenticateWithTLSCertificate(ctx, client, req)
	default:
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid authentication method")
	}
}

func authenticateWithNoneAuthn(
	_ OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {
	if client.ID != req.ClientID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}
	return nil
}

func authenticateWithClientSecretPost(
	ctx OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {
	if client.ID != req.ClientID || req.ClientSecret == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}
	return validateSecret(ctx, client, req.ClientSecret)
}

func authenticateWithClientSecretBasic(
	ctx OAuthContext,
	client goidc.Client,
	_ ClientAuthnRequest,
) goidc.OAuthError {
	clientID, clientSecret, ok := ctx.Request.BasicAuth()
	if !ok || client.ID != clientID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}
	return validateSecret(ctx, client, clientSecret)
}

func validateSecret(
	_ OAuthContext,
	client goidc.Client,
	clientSecret string,
) goidc.OAuthError {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedSecret), []byte(clientSecret))
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid secret")
	}
	return nil
}

func authenticateWithPrivateKeyJWT(
	ctx OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {

	if req.ClientAssertionType != goidc.AssertionTypeJWTBearer {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid assertion_type")
	}

	signatureAlgorithms := ctx.PrivateKeyJWTSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid assertion signature")
	}

	// Verify that the assertion indicates the key ID.
	if len(assertion.Headers) != 1 || assertion.Headers[0].KeyID == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid kid header in the assertion")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.GetJWK(assertion.Headers[0].KeyID)
	if oauthErr != nil {
		return oauthErr
	}

	claims := jwt.Claims{}
	if err := assertion.Claims(jwk.GetKey(), &claims); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid assertion signature")
	}

	return areAssertionClaimsValid(ctx, client, claims, ctx.PrivateKeyJWTAssertionLifetimeSecs)
}

func authenticateWithClientSecretJWT(
	ctx OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {
	if req.ClientAssertionType != goidc.AssertionTypeJWTBearer {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid assertion_type")
	}

	signatureAlgorithms := ctx.ClientSecretJWTSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid assertion")
	}

	claims := jwt.Claims{}
	if err := assertion.Claims([]byte(client.Secret), &claims); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid assertion")
	}

	return areAssertionClaimsValid(ctx, client, claims, ctx.ClientSecretJWTAssertionLifetimeSecs)
}

func areAssertionClaimsValid(
	ctx OAuthContext,
	client goidc.Client,
	claims jwt.Claims,
	maxLifetimeSecs int,
) goidc.OAuthError {
	// Validate that the "iat" and "exp" claims are present and their difference is not too great.
	if claims.Expiry == nil || claims.IssuedAt == nil || int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > maxLifetimeSecs {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid time claim in the assertion")
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		Subject:     client.ID,
		AnyAudience: ctx.GetAudiences(),
	}, time.Duration(0))
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid assertion")
	}
	return nil
}

func authenticateWithSelfSignedTLSCertificate(
	ctx OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {
	if client.ID != req.ClientID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}

	clientCert, ok := ctx.GetClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "client certificate not informed")
	}

	jwks, err := client.GetPublicJWKS()
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, "could not load the client JWKS")
	}

	var jwk goidc.JSONWebKey
	foundMatchingJWK := false
	for _, key := range jwks.Keys {
		if string(key.GetCertificateThumbprintSHA256()) == GenerateSHA256Hash(clientCert.Raw) ||
			string(key.GetCertificateThumbprintSHA1()) == GenerateSHA1Hash(clientCert.Raw) {
			foundMatchingJWK = true
			jwk = key
		}
	}

	if !foundMatchingJWK {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "could not find a JWK matching the client certificate")
	}

	if !ComparePublicKeys(jwk.GetKey(), clientCert.PublicKey) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "the public key in the client certificate and ")
	}

	return nil
}

func authenticateWithTLSCertificate(
	ctx OAuthContext,
	client goidc.Client,
	req ClientAuthnRequest,
) goidc.OAuthError {
	if client.ID != req.ClientID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client")
	}

	clientCert, ok := ctx.GetSecureClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "client certificate not informed")
	}

	if client.TLSSubjectDistinguishedName != "" && clientCert.Subject.String() != client.TLSSubjectDistinguishedName {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid distinguished name")
	}
	if client.TLSSubjectAlternativeName != "" && !slices.Contains(clientCert.DNSNames, client.TLSSubjectAlternativeName) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid alternative name")
	}

	return nil
}

func getClientID(
	ctx OAuthContext,
	req ClientAuthnRequest,
) (
	string,
	bool,
) {
	clientIDs := []string{}

	if req.ClientID != "" {
		clientIDs = append(clientIDs, req.ClientID)
	}

	basicClientID, _, _ := ctx.Request.BasicAuth()
	if basicClientID != "" {
		clientIDs = append(clientIDs, basicClientID)
	}

	clientIDs, ok := appendClientIDFromAssertion(ctx, clientIDs, req)
	if !ok {
		return "", false
	}

	// All the client IDs present must be equal.
	if len(clientIDs) == 0 || !AllEquals(clientIDs) {
		return "", false
	}

	return clientIDs[0], true
}

func appendClientIDFromAssertion(
	ctx OAuthContext,
	clientIDs []string,
	req ClientAuthnRequest,
) (
	[]string,
	bool,
) {
	if req.ClientAssertion == "" {
		return clientIDs, true
	}

	assertionClientID, ok := getClientIDFromAssertion(ctx, req.ClientAssertion)
	if !ok {
		return []string{}, false
	}

	return append(clientIDs, assertionClientID), true
}

func getClientIDFromAssertion(
	ctx OAuthContext,
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
	clientID, ok := claims[goidc.ClaimIssuer]
	if !ok {
		return "", false
	}

	clientIDAsString, ok := clientID.(string)
	if !ok {
		return "", false
	}

	return clientIDAsString, true
}
