package utils

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

func AuthenticateClient(
	ctx Context,
	client models.Client,
	req models.ClientAuthnRequest,
) models.OAuthError {
	switch client.AuthnMethod {
	case constants.ClientSecretPostAuthn:
		return authenticateWithClientSecretPost(ctx, client, req)
	case constants.ClientSecretBasicAuthn:
		return authenticateWithClientSecretBasic(ctx, client, req)
	case constants.PrivateKeyJwtAuthn:
		return authenticateWithPrivateKeyJwt(ctx, client, req)
	case constants.ClientSecretJwt:
		return authenticateWithClientSecretJwt(ctx, client, req)
	case constants.NoneAuthn:
		return authenticateWithNoneAuthn(ctx, client, req)
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
