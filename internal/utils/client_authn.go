package utils

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

func AuthenticateClient(ctx Context, client models.Client, req models.ClientAuthnRequest) issues.OAuthError {
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
		return nil
	default:
		return issues.NewOAuthError(constants.AccessDenied, "invalid authentication method")
	}
}

func authenticateWithClientSecretPost(ctx Context, client models.Client, req models.ClientAuthnRequest) issues.OAuthError {
	return validateSecret(ctx, client, req.ClientSecretPost)
}

func authenticateWithClientSecretBasic(ctx Context, client models.Client, req models.ClientAuthnRequest) issues.OAuthError {
	return validateSecret(ctx, client, req.ClientSecretBasicAuthn)
}

func validateSecret(ctx Context, client models.Client, clientSecret string) issues.OAuthError {
	err := bcrypt.CompareHashAndPassword([]byte(client.HashedSecret), []byte(clientSecret))
	if err != nil {
		return issues.NewOAuthError(constants.AccessDenied, "invalid secret")
	}
	return nil
}

func authenticateWithPrivateKeyJwt(ctx Context, client models.Client, req models.ClientAuthnRequest) issues.OAuthError {
	signatureAlgorithms := ctx.ClientSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	// Verify that the assertion indicates the key ID.
	if len(assertion.Headers) != 1 && assertion.Headers[0].KeyID == "" {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	// Verify that the key ID belongs to the client.
	keys := client.PublicJwks.Key(assertion.Headers[0].KeyID)
	if len(keys) == 0 {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	jwk := keys[0]
	claims := jwt.Claims{}
	if err := assertion.Claims(jwk.Key, &claims); err != nil {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	return areAssertionClaimsValid(claims, ctx.Host, ctx.PrivateKeyJwtAssertionLifetimeSecs)
}

func authenticateWithClientSecretJwt(ctx Context, client models.Client, req models.ClientAuthnRequest) issues.OAuthError {
	signatureAlgorithms := ctx.ClientSignatureAlgorithms
	if client.AuthnSignatureAlgorithm != "" {
		signatureAlgorithms = []jose.SignatureAlgorithm{client.AuthnSignatureAlgorithm}
	}
	assertion, err := jwt.ParseSigned(req.ClientAssertion, signatureAlgorithms)
	if err != nil {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	claims := jwt.Claims{}
	if err := assertion.Claims([]byte(client.Secret), &claims); err != nil {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	return areAssertionClaimsValid(claims, ctx.Host, ctx.ClientSecretJwtAssertionLifetimeSecs)
}

func areAssertionClaimsValid(claims jwt.Claims, host string, maxLifetimeSecs int) issues.OAuthError {
	// Validate that the "iat" and "exp" claims are present and their difference is not too great.
	if claims.Expiry == nil || claims.IssuedAt == nil || int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > maxLifetimeSecs {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:  claims.Subject,
		Subject: claims.Subject,
		// TODO: Choose the right audience
		AnyAudience: []string{host, host + string(constants.TokenEndpoint), host + string(constants.PushedAuthorizationRequestEndpoint)},
	}, time.Duration(0))
	if err != nil {
		return issues.NewOAuthError(constants.AccessDenied, "invalid assertion")
	}
	return nil
}
