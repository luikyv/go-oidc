package userinfo

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateUserInfoRequest(
	ctx utils.Context,
	grantSession goidc.GrantSession,
	token string,
	tokenType goidc.TokenType,
) goidc.OAuthError {
	if grantSession.HasLastTokenExpired() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token expired")
	}

	if !utils.ScopesContainsOpenID(grantSession.GrantedScopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid scope")
	}

	if err := validateDPOP(ctx, token, tokenType, grantSession); err != nil {
		return err
	}

	return validateTLSProofOfPossesion(ctx, grantSession)
}

func validateDPOP(
	ctx utils.Context,
	token string,
	tokenType goidc.TokenType,
	grantSession goidc.GrantSession,
) goidc.OAuthError {

	if grantSession.JWKThumbprint == "" {
		if tokenType == goidc.TokenTypeDPOP {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJWT, ok := ctx.GetDPOPJWT()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return utils.ValidateDPOPJWT(ctx, dpopJWT, utils.DPOPJWTValidationOptions{
		AccessToken:   token,
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}

func validateTLSProofOfPossesion(
	ctx utils.Context,
	grantSession goidc.GrantSession,
) goidc.OAuthError {
	if grantSession.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.GetClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "the client certificate is required")
	}

	if grantSession.ClientCertificateThumbprint != utils.GenerateBase64URLSHA256Hash(string(clientCert.Raw)) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "invalid client certificate")
	}

	return nil
}
