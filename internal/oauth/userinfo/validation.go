package userinfo

import (
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func validateUserInfoRequest(
	ctx *utils.Context,
	grantSession *goidc.GrantSession,
	token string,
	tokenType goidc.TokenType,
) goidc.OAuthError {
	if grantSession.HasLastTokenExpired() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "token expired")
	}

	if !utils.ScopesContainsOpenID(grantSession.ActiveScopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid scope")
	}

	if err := validateDPoP(ctx, token, tokenType, grantSession); err != nil {
		return err
	}

	return validateTLSProofOfPossesion(ctx, grantSession)
}

func validateDPoP(
	ctx *utils.Context,
	token string,
	tokenType goidc.TokenType,
	grantSession *goidc.GrantSession,
) goidc.OAuthError {

	if grantSession.JWKThumbprint == "" {
		if tokenType == goidc.TokenTypeDPoP {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return utils.ValidateDPoPJWT(ctx, dpopJWT, utils.DPoPJWTValidationOptions{
		AccessToken:   token,
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}

func validateTLSProofOfPossesion(
	ctx *utils.Context,
	grantSession *goidc.GrantSession,
) goidc.OAuthError {
	if grantSession.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.ClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "the client certificate is required")
	}

	if grantSession.ClientCertificateThumbprint != utils.HashBase64URLSHA256(string(clientCert.Raw)) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidToken, "invalid client certificate")
	}

	return nil
}
