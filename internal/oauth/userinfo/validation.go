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
		return goidc.NewOAuthError(goidc.InvalidRequest, "token expired")
	}

	if !utils.ScopesContainsOpenId(grantSession.GrantedScopes) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid scope")
	}

	if err := validateDpop(ctx, token, tokenType, grantSession); err != nil {
		return err
	}

	return validateTlsProofOfPossesion(ctx, grantSession)
}

func validateDpop(
	ctx utils.Context,
	token string,
	tokenType goidc.TokenType,
	grantSession goidc.GrantSession,
) goidc.OAuthError {

	if grantSession.JwkThumbprint == "" {
		if tokenType == goidc.DpopTokenType {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return goidc.NewOAuthError(goidc.InvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJwt, ok := ctx.GetDpopJwt()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.NewOAuthError(goidc.UnauthorizedClient, "invalid DPoP header")
	}

	return utils.ValidateDpopJwt(ctx, dpopJwt, utils.DpopJwtValidationOptions{
		AccessToken:   token,
		JwkThumbprint: grantSession.JwkThumbprint,
	})
}

func validateTlsProofOfPossesion(
	ctx utils.Context,
	grantSession goidc.GrantSession,
) goidc.OAuthError {
	if grantSession.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.GetClientCertificate()
	if !ok {
		return goidc.NewOAuthError(goidc.InvalidToken, "the client certificate is required")
	}

	if grantSession.ClientCertificateThumbprint != utils.GenerateBase64UrlSha256Hash(string(clientCert.Raw)) {
		return goidc.NewOAuthError(goidc.InvalidToken, "invalid client certificate")
	}

	return nil
}
