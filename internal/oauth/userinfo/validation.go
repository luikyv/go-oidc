package userinfo

import (
	"github.com/luikymagno/auth-server/internal/constants"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateUserInfoRequest(
	ctx utils.Context,
	grantSession models.GrantSession,
	token string,
	tokenType constants.TokenType,
) models.OAuthError {
	if grantSession.HasLastTokenExpired() {
		return models.NewOAuthError(constants.InvalidRequest, "token expired")
	}

	if !unit.ScopesContainsOpenId(grantSession.GrantedScopes) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid scope")
	}

	if err := validateDpop(ctx, token, tokenType, grantSession); err != nil {
		return err
	}

	return validateTlsProofOfPossesion(ctx, grantSession)
}

func validateDpop(
	ctx utils.Context,
	token string,
	tokenType constants.TokenType,
	grantSession models.GrantSession,
) models.OAuthError {

	if grantSession.JwkThumbprint == "" {
		if tokenType == constants.DpopTokenType {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return models.NewOAuthError(constants.InvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJwt, ok := ctx.GetDpopJwt()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid DPoP header")
	}

	return utils.ValidateDpopJwt(ctx, dpopJwt, models.DpopJwtValidationOptions{
		AccessToken:   token,
		JwkThumbprint: grantSession.JwkThumbprint,
	})
}

func validateTlsProofOfPossesion(
	ctx utils.Context,
	grantSession models.GrantSession,
) models.OAuthError {
	if grantSession.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.GetClientCertificate()
	if !ok {
		return models.NewOAuthError(constants.InvalidToken, "the client certificate is required")
	}

	if grantSession.ClientCertificateThumbprint != unit.GenerateBase64UrlSha256Hash(string(clientCert.Raw)) {
		return models.NewOAuthError(constants.InvalidToken, "invalid client certificate")
	}

	return nil
}
