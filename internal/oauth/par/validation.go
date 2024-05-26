package par

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/authorize"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validatePar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return validatePushedAuthorizationParams(ctx, req.AuthorizationParameters, client)
}

func validateParWithJar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	// The PAR RFC (https://datatracker.ietf.org/doc/html/rfc9126#section-3) says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC (https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2.) says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	return validatePushedAuthorizationParams(ctx, jar.AuthorizationParameters, client)
}

func validatePushedAuthorizationParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	return utils.RunValidations(
		ctx, params, client,
		authorize.ValidateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		authorize.ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed,
		validateRedirectUri,
		authorize.ValidateResponseMode,
		validateScopes,
		validateResponseType,
		authorize.ValidateCodeChallengeMethod,
		validateCannotInformRequestUri,
	)
}

func validateRedirectUri(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RedirectUri != "" && !client.IsRedirectUriAllowed(params.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateResponseType(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.Scopes != "" && ctx.OpenIdScopeIsRequired && !unit.ScopesContainsOpenId(params.Scopes) {
		return issues.NewOAuthError(constants.InvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(params.Scopes) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestUri(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return nil
}
