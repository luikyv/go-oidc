package par

import (
	"github.com/luikymagno/goidc/internal/constants"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
)

func validatePar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	client models.Client,
) models.OAuthError {
	return validatePushedAuthorizationParams(ctx, req.AuthorizationParameters, client)
}

func validateParWithJar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) models.OAuthError {

	if req.RequestUri != "" {
		return models.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientId != client.Id {
		return models.NewOAuthError(constants.InvalidResquestObject, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return models.NewOAuthError(constants.InvalidResquestObject, "request_uri is not allowed inside JAR")
	}

	// The PAR RFC says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	return validatePushedAuthorizationParams(ctx, jar.AuthorizationParameters, client)
}

func validatePushedAuthorizationParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	return utils.RunValidations(
		ctx, params, client,
		validateNoneAuthnNotAllowed,
		validateCannotInformRequestUri,
		authorize.ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		authorize.ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed,
		validateOpenIdRedirectUri,
		validateFapi2RedirectUri,
		authorize.ValidateResponseMode,
		authorize.ValidateJwtResponseModeIsRequired,
		validateScopes,
		validateResponseType,
		authorize.ValidateCodeChallengeMethod,
		authorize.ValidateDisplayValue,
		authorize.ValidateAuthorizationDetails,
		authorize.ValidateAcrValues,
	)
}

func validateNoneAuthnNotAllowed(
	_ utils.Context,
	_ models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if client.AuthnMethod == constants.NoneAuthn {
		return models.NewOAuthError(constants.InvalidRequest, "invalid client authentication method")
	}
	return nil
}

func validateOpenIdRedirectUri(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {

	if ctx.Profile != constants.OpenIdProfile {
		return nil
	}

	if params.RedirectUri != "" && !client.IsRedirectUriAllowed(params.RedirectUri) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateFapi2RedirectUri(
	ctx utils.Context,
	params models.AuthorizationParameters,
	_ models.Client,
) models.OAuthError {

	if ctx.Profile != constants.Fapi2Profile {
		return nil
	}

	// According to FAPI 2.0 "pre-registration is not required with client authentication and PAR".
	if params.RedirectUri == "" {
		return models.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}
	return nil
}

func validateResponseType(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.Scopes != "" && ctx.OpenIdScopeIsRequired && !unit.ScopesContainsOpenId(params.Scopes) {
		return models.NewOAuthError(constants.InvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(params.Scopes) {
		return models.NewOAuthError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestUri(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.RequestUri != "" {
		return models.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return nil
}
