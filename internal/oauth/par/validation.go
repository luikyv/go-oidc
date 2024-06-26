package par

import (
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validatePar(
	ctx utils.Context,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) goidc.OAuthError {
	return validatePushedAuthorizationParams(ctx, req.AuthorizationParameters, client)
}

func validateParWithJar(
	ctx utils.Context,
	req utils.PushedAuthorizationRequest,
	jar utils.AuthorizationRequest,
	client goidc.Client,
) goidc.OAuthError {

	if req.RequestUri != "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientId != client.Id {
		return goidc.NewOAuthError(goidc.InvalidResquestObject, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return goidc.NewOAuthError(goidc.InvalidResquestObject, "request_uri is not allowed inside JAR")
	}

	// The PAR RFC says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	return validatePushedAuthorizationParams(ctx, jar.AuthorizationParameters, client)
}

func validatePushedAuthorizationParams(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
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
	_ goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if client.AuthnMethod == goidc.NoneAuthn {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid client authentication method")
	}
	return nil
}

func validateOpenIdRedirectUri(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {

	if ctx.Profile != goidc.OpenIdProfile {
		return nil
	}

	if params.RedirectUri != "" && !client.IsRedirectUriAllowed(params.RedirectUri) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateFapi2RedirectUri(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {

	if ctx.Profile != goidc.Fapi2Profile {
		return nil
	}

	// According to FAPI 2.0 "pre-registration is not required with client authentication and PAR".
	if params.RedirectUri == "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "redirect_uri is required")
	}
	return nil
}

func validateResponseType(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.Scopes != "" && ctx.OpenIdScopeIsRequired && !utils.ScopesContainsOpenId(params.Scopes) {
		return goidc.NewOAuthError(goidc.InvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(params.Scopes) {
		return goidc.NewOAuthError(goidc.InvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestUri(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.RequestUri != "" {
		return goidc.NewOAuthError(goidc.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return nil
}
