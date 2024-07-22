package par

import (
	"github.com/luikyv/goidc/internal/oauth/authorize"
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func validatePAR(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
	client *goidc.Client,
) goidc.OAuthError {
	return validatePushedAuthorizationParams(ctx, req.AuthorizationParameters, client)
}

func validateParWithJAR(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
	jar utils.AuthorizationRequest,
	client *goidc.Client,
) goidc.OAuthError {

	if req.RequestURI != "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientID != client.ID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid client_id")
	}

	if jar.RequestURI != "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "request_uri is not allowed inside JAR")
	}

	// The PAR RFC says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	return validatePushedAuthorizationParams(ctx, jar.AuthorizationParameters, client)
}

func validatePushedAuthorizationParams(
	ctx *utils.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	return utils.RunValidations(
		ctx, params, client,
		validateNoneAuthnNotAllowed,
		validateCannotInformRequestURI,
		authorize.ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		authorize.ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed,
		validateOpenIDRedirectURI,
		validateFAPI2RedirectURI,
		authorize.ValidateResponseMode,
		authorize.ValidateJWTResponseModeIsRequired,
		validateScopes,
		validateResponseType,
		authorize.ValidateCodeChallengeMethod,
		authorize.ValidateDisplayValue,
		authorize.ValidateAuthorizationDetails,
		authorize.ValidateACRValues,
	)
}

func validateNoneAuthnNotAllowed(
	_ *utils.Context,
	_ goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if client.AuthnMethod == goidc.ClientAuthnNone {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid client authentication method")
	}
	return nil
}

func validateOpenIDRedirectURI(
	ctx *utils.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {

	if ctx.Profile != goidc.ProfileOpenID {
		return nil
	}

	if params.RedirectURI != "" && !client.IsRedirectURIAllowed(params.RedirectURI) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateFAPI2RedirectURI(
	ctx *utils.Context,
	params goidc.AuthorizationParameters,
	_ *goidc.Client,
) goidc.OAuthError {

	if ctx.Profile != goidc.ProfileFAPI2 {
		return nil
	}

	// According to FAPI 2.0 "pre-registration is not required with client authentication and PAR".
	if params.RedirectURI == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "redirect_uri is required")
	}
	return nil
}

func validateResponseType(
	_ *utils.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid response_type")
	}
	return nil
}

func validateScopes(
	ctx *utils.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if params.Scopes != "" && ctx.OpenIDScopeIsRequired && !utils.ScopesContainsOpenID(params.Scopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(ctx, ctx.Scopes, params.Scopes) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestURI(
	ctx *utils.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if params.RequestURI != "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	return nil
}
