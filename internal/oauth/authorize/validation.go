package authorize

// As a general rule, the validations that indicate whether the request is redirectable or not, must come first
// as the other errors should be redirected.

import (
	"slices"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateAuthorizationRequestWithPar(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	session goidc.AuthnSession,
	client goidc.Client,
) goidc.OAuthError {
	if session.ClientId != req.ClientId {
		return goidc.NewOAuthError(goidc.AccessDenied, "invalid client")
	}

	if err := validateInsideWithOutsideParams(ctx, session.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := session.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if session.IsPushedRequestExpired(ctx.ParLifetimeSecs) {
		return mergedParams.NewRedirectError(goidc.InvalidRequest, "the request_uri is expired")
	}

	return nil
}

func validateAuthorizationRequestWithJar(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	jar utils.AuthorizationRequest,
	client goidc.Client,
) goidc.OAuthError {

	if jar.ClientId != client.Id {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid client_id")
	}

	if err := validateInsideWithOutsideParams(ctx, jar.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if jar.RequestUri != "" {
		return mergedParams.NewRedirectError(goidc.InvalidRequest, "request_uri is not allowed inside the request object")
	}

	if jar.RequestObject != "" {
		return mergedParams.NewRedirectError(goidc.InvalidRequest, "request is not allowed inside the request object")
	}

	return nil
}

func validateAuthorizationRequest(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) goidc.OAuthError {
	return validateAuthorizationParams(ctx, req.AuthorizationParameters, client)
}

func validateInsideWithOutsideParams(
	ctx utils.Context,
	insideParams goidc.AuthorizationParameters,
	outsideParams goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	mergedParams := insideParams.Merge(outsideParams)
	if err := validateAuthorizationParams(ctx, mergedParams, client); err != nil {
		return err
	}

	if err := validateOpenIdInsideWithOutsideParams(ctx, insideParams, outsideParams, client); err != nil {
		return err
	}

	return nil
}

func validateOpenIdInsideWithOutsideParams(
	ctx utils.Context,
	insideParams goidc.AuthorizationParameters,
	outsideParams goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {

	mergedParams := insideParams.Merge(outsideParams)
	// When the openid scope is not requested, the authorization request becomes a standard OAuth one,
	// so there's no need to validate these rules below.
	if ctx.Profile == goidc.OpenIdProfile && utils.ScopesContainsOpenId(mergedParams.Scopes) {
		if outsideParams.ResponseType == "" {
			return mergedParams.NewRedirectError(goidc.InvalidRequest, "invalid response_type")
		}

		if insideParams.ResponseType != "" && insideParams.ResponseType != outsideParams.ResponseType {
			return mergedParams.NewRedirectError(goidc.InvalidRequest, "invalid response_type")
		}

		if !utils.ScopesContainsOpenId(outsideParams.Scopes) {
			return mergedParams.NewRedirectError(goidc.InvalidScope, "scope openid is required")
		}
	}

	return nil
}

func validateAuthorizationParams(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	return utils.RunValidations(
		ctx, params, client,
		validateOpenIdRedirectUri,
		ValidateResponseMode,
		ValidateJwtResponseModeIsRequired,
		validateResponseType,
		validateScopes,
		validateScopeOpenIdIsRequiredWhenResponseTypeIsIdToken,
		validateCannotInformRequestUriAndRequestObject,
		validatePkce,
		ValidateCodeChallengeMethod,
		ValidateDisplayValue,
		ValidateAuthorizationDetails,
		ValidateAcrValues,
		validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested,
		validateNonceIsRequiredWhenResponseTypeContainsIdToken,
		ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed,
		validateCannotRequestQueryResponseModeWhenImplicitResponseTypeIsRequested,
	)
}

func validateOpenIdRedirectUri(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {

	if ctx.Profile != goidc.OpenIdProfile {
		return nil
	}

	if params.RedirectUri == "" || !client.IsRedirectUriAllowed(params.RedirectUri) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func ValidateResponseMode(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseMode != "" && (!ctx.JarmIsEnabled && params.ResponseMode.IsJarm()) {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid response_mode")
	}

	return nil
}

func ValidateJwtResponseModeIsRequired(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if params.ResponseMode != "" && client.JarmSignatureAlgorithm != "" && !params.ResponseMode.IsJarm() {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid response_mode")
	}

	return nil
}

func validateResponseType(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType == "" || !client.IsResponseTypeAllowed(params.ResponseType) {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateScopeOpenIdIsRequiredWhenResponseTypeIsIdToken(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.IdTokenResponse) && !utils.ScopesContainsOpenId(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if ctx.OpenIdScopeIsRequired && !utils.ScopesContainsOpenId(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestUriAndRequestObject(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.RequestUri != "" && params.RequestObject != "" {
		return params.NewRedirectError(goidc.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}
	return nil
}

func validatePkce(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if ctx.PkceIsEnabled && client.AuthnMethod == goidc.NoneAuthn && params.CodeChallenge == "" {
		return params.NewRedirectError(goidc.InvalidRequest, "pkce is required for public clients")
	}

	if ctx.PkceIsRequired && params.CodeChallenge == "" {
		return params.NewRedirectError(goidc.InvalidRequest, "code_challenge is required")
	}
	return nil
}

func ValidateCodeChallengeMethod(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.CodeChallengeMethod != "" && !slices.Contains(ctx.CodeChallengeMethods, params.CodeChallengeMethod) {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid code_challenge_method")
	}
	return nil
}

func ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.CodeResponse) && !client.IsGrantTypeAllowed(goidc.AuthorizationCodeGrant) {
		return params.NewRedirectError(goidc.InvalidGrant, "authorization_code grant not allowed")
	}
	return nil
}

func ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.IsImplicit() && !client.IsGrantTypeAllowed(goidc.ImplicitGrant) {
		return params.NewRedirectError(goidc.InvalidRequest, "implicit grant not allowed")
	}
	return nil
}

func validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.IdTokenResponse) && !utils.ScopesContainsOpenId(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateNonceIsRequiredWhenResponseTypeContainsIdToken(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.IdTokenResponse) && params.Nonce == "" {
		return params.NewRedirectError(goidc.InvalidRequest, "nonce is required when response type id_token is requested")
	}
	return nil
}

func validateCannotRequestQueryResponseModeWhenImplicitResponseTypeIsRequested(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.IsImplicit() && params.ResponseMode.IsQuery() {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid response_mode for the chosen response_type")
	}
	return nil
}

func ValidateDisplayValue(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {
	if params.Display != "" && !slices.Contains(ctx.DisplayValues, params.Display) {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid display value")
	}
	return nil
}

func ValidateAuthorizationDetails(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if !ctx.AuthorizationDetailsParameterIsEnabled || params.AuthorizationDetails == nil {
		return nil
	}

	for _, authDetail := range params.AuthorizationDetails {
		authDetailType := authDetail.GetType()
		if !slices.Contains(ctx.AuthorizationDetailTypes, authDetailType) || !client.IsAuthorizationDetailTypeAllowed(authDetailType) {
			return params.NewRedirectError(goidc.InvalidRequest, "invalid authorization detail type")
		}
	}

	return nil
}

func ValidateAcrValues(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {

	if params.AcrValues == "" {
		return nil
	}

	for _, acr := range goidc.SplitStringWithSpaces(params.AcrValues) {
		if !slices.Contains(ctx.AuthenticationContextReferences, goidc.AuthenticationContextReference(acr)) {
			return params.NewRedirectError(goidc.InvalidRequest, "invalid acr value")
		}
	}

	return nil
}
