package authorize

// As a general rule, the validations that indicate whether the request is redirectable or not, must come first
// as the other errors should be redirected.

import (
	"slices"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func validateAuthorizationRequestWithPAR(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	session goidc.AuthnSession,
	client goidc.Client,
) goidc.OAuthError {
	if session.ClientID != req.ClientID {
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

func validateAuthorizationRequestWithJAR(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	jar utils.AuthorizationRequest,
	client goidc.Client,
) goidc.OAuthError {

	if jar.ClientID != client.ID {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid client_id")
	}

	if err := validateInsideWithOutsideParams(ctx, jar.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if jar.RequestURI != "" {
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

	if err := validateOpenIDInsideWithOutsideParams(ctx, insideParams, outsideParams, client); err != nil {
		return err
	}

	return nil
}

func validateOpenIDInsideWithOutsideParams(
	ctx utils.Context,
	insideParams goidc.AuthorizationParameters,
	outsideParams goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {

	mergedParams := insideParams.Merge(outsideParams)
	// When the openid scope is not requested, the authorization request becomes a standard OAuth one,
	// so there's no need to validate these rules below.
	if ctx.Profile == goidc.OpenIDProfile && utils.ScopesContainsOpenID(mergedParams.Scopes) {
		if outsideParams.ResponseType == "" {
			return mergedParams.NewRedirectError(goidc.InvalidRequest, "invalid response_type")
		}

		if insideParams.ResponseType != "" && insideParams.ResponseType != outsideParams.ResponseType {
			return mergedParams.NewRedirectError(goidc.InvalidRequest, "invalid response_type")
		}

		if !utils.ScopesContainsOpenID(outsideParams.Scopes) {
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
		validateOpenIDRedirectURI,
		ValidateResponseMode,
		ValidateJWTResponseModeIsRequired,
		validateResponseType,
		validateScopes,
		validateScopeOpenIDIsRequiredWhenResponseTypeIsIDToken,
		validateCannotInformRequestURIAndRequestObject,
		validatePkce,
		ValidateCodeChallengeMethod,
		ValidateDisplayValue,
		ValidateAuthorizationDetails,
		ValidateAcrValues,
		validateCannotRequestIDTokenResponseTypeIfOpenIDScopeIsNotRequested,
		validateNonceIsRequiredWhenResponseTypeContainsIDToken,
		ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed,
		validateCannotRequestQueryResponseModeWhenImplicitResponseTypeIsRequested,
	)
}

func validateOpenIDRedirectURI(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {

	if ctx.Profile != goidc.OpenIDProfile {
		return nil
	}

	if params.RedirectURI == "" || !client.IsRedirectURIAllowed(params.RedirectURI) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func ValidateResponseMode(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseMode != "" && (!ctx.JARMIsEnabled && params.ResponseMode.IsJARM()) {
		return params.NewRedirectError(goidc.InvalidRequest, "invalid response_mode")
	}

	return nil
}

func ValidateJWTResponseModeIsRequired(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if params.ResponseMode != "" && client.JARMSignatureAlgorithm != "" && !params.ResponseMode.IsJARM() {
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

func validateScopeOpenIDIsRequiredWhenResponseTypeIsIDToken(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.IDTokenResponse) && !utils.ScopesContainsOpenID(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if ctx.OpenIDScopeIsRequired && !utils.ScopesContainsOpenID(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestURIAndRequestObject(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.RequestURI != "" && params.RequestObject != "" {
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

func validateCannotRequestIDTokenResponseTypeIfOpenIDScopeIsNotRequested(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	client goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.IDTokenResponse) && !utils.ScopesContainsOpenID(params.Scopes) {
		return params.NewRedirectError(goidc.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateNonceIsRequiredWhenResponseTypeContainsIDToken(
	_ utils.Context,
	params goidc.AuthorizationParameters,
	_ goidc.Client,
) goidc.OAuthError {
	if params.ResponseType.Contains(goidc.IDTokenResponse) && params.Nonce == "" {
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

	if params.ACRValues == "" {
		return nil
	}

	for _, acr := range goidc.SplitStringWithSpaces(params.ACRValues) {
		if !slices.Contains(ctx.AuthenticationContextReferences, goidc.AuthenticationContextReference(acr)) {
			return params.NewRedirectError(goidc.InvalidRequest, "invalid acr value")
		}
	}

	return nil
}
