package authorize

import (
	"slices"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateAuthorizationRequestWithPar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) models.OAuthError {
	if session.ClientId != req.ClientId {
		return models.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	if err := validateInsideWithOutsideParams(ctx, session.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := session.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if session.IsPushedRequestExpired(ctx.ParLifetimeSecs) {
		return mergedParams.NewRedirectError(constants.InvalidRequest, "the request_uri is expired")
	}

	return nil
}

func validateAuthorizationRequestWithJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) models.OAuthError {

	if jar.ClientId != client.Id {
		return models.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if err := validateInsideWithOutsideParams(ctx, jar.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if jar.RequestUri != "" {
		return mergedParams.NewRedirectError(constants.InvalidRequest, "request_uri is not allowed inside the request object")
	}

	if jar.RequestObject != "" {
		return mergedParams.NewRedirectError(constants.InvalidRequest, "request is not allowed inside the request object")
	}

	return nil
}

func validateAuthorizationRequest(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) models.OAuthError {
	return validateAuthorizationParams(ctx, req.AuthorizationParameters, client)
}

func validateInsideWithOutsideParams(
	ctx utils.Context,
	insideParams models.AuthorizationParameters,
	outsideParams models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	mergedParams := insideParams.Merge(outsideParams)
	if err := validateAuthorizationParams(ctx, mergedParams, client); err != nil {
		return err
	}

	if ctx.Profile == constants.OpenIdProfile {
		if outsideParams.ResponseType == "" {
			return mergedParams.NewRedirectError(constants.InvalidRequest, "invalid response_type")
		}

		if insideParams.ResponseType != "" && insideParams.ResponseType != outsideParams.ResponseType {
			return mergedParams.NewRedirectError(constants.InvalidRequest, "invalid response_type")
		}

		if ctx.OpenIdScopeIsRequired && !unit.ScopesContainsOpenId(outsideParams.Scopes) {
			return mergedParams.NewRedirectError(constants.InvalidScope, "scope openid is required")
		}
	}

	return nil
}

func validateAuthorizationParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	return utils.RunValidations(
		ctx, params, client,
		validateRedirectUri,
		ValidateResponseMode,
		ValidateJwtResponseModeIsRequired,
		validateResponseType,
		validateScopes,
		validateScopeOpenIdIsRequiredWhenResponseTypeIsIdToken,
		validateCannotInformRequestUriAndRequestObject,
		validatePkce,
		ValidateCodeChallengeMethod,
		validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested,
		validateNonceIsRequiredWhenResponseTypeContainsIdToken,
		ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed,
		validateCannotRequestQueryResponseModeWhenImplicitResponseTypeIsRequested,
	)
}

func validateRedirectUri(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.RedirectUri == "" || !client.IsRedirectUriAllowed(params.RedirectUri) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func ValidateResponseMode(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseMode != "" && (!ctx.JarmIsEnabled && params.ResponseMode.IsJarm()) {
		return params.NewRedirectError(constants.InvalidRequest, "invalid response_mode")
	}

	return nil
}

func ValidateJwtResponseModeIsRequired(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if params.ResponseMode != "" && client.JarmSignatureAlgorithm != "" && !params.ResponseMode.IsJarm() {
		return params.NewRedirectError(constants.InvalidRequest, "invalid response_mode")
	}

	return nil
}

func validateResponseType(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseType == "" || !client.IsResponseTypeAllowed(params.ResponseType) {
		return params.NewRedirectError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateScopeOpenIdIsRequiredWhenResponseTypeIsIdToken(
	_ utils.Context,
	params models.AuthorizationParameters,
	_ models.Client,
) models.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && !unit.ScopesContainsOpenId(params.Scopes) {
		return params.NewRedirectError(constants.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateScopes(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if ctx.OpenIdScopeIsRequired && !unit.ScopesContainsOpenId(params.Scopes) {
		return params.NewRedirectError(constants.InvalidScope, "scope openid is required")
	}

	if params.Scopes != "" && !client.AreScopesAllowed(params.Scopes) {
		return params.NewRedirectError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateCannotInformRequestUriAndRequestObject(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.RequestUri != "" && params.RequestObject != "" {
		return params.NewRedirectError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}
	return nil
}

func validatePkce(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if !ctx.PkceIsEnabled {
		return nil
	}

	if (ctx.PkceIsRequired || client.PkceIsRequired) && params.CodeChallenge == "" {
		return params.NewRedirectError(constants.InvalidRequest, "code_challenge is required")
	}
	return nil
}

func ValidateCodeChallengeMethod(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.CodeChallengeMethod != "" && !slices.Contains(ctx.CodeChallengeMethods, params.CodeChallengeMethod) {
		return params.NewRedirectError(constants.InvalidRequest, "invalid code_challenge_method")
	}
	return nil
}

func ValidateCannotRequestCodeResponseTypeWhenAuthorizationCodeGrantIsNotAllowed(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseType.Contains(constants.CodeResponse) && !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return params.NewRedirectError(constants.InvalidGrant, "authorization_code grant not allowed")
	}
	return nil
}

func ValidateCannotRequestImplicitResponseTypeWhenImplicitGrantIsNotAllowed(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseType.IsImplicit() && !client.IsGrantTypeAllowed(constants.ImplicitGrant) {
		return params.NewRedirectError(constants.InvalidGrant, "implicit grant not allowed")
	}
	return nil
}

func validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && !unit.ScopesContainsOpenId(params.Scopes) {
		return params.NewRedirectError(constants.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateNonceIsRequiredWhenResponseTypeContainsIdToken(
	_ utils.Context,
	params models.AuthorizationParameters,
	_ models.Client,
) models.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && params.Nonce == "" {
		return params.NewRedirectError(constants.InvalidRequest, "nonce is required when response type id_token is requested")
	}
	return nil
}

func validateCannotRequestQueryResponseModeWhenImplicitResponseTypeIsRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) models.OAuthError {
	if params.ResponseType.IsImplicit() && params.ResponseMode.IsQuery() {
		return params.NewRedirectError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}
	return nil
}
