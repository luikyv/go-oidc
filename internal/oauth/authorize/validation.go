package authorize

import (
	"github.com/luikymagno/auth-server/internal/issues"
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
) issues.OAuthError {

	if err := validateAuthorizationRequestWithParNoRedirect(ctx, req, session, client); err != nil {
		return convertErrorIfRedirectableWithPriorities(err, req.AuthorizationParameters, session.AuthorizationParameters, client)
	}

	return nil
}

func validateAuthorizationRequestWithParNoRedirect(
	ctx utils.Context,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) issues.OAuthError {
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	if session.IsPushedRequestExpired() {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri is expired")
	}

	return validateParamsWithPrioritiesNoRedirect(ctx, req.AuthorizationParameters, session.AuthorizationParameters, client)
}

func validateAuthorizationRequestWithJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateAuthorizationRequestWithJarNoRedirect(ctx, req, jar, client); err != nil {
		return convertErrorIfRedirectableWithPriorities(err, req.AuthorizationParameters, jar.AuthorizationParameters, client)
	}

	return nil
}

func validateAuthorizationRequestWithJarNoRedirect(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request is not allowed inside the request object")
	}

	if err := ValidateNonEmptyParamsNoRedirect(ctx, jar.AuthorizationParameters, client); err != nil {
		return err
	}

	return validateParamsWithPriorities(ctx, req.AuthorizationParameters, jar.AuthorizationParameters, client)
}

func validateParamsWithPriorities(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if err := validateParamsWithPrioritiesNoRedirect(ctx, params, prioritaryParams, client); err != nil {
		return convertErrorIfRedirectable(err, params, client)
	}

	return nil
}

func validateParamsWithPrioritiesNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	scopes := unit.SplitStringWithSpaces(unit.GetNonEmptyOrDefault(prioritaryParams.Scope, params.Scope))
	switch ctx.GetProfile(scopes) {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreParamsWithPrioritiesNoRedirect(ctx, params, prioritaryParams, client)
	default:
		return validateOAuthCoreParamsWithPrioritiesNoRedirect(ctx, params, prioritaryParams, client)
	}
}

func validateOpenIdCoreParamsWithPrioritiesNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if params.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	if prioritaryParams.ResponseType != "" && params.ResponseType != "" && prioritaryParams.ResponseType != params.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if err := ValidateNonEmptyParamsNoRedirect(ctx, params, client); err != nil {
		return err
	}

	mergedParams := prioritaryParams.Merge(params)
	return validateOpenIdCoreParamsNoRedirect(ctx, mergedParams, client)
}

func validateOAuthCoreParamsWithPrioritiesNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if err := ValidateNonEmptyParamsNoRedirect(ctx, params, client); err != nil {
		return err
	}

	mergedParams := prioritaryParams.Merge(params)
	return ValidateOAuthCoreParamsNoRedirect(ctx, mergedParams, client)
}

func validateAuthorizationRequest(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateParamsNoRedirect(ctx, req.AuthorizationParameters, client); err != nil {
		return convertErrorIfRedirectable(err, req.AuthorizationParameters, client)
	}

	return nil
}

func validateParamsNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	switch ctx.GetProfile(unit.SplitStringWithSpaces(params.Scope)) {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreParamsNoRedirect(ctx, params, client)
	default:
		return ValidateOAuthCoreParamsNoRedirect(ctx, params, client)
	}
}

func validateOpenIdCoreParamsNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	if params.ResponseType.Contains(constants.IdTokenResponse) && params.Nonce == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "nonce is required when response_type contains id_token")
	}

	return ValidateOAuthCoreParamsNoRedirect(ctx, params, client)
}

func ValidateOAuthCoreParamsNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if params.ResponseType.Contains(constants.IdTokenResponse) && !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidRequest, "cannot request id_token without the scope openid")
	}

	if params.RedirectUri == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}

	if params.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if params.ResponseType.IsImplict() && params.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if client.PkceIsRequired && params.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}

	return ValidateNonEmptyParamsNoRedirect(ctx, params, client)
}

func ValidateNonEmptyParamsNoRedirect(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if params.RedirectUri != "" && !client.IsRedirectUriAllowed(params.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if params.ResponseMode != "" && !client.IsResponseModeAllowed(params.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}

	if params.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(params.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if params.ResponseType.Contains(constants.CodeResponse) && !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return issues.NewOAuthError(constants.InvalidGrant, "authorization_code grant not allowed")
	}

	if params.ResponseType.IsImplict() && !client.IsGrantTypeAllowed(constants.ImplictGrant) {
		return issues.NewOAuthError(constants.InvalidGrant, "implicit grant not allowed")
	}

	if params.CodeChallengeMethod != "" && !params.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}

	if params.RequestUri != "" && params.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}

	return nil
}

func convertErrorIfRedirectableWithPriorities(
	oauthErr issues.OAuthError,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	mergedParams := prioritaryParams.Merge(params)
	return convertErrorIfRedirectable(oauthErr, mergedParams, client)
}

func convertErrorIfRedirectable(
	oauthErr issues.OAuthError,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	responseMode := unit.GetResponseModeOrDefault(params.ResponseMode, params.ResponseType)
	if client.IsRedirectUriAllowed(params.RedirectUri) && client.IsResponseModeAllowed(responseMode) {
		return issues.NewOAuthRedirectError(
			oauthErr.GetCode(),
			oauthErr.Error(),
			client.Id,
			params.RedirectUri,
			responseMode,
			params.State,
		)
	}

	return oauthErr
}
