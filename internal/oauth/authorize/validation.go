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
		return convertErrorIfRedirectableWithPar(err, req, session, client)
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

	return validateAuthorizationParamsWithPriorities(ctx, req.AuthorizationParameters, session.AuthorizationParameters, client)
}

func validateAuthorizationRequestWithJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateAuthorizationRequestWithJarNoRedirect(ctx, req, jar, client); err != nil {
		return convertErrorIfRedirectableWithJar(err, req, jar, client)
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

	if err := ValidateNonEmptyParams(ctx, jar.AuthorizationParameters, client); err != nil {
		return err
	}

	return validateAuthorizationParamsWithPriorities(ctx, req.AuthorizationParameters, jar.AuthorizationParameters, client)
}

func validateAuthorizationParamsWithPriorities(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if err := validateOpenIdScopeIfRequiredWithPriorities(ctx, params, prioritaryParams, client); err != nil {
		return err
	}

	if err := validateResponseTypeIsRequired(ctx, params, client); err != nil {
		return err
	}

	if err := validateResponseTypeMustMatch(ctx, params, prioritaryParams, client); err != nil {
		return err
	}

	if err := ValidateNonEmptyParams(ctx, params, client); err != nil {
		return err
	}

	mergedParams := prioritaryParams.Merge(params)
	return validateAuthorizationParams(ctx, mergedParams, client)
}

func validateAuthorizationRequest(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateAuthorizationParams(ctx, req.AuthorizationParameters, client); err != nil {
		return convertErrorIfRedirectable(err, req.AuthorizationParameters, client)
	}

	return nil
}

func validateAuthorizationParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	return runValidations(
		ctx, params, client,
		validateOpenIdScopeIfRequired,
		validateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		validateCannotRequestImplictResponseTypeWhenImplictGrantIsNotAllowed,
		validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested,
		validateRedirectUriIsRequired,
		validateResponseTypeIsRequired,
		validateResponseModeIfPresent,
		validateScopesIfPresent,
		validateCannotRequestQueryResponseModeWhenImplictResponseTypeIsRequested,
		validateNonceIsRequiredWhenIdTokenResponseTypeIsRequested,
		validatePkceIfRequired,
		validateCodeChallengeMethodIfPresent,
	)
}

func ValidateNonEmptyParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	return runValidations(
		ctx, params, client,
		validateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		validateCannotRequestImplictResponseTypeWhenImplictGrantIsNotAllowed,
		validateRedirectUriIfPresent,
		validateResponseModeIfPresent,
		validateScopesIfPresent,
		validateResponseTypeIfPresent,
		validateCodeChallengeMethodIfPresent,
		validateCannotInformRequestUriAndRequestObject,
	)
}

//---------------------------------------- Unit Validations ----------------------------------------//

func runValidations(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
	validators ...func(
		ctx utils.Context,
		params models.AuthorizationParameters,
		client models.Client,
	) issues.OAuthError,
) issues.OAuthError {
	for _, validator := range validators {
		if err := validator(ctx, params, client); err != nil {
			return err
		}
	}

	return nil
}

func validateOpenIdScopeIfRequiredWithPriorities(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	_ models.Client,
) issues.OAuthError {

	scopes := unit.SplitStringWithSpaces(unit.GetNonEmptyOrDefault(prioritaryParams.Scope, params.Scope))
	profile := ctx.GetProfile(scopes)
	if !profile.IsOpenIdVariant() {
		return nil
	}

	if !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return nil
}

func validateOpenIdScopeIfRequired(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	profile := ctx.GetProfile(unit.SplitStringWithSpaces(params.Scope))
	if !profile.IsOpenIdVariant() {
		return nil
	}

	if !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateRedirectUriIsRequired(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RedirectUri == "" || !client.IsRedirectUriAllowed(params.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateRedirectUriIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RedirectUri != "" && !client.IsRedirectUriAllowed(params.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateResponseModeIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseMode != "" && !client.IsResponseModeAllowed(params.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}
	return nil
}

func validateScopesIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(params.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateResponseTypeIsRequired(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType == "" || !client.IsResponseTypeAllowed(params.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateResponseTypeIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateCodeChallengeMethodIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.CodeChallengeMethod != "" && !params.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}
	return nil
}

func validateCannotInformRequestUriAndRequestObject(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RequestUri != "" && params.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}
	return nil
}

func validateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.Contains(constants.CodeResponse) && !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return issues.NewOAuthError(constants.InvalidGrant, "authorization_code grant not allowed")
	}
	return nil
}

func validateCannotRequestImplictResponseTypeWhenImplictGrantIsNotAllowed(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.IsImplict() && !client.IsGrantTypeAllowed(constants.ImplictGrant) {
		return issues.NewOAuthError(constants.InvalidGrant, "implicit grant not allowed")
	}
	return nil
}

func validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateCannotRequestQueryResponseModeWhenImplictResponseTypeIsRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.IsImplict() && params.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}
	return nil
}

func validateNonceIsRequiredWhenIdTokenResponseTypeIsRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && params.Nonce == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "nonce is required when response_type contains id_token")
	}
	return nil
}

func validatePkceIfRequired(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if client.PkceIsRequired && params.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}
	return nil
}

func validateResponseTypeMustMatch(
	_ utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	_ models.Client,
) issues.OAuthError {
	if prioritaryParams.ResponseType != "" && params.ResponseType != "" && prioritaryParams.ResponseType != params.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

//---------------------------------------- Redirect Errors ----------------------------------------//

func convertErrorIfRedirectableWithPar(
	oauthErr issues.OAuthError,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) issues.OAuthError {

	if req.ClientId != session.ClientId {
		return oauthErr
	}

	mergedParams := session.AuthorizationParameters.Merge(req.AuthorizationParameters)
	return convertErrorIfRedirectable(oauthErr, mergedParams, client)
}

func convertErrorIfRedirectableWithJar(
	oauthErr issues.OAuthError,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if req.ClientId != jar.ClientId {
		return oauthErr
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	return convertErrorIfRedirectable(oauthErr, mergedParams, client)
}

func convertErrorIfRedirectable(
	oauthErr issues.OAuthError,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	responseMode := unit.GetResponseModeOrDefault(params.ResponseMode, params.ResponseType)
	if !client.IsRedirectUriAllowed(params.RedirectUri) || !client.IsResponseModeAllowed(responseMode) {
		return oauthErr
	}

	return issues.NewOAuthRedirectError(
		oauthErr.GetCode(),
		oauthErr.Error(),
		client.Id,
		params.RedirectUri,
		responseMode,
		params.State,
	)
}
