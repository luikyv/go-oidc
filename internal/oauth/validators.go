package oauth

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//-------------------------------------------------------------- Validators --------------------------------------------------------------//

// Validate a client authentication request and return a valid client ID from it.
func validateClientAuthnRequest(req models.ClientAuthnRequest) (validClientId string, err issues.OAuthError) {

	validClientId, ok := getClientId(req)
	if !ok {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	// Validate parameters for client secret basic authentication.
	if req.ClientSecretBasicAuthn != "" && (req.ClientIdBasicAuthn == "" || unit.AnyNonEmpty(req.ClientSecretPost, string(req.ClientAssertionType), req.ClientAssertion)) {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	// Validate parameters for client secret post authentication.
	if req.ClientSecretPost != "" && (req.ClientIdPost == "" || unit.AnyNonEmpty(req.ClientIdBasicAuthn, req.ClientSecretBasicAuthn, string(req.ClientAssertionType), req.ClientAssertion)) {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	// Validate parameters for private key jwt authentication.
	if req.ClientAssertion != "" && (req.ClientAssertionType != constants.JWTBearerAssertion || unit.AnyNonEmpty(req.ClientIdBasicAuthn, req.ClientSecretBasicAuthn, req.ClientSecretPost)) {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	return validClientId, nil
}

func validatePushedRequest(_ utils.Context, req models.PushedAuthorizationRequest, client models.Client) issues.OAuthError {

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return validateNonEmptyParamsNoRedirect(req.AuthorizationParameters, client)
}

func validatePushedRequestWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, jar models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	// The PAR RFC (https://datatracker.ietf.org/doc/html/rfc9126#section-3) says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC (https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2.) says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	return validateOAuthCoreParamsNoRedirect(ctx, jar.AuthorizationParameters, client)
}

func validateAuthorizationRequestWithPar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) issues.OAuthError {

	if err := validateAuthorizationRequestWithParNoRedirect(ctx, req, session, client); err != nil {
		return convertErrorIfRedirectableWithPriorities(err, req, session.AuthorizationParameters, client)
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

	return validateParamsWithPriorities(ctx, req.AuthorizationParameters, session.AuthorizationParameters, client)
}

func validateAuthorizationRequestWithJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateAuthorizationRequestWithJarNoRedirect(ctx, req, jar, client); err != nil {
		return convertErrorIfRedirectableWithPriorities(err, req, jar.AuthorizationParameters, client)
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

	if err := validateNonEmptyParamsNoRedirect(jar.AuthorizationParameters, client); err != nil {
		return err
	}

	return validateParamsWithPriorities(ctx, req.AuthorizationParameters, jar.AuthorizationParameters, client)
}

func validateRequest(ctx utils.Context, params models.AuthorizationParameters, client models.Client) issues.OAuthError {
	if err := validateParamsNoRedirect(ctx, params, client); err != nil {
		return convertErrorIfRedirectable(err, params, client)
	}

	return nil
}

func validateParamsNoRedirect(ctx utils.Context, params models.AuthorizationParameters, client models.Client) issues.OAuthError {
	switch ctx.GetProfile(params.Scope) {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreParamsNoRedirect(ctx, params, client)
	default:
		return validateOAuthCoreParamsNoRedirect(ctx, params, client)
	}
}

func validateParamsWithPriorities(ctx utils.Context, params models.AuthorizationParameters, prioritaryParams models.AuthorizationParameters, client models.Client) issues.OAuthError {
	if err := validateParamsWithPrioritiesNoRedirect(ctx, params, prioritaryParams, client); err != nil {
		return convertErrorIfRedirectable(err, params, client)
	}

	return nil
}

func validateParamsWithPrioritiesNoRedirect(ctx utils.Context, params models.AuthorizationParameters, prioritaryParams models.AuthorizationParameters, client models.Client) issues.OAuthError {
	// FIXME
	switch ctx.GetProfile(params.Scope) {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreParamsWithPrioritiesNoRedirect(ctx, params, prioritaryParams, client)
	default:
		return validateOAuthCoreParamsWithPrioritiesNoRedirect(ctx, params, prioritaryParams, client)
	}
}

// func validateOpenIdCoreRequestWithDefaultValuesNoRedirect(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {

// 	if req.ResponseType == "" {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
// 	}

// 	if !unit.ScopeContainsOpenId(req.Scope) {
// 		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
// 	}

// 	return validateOAuthCoreRequestWithDefaultValuesNoRedirect(ctx, req, defaultValues, client)
// }

// func validateOAuthCoreRequestWithDefaultValuesNoRedirect(_ utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {

// 	if defaultValues.RedirectUri == "" && req.RedirectUri == "" {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
// 	}

// 	if req.RequestUri != "" && req.RequestObject != "" {
// 		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
// 	}

// 	responseType := defaultValues.ResponseType
// 	if responseType == "" {
// 		responseType = req.ResponseType
// 	}
// 	if defaultValues.ResponseType != "" && req.ResponseType != "" && defaultValues.ResponseType != req.ResponseType {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
// 	}

// 	responseMode := defaultValues.ResponseMode
// 	if responseMode == "" {
// 		responseMode = req.ResponseMode
// 	}
// 	if responseType.IsImplict() && responseMode.IsQuery() {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
// 	}

// 	if client.PkceIsRequired && defaultValues.CodeChallenge == "" && req.CodeChallenge == "" {
// 		return issues.NewOAuthError(constants.InvalidRequest, "PKCE is required")
// 	}

// 	return validateBaseRequestNonEmptyFieldsNoRedirect(req.AuthorizationParameters, client)
// }

func validateOpenIdCoreParamsWithPrioritiesNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if params.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if !unit.ScopeContainsOpenId(params.Scope) || !unit.ScopeContainsOpenId(prioritaryParams.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateParamsWithPrioritiesCommonRulesNoRedirect(ctx, params, prioritaryParams, client)
}

func validateOAuthCoreParamsWithPrioritiesNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	responseType := unit.GetNonEmptyOrDefault(prioritaryParams.ResponseType, params.ResponseType)
	if !responseType.IsOAuthCoreValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	return validateParamsWithPrioritiesCommonRulesNoRedirect(ctx, params, prioritaryParams, client)
}

func validateParamsWithPrioritiesCommonRulesNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if prioritaryParams.ResponseType != "" && params.ResponseType != "" && prioritaryParams.ResponseType != params.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	combinedParams := models.AuthorizationParameters{
		RedirectUri:         unit.GetNonEmptyOrDefault(prioritaryParams.RedirectUri, params.RedirectUri),
		ResponseMode:        unit.GetNonEmptyOrDefault(prioritaryParams.ResponseMode, params.ResponseMode),
		ResponseType:        unit.GetNonEmptyOrDefault(prioritaryParams.ResponseType, params.ResponseType),
		Scope:               unit.GetNonEmptyOrDefault(prioritaryParams.Scope, params.Scope),
		State:               unit.GetNonEmptyOrDefault(prioritaryParams.State, params.State),
		Nonce:               unit.GetNonEmptyOrDefault(prioritaryParams.Nonce, params.Nonce),
		CodeChallenge:       unit.GetNonEmptyOrDefault(prioritaryParams.CodeChallenge, params.CodeChallenge),
		CodeChallengeMethod: unit.GetNonEmptyOrDefault(prioritaryParams.CodeChallengeMethod, params.CodeChallengeMethod),
	}

	return validateParamsCommonRulesNoRedirect(ctx, combinedParams, client)
}

func validateOpenIdCoreParamsNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if params.Scope == "" || !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateParamsCommonRulesNoRedirect(ctx, params, client)
}

func validateOAuthCoreParamsNoRedirect(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if !params.ResponseType.IsOAuthCoreValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	return validateParamsCommonRulesNoRedirect(ctx, params, client)
}

func validateParamsCommonRulesNoRedirect(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if params.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}

	if params.ResponseType.IsImplict() && params.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if client.PkceIsRequired && params.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}

	return validateNonEmptyParamsNoRedirect(params, client)
}

func validateNonEmptyParamsNoRedirect(
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

	if params.ResponseType != "" && (!params.ResponseType.IsValid() || !client.IsResponseTypeAllowed(params.ResponseType)) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if params.CodeChallengeMethod != "" && !params.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}

	if params.RequestUri != "" && params.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}

	return nil
}
