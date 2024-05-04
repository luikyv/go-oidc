package oauth

import (
	"slices"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//-------------------------------------------------------------- Validators --------------------------------------------------------------//

func validateClientAuthnRequest(req models.ClientAuthnRequest) (clientId string, err issues.OAuthError) {

	clientId, ok := getClientId(req)
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

	return clientId, nil
}

func getClientId(req models.ClientAuthnRequest) (clientId string, ok bool) {
	clientIds := []string{}

	if req.ClientIdPost != "" {
		clientIds = append(clientIds, req.ClientIdPost)
	}

	if req.ClientIdBasicAuthn != "" {
		clientIds = append(clientIds, req.ClientIdBasicAuthn)
	}

	if req.ClientAssertion != "" {
		assertionClientId, ok := getClientIdFromAssertion(req)
		if !ok {
			return "", false
		}
		clientIds = append(clientIds, assertionClientId)
	}

	// All the client IDs present must be equal.
	if len(clientIds) == 0 || !unit.AllEquals(clientIds) {
		return "", false
	}

	return clientIds[0], true
}

func validatePushedRequest(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) issues.OAuthError {

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return validateBaseRequestNonEmptyFields(req.AuthorizationParameters, client)
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
	return validateOAuthCoreRequest(ctx, jar, client)
}

func validateRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) issues.OAuthError {

	if err := validateRequestWithParNoRedirect(ctx, req, session, client); err != nil {
		return convertErrorIfRedirectableWithDefaultValues(err, req, session.AuthorizationParameters, client)
	}

	return nil
}

func validateRequestWithParNoRedirect(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) issues.OAuthError {
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	if session.IsPushedRequestExpired() {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri is expired")
	}

	return validateRequestWithDefaultValues(ctx, req, session.AuthorizationParameters, client)
}

func validateRequestWithJar(ctx utils.Context, req models.AuthorizationRequest, jar models.AuthorizationRequest, client models.Client) issues.OAuthError {
	if err := validateRequestWithJarNoRedirect(ctx, req, jar, client); err != nil {
		return convertErrorIfRedirectableWithDefaultValues(err, req, jar.AuthorizationParameters, client)
	}

	return nil
}

func validateRequestWithJarNoRedirect(ctx utils.Context, req models.AuthorizationRequest, jar models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request is not allowed inside the request object")
	}

	if err := validateBaseRequestNonEmptyFields(jar.AuthorizationParameters, client); err != nil {
		return err
	}

	return validateRequestWithDefaultValues(ctx, req, jar.AuthorizationParameters, client)
}

func validateRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {
	if err := validateRequestNoRedirect(ctx, req, client); err != nil {
		return convertErrorIfRedirectable(err, req, client)
	}

	return nil
}

func validateRequestNoRedirect(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreRequest(ctx, req, client)
	default:
		return validateOAuthCoreRequest(ctx, req, client)
	}
}

func validateRequestWithDefaultValues(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreRequestWithDefaultValues(ctx, req, defaultValues, client)
	default:
		return validateOAuthCoreRequestWithDefaultValues(ctx, req, defaultValues, client)
	}
}

func validateOpenIdCoreRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if req.Scope == "" || !slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateOAuthCoreRequest(ctx, req, client)
}

func validateOAuthCoreRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "response_type is required")
	}

	if client.PkceIsRequired && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}

	if req.RequestUri != "" && req.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}

	return validateBaseRequestNonEmptyFields(req.AuthorizationParameters, client)
}

func validateOpenIdCoreRequestWithDefaultValues(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if !unit.ScopeContainsOpenId(req.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateOAuthCoreRequestWithDefaultValues(ctx, req, defaultValues, client)
}

func validateOAuthCoreRequestWithDefaultValues(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {

	if defaultValues.RedirectUri == "" && req.RedirectUri == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.RequestUri != "" && req.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}

	if defaultValues.ResponseType != "" && req.ResponseType != "" && defaultValues.ResponseType != req.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	responseType := defaultValues.ResponseType
	if responseType == "" {
		responseType = req.ResponseType
	}
	responseMode := defaultValues.ResponseMode
	if responseMode == "" {
		responseMode = req.ResponseMode
	}
	if responseType.IsImplict() && responseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if client.PkceIsRequired && defaultValues.CodeChallenge == "" && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "PKCE is required")
	}

	return validateBaseRequestNonEmptyFields(req.AuthorizationParameters, client)
}

func validateBaseRequestNonEmptyFields(req models.AuthorizationParameters, client models.Client) issues.OAuthError {

	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}

	if req.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	if req.ResponseType != "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}

	return nil
}
