package oauth

import (
	"strings"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateSimpleRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreSimpleRequest(ctx, req, client)
	default:
		return validateOAuthCoreSimpleRequest(ctx, req, client)
	}
}

func validateRequestWithSupportingSession(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreRequestWithSupportingSession(ctx, req, session, client)
	default:
		return validateOAuthCoreRequestWithSupportingSession(ctx, req, session, client)
	}
}

func validateOpenIdCoreSimpleRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// redirect_uri is required.
	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}

	// scope is required and must contain openid.
	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return newRedirectErrorForRequest(constants.InvalidScope, "invalid scope", req, client)
	}

	if err := validateOAuthCoreSimpleRequest(ctx, req, client); err != nil {
		return err
	}

	return nil
}

func validateOAuthCoreSimpleRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	// If the client has multiple redirect_uri's, it must inform one.
	if req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri must be provided")
	}

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "response_type is required")
	}

	if client.PkceIsRequired && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}

	return validateBaseRequestNonEmptyFields(req.BaseAuthorizationRequest, client)
}

func validateOpenIdCoreRequestWithSupportingSession(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {

	if session.RedirectUri == "" && req.RedirectUri == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateOAuthCoreRequestWithSupportingSession(ctx, req, session, client)
}

func validateOAuthCoreRequestWithSupportingSession(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	if session.RedirectUri == "" && req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri must be provided")
	}

	if session.ResponseType != "" && req.ResponseType != "" && session.ResponseType != req.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	responseType := session.ResponseType
	if responseType == "" {
		responseType = req.ResponseType
	}
	responseMode := session.ResponseMode
	if responseMode == "" {
		responseMode = req.ResponseMode
	}
	if responseType.IsImplict() && responseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if client.PkceIsRequired && session.CodeChallenge == "" && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "PKCE is required")
	}

	if session.IsPushedRequestExpired() {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri is expired")
	}

	return validateBaseRequestNonEmptyFields(req.BaseAuthorizationRequest, client)
}

func validateBaseRequestNonEmptyFields(req models.BaseAuthorizationRequest, client models.Client) error {

	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scopes")
	}

	if req.ResponseType != "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}

	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}

	return nil
}

func validateSimplePushedRequest(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) error {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if req.Request != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request is not allowed during PAR")
	}

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	return validateBaseRequestNonEmptyFields(req.BaseAuthorizationRequest, client)
}

// The PAR RFC (https://datatracker.ietf.org/doc/html/rfc9126#section-3) says:
// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
// In turn, the JAR RFC (https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2.) says:
// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
func validatePushedRequestWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, jarReq models.AuthorizationRequest, client models.Client) error {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	return validateJwtRequest(jarReq, client)
}

func validateJwtRequest(jar models.AuthorizationRequest, client models.Client) error {
	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.Request != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request is not allowed during PAR")
	}

	return validateBaseRequestNonEmptyFields(jar.BaseAuthorizationRequest, client)
}
