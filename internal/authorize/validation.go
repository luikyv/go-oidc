package authorize

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateRequest(
	ctx *oidc.Context,
	req authorizationRequest,
	client *goidc.Client,
) goidc.OAuthError {
	return validateParamsAuthorize(ctx, req.AuthorizationParameters, client)
}

func validateRequestWithPAR(
	ctx *oidc.Context,
	req authorizationRequest,
	session *goidc.AuthnSession,
	client *goidc.Client,
) goidc.OAuthError {
	if session.ClientID != req.ClientID {
		return goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, "invalid client")
	}

	if err := validateInWithOutParams(ctx, session.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := session.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if session.IsExpired() {
		return mergedParams.NewRedirectError(goidc.ErrorCodeInvalidRequest, "the request_uri is expired")
	}

	return nil
}

func validateRequestWithJAR(
	ctx *oidc.Context,
	req authorizationRequest,
	jar authorizationRequest,
	client *goidc.Client,
) goidc.OAuthError {
	if jar.ClientID != client.ID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	if err := validateInWithOutParams(ctx, jar.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if jar.RequestURI != "" {
		return mergedParams.NewRedirectError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed inside the request object")
	}

	if jar.RequestObject != "" {
		return mergedParams.NewRedirectError(goidc.ErrorCodeInvalidRequest, "request is not allowed inside the request object")
	}

	return nil
}

func validatePushedRequestWithJAR(
	ctx *oidc.Context,
	req pushedAuthorizationRequest,
	jar authorizationRequest,
	client *goidc.Client,
) goidc.OAuthError {
	if req.RequestURI != "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientID != client.ID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "invalid client_id")
	}

	if jar.RequestObject != "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidResquestObject, "request object is not allowed inside JAR")
	}

	// The PAR RFC says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	req.AuthorizationParameters = jar.AuthorizationParameters
	return validatePushedRequest(ctx, req, client)
}

func validatePushedRequest(
	ctx *oidc.Context,
	req pushedAuthorizationRequest,
	client *goidc.Client,
) goidc.OAuthError {

	if client.AuthnMethod == goidc.ClientAuthnNone {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid client authentication method")
	}

	if req.RequestURI != "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	if ctx.Profile == goidc.ProfileFAPI2 && req.RedirectURI != "" {
		client.AllowRedirectURI(req.RedirectURI)
	}

	return validateParams(ctx, req.AuthorizationParameters, client)
}

// -------------------------------------------------- Helper Functions -------------------------------------------------- //

func validateInWithOutParams(
	ctx *oidc.Context,
	insideParams goidc.AuthorizationParameters,
	outsideParams goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {

	if ctx.Profile == goidc.ProfileFAPI2 && insideParams.RedirectURI != "" {
		client.AllowRedirectURI(insideParams.RedirectURI)
	}

	mergedParams := insideParams.Merge(outsideParams)
	if err := validateParamsAuthorize(ctx, mergedParams, client); err != nil {
		return err
	}

	// When the openid scope is not requested, the authorization request becomes a standard OAuth one,
	// so there's no need to validate these rules below.
	if ctx.Profile == goidc.ProfileOpenID && goidc.ScopesContainsOpenID(mergedParams.Scopes) {
		if outsideParams.ResponseType == "" {
			return mergedParams.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid response_type")
		}

		if insideParams.ResponseType != "" && insideParams.ResponseType != outsideParams.ResponseType {
			return mergedParams.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid response_type")
		}

		if !goidc.ScopesContainsOpenID(outsideParams.Scopes) {
			return mergedParams.NewRedirectError(goidc.ErrorCodeInvalidScope, "scope openid is required")
		}
	}

	return nil
}

func validateParamsAuthorize(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {

	if params.RedirectURI == "" {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "redirect_uri is required")
	}

	if err := validateParams(ctx, params, client); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "response_type is required")
	}

	if ctx.OpenIDScopeIsRequired && !goidc.ScopesContainsOpenID(params.Scopes) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidScope, "scope openid is required")
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && !goidc.ScopesContainsOpenID(params.Scopes) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "cannot request id_token without the scope openid")
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "nonce is required when response type id_token is requested")
	}

	if err := validatePKCE(ctx, params, client); err != nil {
		return err
	}

	return nil
}

func validateParams(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {

	if !client.IsRedirectURIAllowed(params.RedirectURI) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid redirect_uri")
	}

	if err := validateScopes(ctx, params, client); err != nil {
		return err
	}

	if err := validateResponseType(ctx, params, client); err != nil {
		return err
	}

	if err := validateResponseMode(ctx, params, client); err != nil {
		return err
	}

	if params.CodeChallengeMethod != "" && !slices.Contains(ctx.CodeChallengeMethods, params.CodeChallengeMethod) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid code_challenge_method")
	}

	if err := validateAuthorizationDetails(ctx, params, client); err != nil {
		return err
	}

	if err := validateACRValues(ctx, params, client); err != nil {
		return err
	}

	if params.Display != "" && !slices.Contains(ctx.DisplayValues, params.Display) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid display value")
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "cannot inform a request object and request_uri at the same time")
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if !client.AreScopesAllowed(ctx, ctx.Scopes, params.Scopes) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if params.Scopes != "" && ctx.OpenIDScopeIsRequired && !goidc.ScopesContainsOpenID(params.Scopes) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidScope, "scope openid is required")
	}

	return nil
}

func validatePKCE(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if ctx.PkceIsEnabled && client.AuthnMethod == goidc.ClientAuthnNone && params.CodeChallenge == "" {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "pkce is required for public clients")
	}

	if ctx.PkceIsRequired && params.CodeChallenge == "" {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "code_challenge is required")
	}
	return nil
}

func validateResponseType(
	_ *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {

	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid response_type")
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) && !client.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidGrant, "response type code is not allowed")
	}

	if params.ResponseType.IsImplicit() && !client.IsGrantTypeAllowed(goidc.GrantImplicit) {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "implicit response type is not allowed")
	}

	return nil
}

func validateResponseMode(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if !ctx.JARMIsEnabled && params.ResponseMode.IsJARM() {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid response_mode")
	}

	if params.ResponseType.IsImplicit() && params.ResponseMode.IsQuery() {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid response_mode for the chosen response_type")
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if client.JARMSignatureAlgorithm != "" && params.ResponseMode.IsPlain() {
		return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid response_mode")
	}

	return nil
}

func validateAuthorizationDetails(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) goidc.OAuthError {
	if !ctx.AuthorizationDetailsParameterIsEnabled || params.AuthorizationDetails == nil {
		return nil
	}

	for _, authDetail := range params.AuthorizationDetails {
		authDetailType := authDetail.Type()
		if !slices.Contains(ctx.AuthorizationDetailTypes, authDetailType) || !client.IsAuthorizationDetailTypeAllowed(authDetailType) {
			return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid authorization detail type")
		}
	}

	return nil
}

func validateACRValues(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	_ *goidc.Client,
) goidc.OAuthError {

	for _, acr := range goidc.SplitStringWithSpaces(params.ACRValues) {
		if !slices.Contains(ctx.AuthenticationContextReferences, goidc.ACR(acr)) {
			return params.NewRedirectError(goidc.ErrorCodeInvalidRequest, "invalid acr value")
		}
	}

	return nil
}
