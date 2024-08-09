package authorize

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateRequest(
	ctx *oidc.Context,
	req authorizationRequest,
	client *goidc.Client,
) oidc.Error {
	return validateParamsAuthorize(ctx, req.AuthorizationParameters, client)
}

func validateRequestWithPAR(
	ctx *oidc.Context,
	req authorizationRequest,
	session *goidc.AuthnSession,
	client *goidc.Client,
) oidc.Error {
	if session.ClientID != req.ClientID {
		return oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid client")
	}

	if err := validateInWithOutParams(ctx, session.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := session.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if session.IsExpired() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "the request_uri is expired", mergedParams)
	}

	return nil
}

func validateRequestWithJAR(
	ctx *oidc.Context,
	req authorizationRequest,
	jar authorizationRequest,
	client *goidc.Client,
) oidc.Error {
	if jar.ClientID != client.ID {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	if err := validateInWithOutParams(ctx, jar.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	if jar.RequestURI != "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "request_uri is not allowed inside the request object", mergedParams)
	}

	if jar.RequestObject != "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "request is not allowed inside the request object", mergedParams)
	}

	return nil
}

func validatePushedRequestWithJAR(
	ctx *oidc.Context,
	req pushedAuthorizationRequest,
	jar authorizationRequest,
	client *goidc.Client,
) oidc.Error {
	if req.RequestURI != "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientID != client.ID {
		return oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "invalid client_id")
	}

	if jar.RequestObject != "" {
		return oidc.NewError(oidc.ErrorCodeInvalidResquestObject, "request object is not allowed inside JAR")
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
) oidc.Error {

	if client.AuthnMethod == goidc.ClientAuthnNone {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid client authentication method")
	}

	if req.RequestURI != "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
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
) oidc.Error {

	if ctx.Profile == goidc.ProfileFAPI2 && insideParams.RedirectURI != "" {
		client.AllowRedirectURI(insideParams.RedirectURI)
	}

	mergedParams := insideParams.Merge(outsideParams)
	if err := validateParamsAuthorize(ctx, mergedParams, client); err != nil {
		return err
	}

	// When the openid scope is not requested, the authorization request becomes a standard OAuth one,
	// so there's no need to validate these rules below.
	if ctx.Profile == goidc.ProfileOpenID && strutil.ContainsOpenID(mergedParams.Scopes) {
		if outsideParams.ResponseType == "" {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams)
		}

		if insideParams.ResponseType != "" && insideParams.ResponseType != outsideParams.ResponseType {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams)
		}

		if !strutil.ContainsOpenID(outsideParams.Scopes) {
			return newRedirectionError(oidc.ErrorCodeInvalidScope, "scope openid is required", mergedParams)
		}
	}

	return nil
}

func validateParamsAuthorize(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {

	if params.RedirectURI == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "redirect_uri is required")
	}

	if err := validateParams(ctx, params, client); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "response_type is required", params)
	}

	if ctx.OpenIDScopeIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidScope, "scope openid is required", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "cannot request id_token without the scope openid", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "nonce is required when response type id_token is requested", params)
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
) oidc.Error {

	if !client.IsRedirectURIAllowed(params.RedirectURI) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid redirect_uri")
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
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid code_challenge_method", params)
	}

	if err := validateAuthorizationDetails(ctx, params, client); err != nil {
		return err
	}

	if err := validateACRValues(ctx, params, client); err != nil {
		return err
	}

	if params.Display != "" && !slices.Contains(ctx.DisplayValues, params.Display) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid display value", params)
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "cannot inform a request object and request_uri at the same time", params)
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {
	if !client.AreScopesAllowed(ctx.Scopes, params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidScope, "invalid scope", params)
	}

	if params.Scopes != "" && ctx.OpenIDScopeIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidScope, "scope openid is required", params)
	}

	return nil
}

func validatePKCE(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {
	if ctx.PkceIsEnabled && client.AuthnMethod == goidc.ClientAuthnNone && params.CodeChallenge == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "pkce is required for public clients", params)
	}

	if ctx.PkceIsRequired && params.CodeChallenge == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "code_challenge is required", params)
	}
	return nil
}

func validateResponseType(
	_ *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {

	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_type", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) && !client.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return newRedirectionError(oidc.ErrorCodeInvalidGrant, "response type code is not allowed", params)
	}

	if params.ResponseType.IsImplicit() && !client.IsGrantTypeAllowed(goidc.GrantImplicit) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "implicit response type is not allowed", params)
	}

	return nil
}

func validateResponseMode(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {
	if !ctx.JARMIsEnabled && params.ResponseMode.IsJARM() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_mode", params)
	}

	if params.ResponseType.IsImplicit() && params.ResponseMode.IsQuery() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_mode for the chosen response_type", params)
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if client.JARMSignatureAlgorithm != "" && params.ResponseMode.IsPlain() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_mode", params)
	}

	return nil
}

func validateAuthorizationDetails(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {
	if !ctx.AuthorizationDetailsParameterIsEnabled || params.AuthorizationDetails == nil {
		return nil
	}

	for _, authDetail := range params.AuthorizationDetails {
		authDetailType := authDetail.Type()
		if !slices.Contains(ctx.AuthorizationDetailTypes, authDetailType) || !client.IsAuthorizationDetailTypeAllowed(authDetailType) {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid authorization detail type", params)
		}
	}

	return nil
}

func validateACRValues(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	_ *goidc.Client,
) oidc.Error {

	for _, acr := range strutil.SplitWithSpaces(params.ACRValues) {
		if !slices.Contains(ctx.AuthenticationContextReferences, goidc.ACR(acr)) {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid acr value", params)
		}
	}

	return nil
}
