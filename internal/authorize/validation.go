package authorize

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateRequest(
	ctx *oidc.Context,
	req request,
	c *goidc.Client,
) error {
	return validateParams(ctx, req.AuthorizationParameters, c)
}

func validateRequestWithPAR(
	ctx *oidc.Context,
	req request,
	session *goidc.AuthnSession,
	c *goidc.Client,
) error {
	if session.ClientID != req.ClientID {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid client")
	}

	if ctx.PARAllowUnregisteredRedirectURI && req.RedirectURI != "" {
		c.RedirectURIs = append(c.RedirectURIs, req.RedirectURI)
	}

	if err := validateInWithOutParams(ctx, session.AuthorizationParameters,
		req.AuthorizationParameters, c); err != nil {
		return err
	}

	mergedParams := mergeParams(session.AuthorizationParameters,
		req.AuthorizationParameters)
	if session.IsExpired() {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"the request_uri is expired", mergedParams)
	}

	return nil
}

func validateRequestWithJAR(
	ctx *oidc.Context,
	req request,
	jar request,
	c *goidc.Client,
) error {
	if jar.ClientID != c.ID {
		return goidc.NewError(goidc.ErrorCodeInvalidClient,
			"invalid client_id")
	}

	if err := validateInWithOutParams(ctx, jar.AuthorizationParameters,
		req.AuthorizationParameters, c); err != nil {
		return err
	}

	mergedParams := mergeParams(jar.AuthorizationParameters,
		req.AuthorizationParameters)
	if jar.RequestURI != "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"request_uri is not allowed inside the request object", mergedParams)
	}

	if jar.RequestObject != "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"request is not allowed inside the request object", mergedParams)
	}

	return nil
}

func validatePushedRequestWithJAR(
	ctx *oidc.Context,
	req pushedRequest,
	jar request,
	c *goidc.Client,
) error {
	if req.RequestURI != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"request_uri is not allowed during PAR")
	}

	if jar.ClientID != c.ID {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"invalid client_id")
	}

	if jar.RequestObject != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject,
			"request object is not allowed inside JAR")
	}

	// The PAR RFC says:
	// "...The rules for processing, signing, and encryption of the Request
	// Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC says about the request object:
	// "...It MUST contain all the parameters (including extension parameters)
	// used to process the OAuth 2.0 [RFC6749] authorization request..."
	req.AuthorizationParameters = jar.AuthorizationParameters
	return validatePushedRequest(ctx, req, c)
}

func validatePushedRequest(
	ctx *oidc.Context,
	req pushedRequest,
	c *goidc.Client,
) error {

	if c.AuthnMethod == goidc.ClientAuthnNone {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"invalid client authentication method")
	}

	if req.RequestURI != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"request_uri is not allowed during PAR")
	}

	if ctx.PARAllowUnregisteredRedirectURI && req.RedirectURI != "" {
		c.RedirectURIs = append(c.RedirectURIs, req.RedirectURI)
	}

	return validateParamsAsOptionals(ctx, req.AuthorizationParameters, c)
}

// -------------------------------------------------- Helper Functions -------------------------------------------------- //

// validateInWithOutParams validates the combination of inner parameters, those
// sent during PAR or inside a request object during JAR, and outter parameters,
// those sent during the authorization request as query parameters.
// The inner parameters take priority over the outter ones.
func validateInWithOutParams(
	ctx *oidc.Context,
	inParams goidc.AuthorizationParameters,
	outParams goidc.AuthorizationParameters,
	c *goidc.Client,
) error {

	mergedParams := mergeParams(inParams, outParams)
	if err := validateParams(ctx, mergedParams, c); err != nil {
		return err
	}

	if ctx.OutterAuthParamsRequired {
		if outParams.ResponseType == "" {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"invalid response_type", mergedParams)
		}

		if inParams.ResponseType != "" && inParams.ResponseType != outParams.ResponseType {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"invalid response_type", mergedParams)
		}

		if strutil.ContainsOpenID(inParams.Scopes) && !strutil.ContainsOpenID(outParams.Scopes) {
			return newRedirectionError(goidc.ErrorCodeInvalidScope,
				"scope openid is required", mergedParams)
		}
	}

	return nil
}

// validateParams validates the parameters of an authorization request.
func validateParams(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {

	if params.RedirectURI == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRedirectURI,
			"redirect_uri is required")
	}

	if err := validateParamsAsOptionals(ctx, params, c); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"response_type is required", params)
	}

	if ctx.ResourceIndicatorsIsRequired && params.Resources == nil {
		return newRedirectionError(goidc.ErrorCodeInvalidTarget,
			"the resources parameter is required", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidScope,
			"scope openid is required", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) &&
		!strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"cannot request id_token without the scope openid", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"nonce is required when response type id_token is requested", params)
	}

	if err := validatePKCE(ctx, params, c); err != nil {
		return err
	}

	return nil
}

// validateParamsAsOptionals validates the parameters of an authorization
// request considering them as optional.
// This validation is meant to be shared during PAR and authorization requests.
func validateParamsAsOptionals(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {

	if params.RedirectURI != "" && !isRedirectURIAllowed(c, params.RedirectURI) {
		return goidc.NewError(goidc.ErrorCodeInvalidRedirectURI,
			"invalid redirect_uri")
	}

	if params.Scopes != "" {
		if err := validateScopes(ctx, params, c); err != nil {
			return err
		}
	}

	if params.ResponseType != "" {
		if err := validateResponseType(ctx, params, c); err != nil {
			return err
		}
	}

	if params.ResponseMode != "" {
		if err := validateResponseMode(ctx, params, c); err != nil {
			return err
		}
	}

	if params.CodeChallengeMethod != "" &&
		!slices.Contains(ctx.PKCEChallengeMethods, params.CodeChallengeMethod) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"invalid code_challenge_method", params)
	}

	if params.AuthorizationDetails != nil {
		if err := validateAuthorizationDetails(ctx, params, c); err != nil {
			return err
		}
	}

	if params.ACRValues != "" {
		if err := validateACRValues(ctx, params, c); err != nil {
			return err
		}
	}

	if params.Resources != nil {
		if err := validateResources(ctx, params, c); err != nil {
			return err
		}
	}

	if params.Display != "" && !slices.Contains(ctx.DisplayValues, params.Display) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"invalid display value", params)
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"cannot inform a request object and request_uri at the same time", params)
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {
	if !clientutil.AreScopesAllowed(c, ctx.Scopes, params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidScope, "scope openid is required", params)
	}

	return nil
}

func validatePKCE(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {
	if ctx.PKCEIsEnabled && c.AuthnMethod == goidc.ClientAuthnNone && params.CodeChallenge == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"pkce is required for public clients", params)
	}

	if ctx.PKCEIsRequired && params.CodeChallenge == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"code_challenge is required", params)
	}
	return nil
}

func validateResponseType(
	_ *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {

	if !slices.Contains(c.ResponseTypes, params.ResponseType) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"invalid response_type", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) &&
		!slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return newRedirectionError(goidc.ErrorCodeInvalidGrant,
			"response type code is not allowed", params)
	}

	if params.ResponseType.IsImplicit() &&
		!slices.Contains(c.GrantTypes, goidc.GrantImplicit) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"implicit response type is not allowed", params)
	}

	return nil
}

func validateResponseMode(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {

	if !slices.Contains(ctx.ResponseModes, params.ResponseMode) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"invalid response_mode", params)
	}

	if params.ResponseMode.IsQuery() && params.ResponseType.IsImplicit() {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"invalid response_mode for the chosen response_type", params)
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if c.JARMSigAlg != "" && params.ResponseMode.IsPlain() {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"invalid response_mode", params)
	}

	return nil
}

func validateAuthorizationDetails(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {
	if !ctx.AuthDetailsIsEnabled {
		return nil
	}

	for _, authDetail := range params.AuthorizationDetails {
		authDetailType := authDetail.Type()
		if !slices.Contains(ctx.AuthDetailTypes, authDetailType) ||
			!isAuthDetailTypeAllowed(c, authDetailType) {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"invalid authorization detail type", params)
		}
	}

	return nil
}

func validateACRValues(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	_ *goidc.Client,
) error {

	for _, acr := range strutil.SplitWithSpaces(params.ACRValues) {
		if !slices.Contains(ctx.ACRs, goidc.ACR(acr)) {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"invalid acr value", params)
		}
	}

	return nil
}

func validateResources(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	_ *goidc.Client,
) error {

	if !ctx.ResourceIndicatorsIsEnabled {
		return nil
	}

	for _, resource := range params.Resources {
		if !slices.Contains(ctx.Resources, resource) {
			return newRedirectionError(goidc.ErrorCodeInvalidTarget,
				"the resource "+resource+" is invalid", params)
		}
	}

	return nil
}

func isRedirectURIAllowed(c *goidc.Client, redirectURI string) bool {
	for _, ru := range c.RedirectURIs {
		if redirectURI == ru {
			return true
		}
	}
	return false
}

func isAuthDetailTypeAllowed(c *goidc.Client, authDetailType string) bool {
	// If the client didn't announce the authorization types it will use,
	// consider any value valid.
	if c.AuthDetailTypes == nil {
		return true
	}

	return slices.Contains(c.AuthDetailTypes, authDetailType)
}
