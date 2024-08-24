package authorize

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateRequest(
	ctx *oidc.Context,
	req request,
	client *goidc.Client,
) error {
	return validateParams(ctx, req.AuthorizationParameters, client)
}

func validateRequestWithPAR(
	ctx *oidc.Context,
	req request,
	session *goidc.AuthnSession,
	client *goidc.Client,
) error {
	if session.ClientID != req.ClientID {
		return oidcerr.New(oidcerr.CodeAccessDenied, "invalid client")
	}

	if ctx.PAR.AllowUnregisteredRedirectURI && req.RedirectURI != "" {
		client.RedirectURIS = append(client.RedirectURIS, req.RedirectURI)
	}

	if err := validateInWithOutParams(ctx, session.AuthorizationParameters,
		req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := mergeParams(session.AuthorizationParameters,
		req.AuthorizationParameters)
	if session.IsExpired() {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"the request_uri is expired", mergedParams)
	}

	return nil
}

func validateRequestWithJAR(
	ctx *oidc.Context,
	req request,
	jar request,
	client *goidc.Client,
) error {
	if jar.ClientID != client.ID {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"invalid client_id")
	}

	if err := validateInWithOutParams(ctx, jar.AuthorizationParameters,
		req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := mergeParams(jar.AuthorizationParameters,
		req.AuthorizationParameters)
	if jar.RequestURI != "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"request_uri is not allowed inside the request object", mergedParams)
	}

	if jar.RequestObject != "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"request is not allowed inside the request object", mergedParams)
	}

	return nil
}

func validatePushedRequestWithJAR(
	ctx *oidc.Context,
	req pushedRequest,
	jar request,
	client *goidc.Client,
) error {
	if req.RequestURI != "" {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"request_uri is not allowed during PAR")
	}

	if jar.ClientID != client.ID {
		return oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"invalid client_id")
	}

	if jar.RequestObject != "" {
		return oidcerr.New(oidcerr.CodeInvalidResquestObject,
			"request object is not allowed inside JAR")
	}

	// The PAR RFC says:
	// "...The rules for processing, signing, and encryption of the Request
	// Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC says about the request object:
	// "...It MUST contain all the parameters (including extension parameters)
	// used to process the OAuth 2.0 [RFC6749] authorization request..."
	req.AuthorizationParameters = jar.AuthorizationParameters
	return validatePushedRequest(ctx, req, client)
}

func validatePushedRequest(
	ctx *oidc.Context,
	req pushedRequest,
	client *goidc.Client,
) error {

	if client.AuthnMethod == goidc.ClientAuthnNone {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"invalid client authentication method")
	}

	if req.RequestURI != "" {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"request_uri is not allowed during PAR")
	}

	if ctx.PAR.AllowUnregisteredRedirectURI && req.RedirectURI != "" {
		client.RedirectURIS = append(client.RedirectURIS, req.RedirectURI)
	}

	return validateParamsAsOptionals(ctx, req.AuthorizationParameters, client)
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
	client *goidc.Client,
) error {

	mergedParams := mergeParams(inParams, outParams)
	if err := validateParams(ctx, mergedParams, client); err != nil {
		return err
	}

	if ctx.OutterAuthParamsRequired {
		if outParams.ResponseType == "" {
			return newRedirectionError(oidcerr.CodeInvalidRequest,
				"invalid response_type", mergedParams)
		}

		if inParams.ResponseType != "" && inParams.ResponseType != outParams.ResponseType {
			return newRedirectionError(oidcerr.CodeInvalidRequest,
				"invalid response_type", mergedParams)
		}

		if strutil.ContainsOpenID(inParams.Scopes) && !strutil.ContainsOpenID(outParams.Scopes) {
			return newRedirectionError(oidcerr.CodeInvalidScope,
				"scope openid is required", mergedParams)
		}
	}

	return nil
}

// validateParams validates the parameters of an authorization request.
func validateParams(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) error {

	if params.RedirectURI == "" {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"redirect_uri is required")
	}

	if err := validateParamsAsOptionals(ctx, params, client); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"response_type is required", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidcerr.CodeInvalidScope,
			"scope openid is required", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) &&
		!strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"cannot request id_token without the scope openid", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"nonce is required when response type id_token is requested", params)
	}

	if err := validatePKCE(ctx, params, client); err != nil {
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
	client *goidc.Client,
) error {

	if params.RedirectURI != "" && !client.IsRedirectURIAllowed(params.RedirectURI) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid redirect_uri")
	}

	if params.Scopes != "" {
		if err := validateScopes(ctx, params, client); err != nil {
			return err
		}
	}

	if params.ResponseType != "" {
		if err := validateResponseType(ctx, params, client); err != nil {
			return err
		}
	}

	if params.ResponseMode != "" {
		if err := validateResponseMode(ctx, params, client); err != nil {
			return err
		}
	}

	if params.CodeChallengeMethod != "" &&
		!slices.Contains(ctx.PKCE.ChallengeMethods, params.CodeChallengeMethod) {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"invalid code_challenge_method", params)
	}

	if params.AuthorizationDetails != nil {
		if err := validateAuthorizationDetails(ctx, params, client); err != nil {
			return err
		}
	}

	if params.ACRValues != "" {
		if err := validateACRValues(ctx, params, client); err != nil {
			return err
		}
	}

	if params.Display != "" && !slices.Contains(ctx.DisplayValues, params.Display) {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"invalid display value", params)
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"cannot inform a request object and request_uri at the same time", params)
	}

	return nil
}

func validateScopes(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) error {
	if !client.AreScopesAllowed(ctx.Scopes, params.Scopes) {
		return newRedirectionError(oidcerr.CodeInvalidScope, "invalid scope", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidcerr.CodeInvalidScope, "scope openid is required", params)
	}

	return nil
}

func validatePKCE(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {
	if ctx.PKCE.IsEnabled && c.AuthnMethod == goidc.ClientAuthnNone && params.CodeChallenge == "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"pkce is required for public clients", params)
	}

	if ctx.PKCE.IsRequired && params.CodeChallenge == "" {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"code_challenge is required", params)
	}
	return nil
}

func validateResponseType(
	_ *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {

	if !c.IsResponseTypeAllowed(params.ResponseType) {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"invalid response_type", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) &&
		!c.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return newRedirectionError(oidcerr.CodeInvalidGrant,
			"response type code is not allowed", params)
	}

	if params.ResponseType.IsImplicit() &&
		!c.IsGrantTypeAllowed(goidc.GrantImplicit) {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
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
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"invalid response_mode", params)
	}

	if params.ResponseMode.IsQuery() && params.ResponseType.IsImplicit() {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"invalid response_mode for the chosen response_type", params)
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if c.JARMSignatureAlgorithm != "" && params.ResponseMode.IsPlain() {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"invalid response_mode", params)
	}

	return nil
}

func validateAuthorizationDetails(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) error {
	if !ctx.AuthorizationDetails.IsEnabled {
		return nil
	}

	for _, authDetail := range params.AuthorizationDetails {
		authDetailType := authDetail.Type()
		if !slices.Contains(ctx.AuthorizationDetails.Types, authDetailType) ||
			!c.IsAuthorizationDetailTypeAllowed(authDetailType) {
			return newRedirectionError(oidcerr.CodeInvalidRequest,
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
			return newRedirectionError(oidcerr.CodeInvalidRequest,
				"invalid acr value", params)
		}
	}

	return nil
}
