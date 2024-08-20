package authorize

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateRequest(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) oidc.Error {
	return validateParams(ctx, req.AuthorizationParameters, client)
}

func validateRequestWithPAR(
	ctx *oidc.Context,
	req Request,
	session *goidc.AuthnSession,
	client *goidc.Client,
) oidc.Error {
	if session.ClientID != req.ClientID {
		return oidc.NewError(oidc.ErrorCodeAccessDenied, "invalid client")
	}

	if ctx.PAR.AllowUnregisteredRedirectURI && req.RedirectURI != "" {
		client.RedirectURIS = append(client.RedirectURIS, req.RedirectURI)
	}

	if err := validateInWithOutParams(ctx, session.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := mergeParams(session.AuthorizationParameters, req.AuthorizationParameters)
	if session.IsExpired() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "the request_uri is expired", mergedParams)
	}

	return nil
}

func validateRequestWithJAR(
	ctx *oidc.Context,
	req Request,
	jar Request,
	client *goidc.Client,
) oidc.Error {
	if jar.ClientID != client.ID {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid client_id")
	}

	if err := validateInWithOutParams(ctx, jar.AuthorizationParameters, req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := mergeParams(jar.AuthorizationParameters, req.AuthorizationParameters)
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
	req PushedRequest,
	jar Request,
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
	req PushedRequest,
	client *goidc.Client,
) oidc.Error {

	if client.AuthnMethod == goidc.ClientAuthnNone {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid client authentication method")
	}

	if req.RequestURI != "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
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
) oidc.Error {

	mergedParams := mergeParams(inParams, outParams)
	if err := validateParams(ctx, mergedParams, client); err != nil {
		return err
	}

	if ctx.OutterAuthParamsRequired {
		if outParams.ResponseType == "" {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams)
		}

		if inParams.ResponseType != "" && inParams.ResponseType != outParams.ResponseType {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams)
		}

		if strutil.ContainsOpenID(inParams.Scopes) && !strutil.ContainsOpenID(outParams.Scopes) {
			return newRedirectionError(oidc.ErrorCodeInvalidScope, "scope openid is required", mergedParams)
		}
	}

	return nil
}

// validateParams validates the parameters of an authorization request.
func validateParams(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	client *goidc.Client,
) oidc.Error {

	if params.RedirectURI == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "redirect_uri is required")
	}

	if err := validateParamsAsOptionals(ctx, params, client); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"response_type is required", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidScope,
			"scope openid is required", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) &&
		!strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"cannot request id_token without the scope openid", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
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
) oidc.Error {

	if params.RedirectURI != "" && !client.IsRedirectURIAllowed(params.RedirectURI) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid redirect_uri")
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
		!slices.Contains(ctx.PKCE.CodeChallengeMethods, params.CodeChallengeMethod) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
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
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"invalid display value", params)
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"cannot inform a request object and request_uri at the same time", params)
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

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(oidc.ErrorCodeInvalidScope, "scope openid is required", params)
	}

	return nil
}

func validatePKCE(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) oidc.Error {
	if ctx.PKCE.IsEnabled && c.AuthnMethod == goidc.ClientAuthnNone && params.CodeChallenge == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"pkce is required for public clients", params)
	}

	if ctx.PKCE.IsRequired && params.CodeChallenge == "" {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"code_challenge is required", params)
	}
	return nil
}

func validateResponseType(
	_ *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) oidc.Error {

	if !c.IsResponseTypeAllowed(params.ResponseType) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"invalid response_type", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) &&
		!c.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return newRedirectionError(oidc.ErrorCodeInvalidGrant,
			"response type code is not allowed", params)
	}

	if params.ResponseType.IsImplicit() &&
		!c.IsGrantTypeAllowed(goidc.GrantImplicit) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"implicit response type is not allowed", params)
	}

	return nil
}

func validateResponseMode(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) oidc.Error {

	if !slices.Contains(ctx.ResponseModes, params.ResponseMode) {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"invalid response_mode", params)
	}

	if params.ResponseMode.IsQuery() && params.ResponseType.IsImplicit() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"invalid response_mode for the chosen response_type", params)
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if c.JARMSignatureAlgorithm != "" && params.ResponseMode.IsPlain() {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"invalid response_mode", params)
	}

	return nil
}

func validateAuthorizationDetails(
	ctx *oidc.Context,
	params goidc.AuthorizationParameters,
	c *goidc.Client,
) oidc.Error {
	if !ctx.AuthorizationDetails.IsEnabled {
		return nil
	}

	for _, authDetail := range params.AuthorizationDetails {
		authDetailType := authDetail.Type()
		if !slices.Contains(ctx.AuthorizationDetails.Types, authDetailType) ||
			!c.IsAuthorizationDetailTypeAllowed(authDetailType) {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest,
				"invalid authorization detail type", params)
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
		if !slices.Contains(ctx.ACRs, goidc.ACR(acr)) {
			return newRedirectionError(oidc.ErrorCodeInvalidRequest,
				"invalid acr value", params)
		}
	}

	return nil
}
