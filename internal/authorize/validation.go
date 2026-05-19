package authorize

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/vc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// validateRequest validates the parameters sent in an authorization request.
func validateRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	return validateParams(ctx, req.AuthorizationParameters, c)
}

// validateRequestWithPAR validates the parameters in an authorization request
// that includes a Pushed Authorization Request (PAR).
func validateRequestWithPAR(ctx oidc.Context, req request, as *goidc.AuthnSession, c *goidc.Client) error {
	if as.ClientID != req.ClientID {
		return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("the request_uri belongs to a different client"))
	}

	if as.Status != goidc.StatusPending {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the request_uri has already been used"))
	}

	if timeutil.TimestampNow() > as.ExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the request_uri has expired"))
	}

	if ctx.PARUnregisteredRedirectURIIsEnabled && as.RedirectURI != "" {
		c = clientWithRedirectURI(c, as.RedirectURI)
	}

	return validateInWithOutParams(ctx, as.AuthorizationParameters, req.AuthorizationParameters, c)
}

// validateRequestWithJAR validates the parameters in an authorization request
// that includes a JWT Authorization Request (JAR).
func validateRequestWithJAR(ctx oidc.Context, req request, jar request, client *goidc.Client) error {
	if jar.ClientID != client.ID {
		return goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	if ctx.Profile.IsFAPI() {
		if err := validateParams(ctx, jar.AuthorizationParameters, client); err != nil {
			return err
		}
	}

	if err := validateInWithOutParams(ctx, jar.AuthorizationParameters,
		req.AuthorizationParameters, client); err != nil {
		return err
	}

	mergedParams := mergeParams(jar.AuthorizationParameters, req.AuthorizationParameters)
	if jar.RequestURI != "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", mergedParams,
			errors.New("request_uri is not allowed inside the request object"))
	}

	if jar.RequestObject != "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", mergedParams,
			errors.New("request is not allowed inside the request object"))
	}

	return nil
}

// validatePushedRequestWithJAR validates the parameters sent in a Pushed
// Authorization Request (PAR) that also includes a JWT Authorization Request (JAR).
// For FAPI, all required authorization request parameters must be present
// within the JAR.
// For OIDC, the JAR parameters are optional, as additional parameters can be
// supplied later at the authorization endpoint, where they will be merged.
// For both cases, any parameters outside the JAR are ignored.
func validatePushedRequestWithJAR(ctx oidc.Context, req request, jar request, c *goidc.Client) error {
	if req.RequestURI != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("request_uri is not allowed during PAR"))
	}

	if jar.ClientID != c.ID {
		return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object", errors.New("client_id in the request object does not match the authenticated client"))
	}

	if jar.RequestObject != "" || jar.RequestURI != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidResquestObject, "invalid request object", errors.New("nested request objects and request_uri are not allowed inside JAR"))
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

func validateSimplePushedRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	return validatePushedRequest(ctx, req, c)
}

// validatePushedRequest validates the parameters sent in a Pushed Authorization
// Request (PAR).
// In the context of FAPI, all required parameters for the authorization
// request must be included during PAR.
// For OpenID Connect, however, the parameters sent during the PAR are considered
// optional, as any missing parameters can be provided later at the authorization
// endpoint, where they will be merged.
func validatePushedRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	if req.RequestURI != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("request_uri is not allowed during PAR"))
	}

	if ctx.PARUnregisteredRedirectURIIsEnabled && req.RedirectURI != "" {
		c = clientWithRedirectURI(c, req.RedirectURI)
	}

	if ctx.Profile.IsFAPI() {
		if err := validateParams(ctx, req.AuthorizationParameters, c); err != nil {
			return err
		}
	} else {
		if err := validateParamsAsOptionals(ctx, req.AuthorizationParameters, c); err != nil {
			return err
		}
	}

	if ctx.Profile == goidc.ProfileFAPI1 {
		if c.TokenAuthnMethod == goidc.AuthnMethodNone {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("public clients are not allowed to use pushed authorization requests"))
		}

		if ctx.PKCEIsEnabled && req.CodeChallenge == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("code_challenge is required for PAR in this profile"))
		}
	}

	if err := validateCodeBindingDPoP(ctx, req.AuthorizationParameters); err != nil {
		return err
	}

	return nil
}

// -------------------------------------------------- Helper Functions -------------------------------------------------- //

// validateInWithOutParams validates the combination of inner parameters, those
// sent during PAR or inside a request object during JAR, and outter parameters,
// those sent during the authorization request as query parameters.
// The inner parameters take priority over the outter ones.
func validateInWithOutParams(ctx oidc.Context, inParams goidc.AuthorizationParameters, outParams goidc.AuthorizationParameters, c *goidc.Client) error {

	// Always validate the redirect URI first before other validations.
	// If the redirect URI is invalid, we cannot safely redirect the error, even
	// if the redirect URI is not used in the flow.
	if err := validateRedirectURIAsOptional(ctx, outParams, c); err != nil {
		return err
	}

	mergedParams := mergeParams(inParams, outParams)
	if err := validateParams(ctx, mergedParams, c); err != nil {
		return err
	}

	// Make sure all the outter parameters parameters are valid even if they are
	// not used.
	if err := validateParamsAsOptionals(ctx, outParams, c); err != nil {
		return err
	}

	// For OIDC, the required OAuth parameters must be sent as query parameters
	// even if they are among the inner parameters.
	if ctx.Profile == goidc.ProfileOpenID && strutil.ContainsOpenID(mergedParams.Scopes) {
		if outParams.ResponseType == "" {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams,
				errors.New("response_type must be repeated outside the request object or PAR payload for OpenID requests"))
		}

		if inParams.ResponseType != "" && inParams.ResponseType != outParams.ResponseType {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams,
				errors.New("response_type inside and outside the request object or PAR payload must match"))
		}

		if strutil.ContainsOpenID(inParams.Scopes) && !strutil.ContainsOpenID(outParams.Scopes) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", mergedParams,
				errors.New("scope openid must be repeated outside the request object or PAR payload for OpenID requests"))
		}
	}

	return nil
}

// validateParams validates the parameters of an authorization request.
func validateParams(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.RedirectURI == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("redirect_uri is required"))
	}

	if err := validateParamsAsOptionals(ctx, params, c); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("response_type is required"))
	}

	if ctx.ResourceIndicatorsIsRequired && params.Resources == nil {
		return wrapRedirectionError(goidc.ErrorCodeInvalidTarget, "invalid target", params,
			errors.New("the resource parameter is required"))
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "scope openid is required", params,
			errors.New("scope openid is required"))
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && !strutil.ContainsOpenID(params.Scopes) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("id_token requires the openid scope"))
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("nonce is required when response_type includes id_token"))
	}

	if err := validatePKCE(ctx, params, c); err != nil {
		return err
	}

	if ctx.Profile == goidc.ProfileFAPI1 {
		if !slices.Contains([]goidc.ResponseType{
			goidc.ResponseTypeCode,
			goidc.ResponseTypeCodeAndIDToken,
		}, params.ResponseType) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params,
				errors.New("response_type is not supported by this FAPI profile"))
		}

		if params.ResponseType == goidc.ResponseTypeCode && params.ResponseMode != goidc.ResponseModeJWT {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params,
				errors.New("response_mode jwt is required when response_type is code"))
		}

		if strutil.ContainsOpenID(params.Scopes) && params.Nonce == "" {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
				errors.New("nonce is required for OpenID requests in this FAPI profile"))
		}
	}

	if ctx.Profile == goidc.ProfileFAPI2 {
		if params.ResponseType != goidc.ResponseTypeCode {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params,
				errors.New("response_type code is required by this FAPI profile"))
		}
	}

	return nil
}

// validateParamsAsOptionals validates the parameters of an authorization
// request considering them as optional.
// This validation is meant to be shared during PAR and authorization requests.
// The redirect URI is ALWAYS validated before any other validations, since
// it determines when or not to redirect errors.
func validateParamsAsOptionals(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if err := validateRedirectURIAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateRequestURIAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateScopesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResponseTypeAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResponseModeAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateCodeChallengeMethodAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateAuthDetailsAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateACRValuesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResourcesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateVerifiableCredentialsAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateIDTokenHintAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateDisplayValueAsOptional(ctx, params, c); err != nil {
		return err
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("request and request_uri cannot be used at the same time"))
	}

	return nil
}

func validateRedirectURIAsOptional(_ oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.RedirectURI == "" {
		return nil
	}

	parsedURI, err := url.Parse(params.RedirectURI)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid redirect_uri", err)
	}

	// RFC 8252: Native apps can use loopback interface on any port.
	if host := parsedURI.Hostname(); c.ApplicationType == goidc.ApplicationTypeNative {
		if host == "::1" {
			host = "[::1]"
		}
		parsedURI.Host = host
	}

	if !slices.Contains(c.RedirectURIs, parsedURI.String()) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid redirect_uri", errors.New("redirect_uri is not registered for the client"))
	}

	return nil
}

func validateRequestURIAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.RequestURI == "" || strings.HasPrefix(params.RequestURI, parRequestURIPrefix) {
		return nil
	}

	if !ctx.JARByReferenceIsEnabled {
		return goidc.WrapError(goidc.ErrorCodeRequestURINotSupported, "request_uri_not_supported", errors.New("request_uri is not supported"))
	}

	if ctx.JARRequestURIRegistrationIsRequired && !slices.Contains(c.RequestURIs, params.RequestURI) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri", errors.New("request_uri is not registered for the client"))
	}

	if parsedURI, err := url.Parse(params.RequestURI); err != nil || parsedURI.Scheme != "https" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri", errors.New("request_uri must be a valid https URL"))
	}

	return nil
}

func validateCodeChallengeMethodAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.CodeChallengeMethod == "" {
		return nil
	}

	if !slices.Contains(ctx.PKCEChallengeMethods, params.CodeChallengeMethod) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("code_challenge_method is not supported"))
	}

	return nil
}

func validateDisplayValueAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.Display == "" {
		return nil
	}

	if !slices.Contains(ctx.DisplayValues, params.Display) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("display is not supported"))
	}

	return nil
}

func validateScopesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.Scopes == "" {
		return nil
	}

	for _, s := range strings.Fields(params.Scopes) {
		scope, ok := ctx.Scope(s)
		if !ok {
			return wrapRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", params, fmt.Errorf("scope %s does not match any available scope", s))
		}

		if !strings.Contains(c.ScopeIDs, scope.ID) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", params, fmt.Errorf("scope %s is not allowed for the client", s))
		}
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "scope openid is required", params,
			errors.New("scope openid is required"))
	}

	return nil
}

func validatePKCE(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if ctx.PKCEIsEnabled && c.IsPublic() && params.CodeChallenge == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("pkce is required for public clients"))
	}

	if ctx.PKCEIsRequired && params.CodeChallenge == "" {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
			errors.New("code_challenge is required"))
	}
	return nil
}

func validateResponseTypeAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.ResponseType == "" {
		return nil
	}

	if !slices.Contains(ctx.ResponseTypes, params.ResponseType) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params)
	}

	if !slices.Contains(c.ResponseTypes, params.ResponseType) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeCode) && !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidGrant, "invalid grant", params,
			errors.New("response_type includes code but the client is not allowed to use the authorization_code grant"))
	}

	if params.ResponseType.IsImplicit() && !slices.Contains(c.GrantTypes, goidc.GrantImplicit) {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", params,
			errors.New("the implicit response types are not allowed for the client"))
	}

	return nil
}

func validateResponseModeAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.ResponseMode == "" {
		return nil
	}

	if !slices.Contains(ctx.ResponseModes, params.ResponseMode) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params)
	}

	if params.ResponseMode.IsQuery() && params.ResponseType.IsImplicit() {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params,
			errors.New("response_mode query is not allowed with implicit or hybrid response types"))
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if c.JARMSigAlg != "" && params.ResponseMode.IsPlain() {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params,
			errors.New("the client requires a JWT-secured authorization response mode"))
	}

	return nil
}

func validateAuthDetailsAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if !ctx.RARIsEnabled || params.AuthDetails == nil {
		return nil
	}

	for _, detail := range params.AuthDetails {
		typ := detail.Type()
		if typ == "" {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params,
				errors.New("authorization detail type is required"))
		}

		if !slices.Contains(ctx.RARDetailTypes, typ) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params,
				fmt.Errorf("authorization detail type %q is not supported", typ))
		}

		if c.AuthDetailTypes != nil && !slices.Contains(c.AuthDetailTypes, typ) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params,
				fmt.Errorf("authorization detail type %q is not allowed for the client", typ))
		}

		if err := ctx.RARValidateDetail(detail); err != nil {
			return wrapRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", params, err)
		}
	}

	return nil
}

func validateACRValuesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.ACRValues == "" {
		return nil
	}

	for acr := range strings.FieldsSeq(params.ACRValues) {
		if !slices.Contains(ctx.ACRs, goidc.ACR(acr)) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid request", params,
				fmt.Errorf("acr value %q is not supported", acr))
		}
	}

	return nil
}

func validateResourcesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if !ctx.ResourceIndicatorsIsEnabled || params.Resources == nil {
		return nil
	}

	for _, resource := range params.Resources {
		if !slices.Contains(ctx.Resources, resource) {
			return wrapRedirectionError(goidc.ErrorCodeInvalidTarget, "invalid target", params,
				fmt.Errorf("resource %q is not configured by the server", resource))
		}
	}

	return nil
}

func validateIDTokenHintAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.IDTokenHint == "" {
		return nil
	}

	parsedIDToken, err := jwt.ParseSigned(params.IDTokenHint, ctx.IDTokenSigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint", err)
	}

	if len(parsedIDToken.Headers) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint",
			errors.New("the id_token_hint must contain exactly one JOSE header"))
	}

	publicKey, err := ctx.PublicJWK(parsedIDToken.Headers[0].KeyID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint", err)
	}

	var claims jwt.Claims
	if err := parsedIDToken.Claims(publicKey.Key, &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      ctx.Issuer(),
		AnyAudience: []string{c.ID},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id_token_hint", err)
	}

	return nil
}

func validateCodeBindingDPoP(ctx oidc.Context, params goidc.AuthorizationParameters) error {
	if !ctx.DPoPIsEnabled {
		return nil
	}

	dpopJWT, ok := dpop.JWT(ctx)
	// If the DPoP header was not informed, there's nothing to validate.
	if !ok {
		return nil
	}

	return dpop.ValidateJWT(ctx, dpopJWT, dpop.ValidationOptions{
		// "dpop_jkt" is optional, but it must match the DPoP JWT if present.
		JWKThumbprint: params.DPoPJKT,
	})
}

func validateVerifiableCredentialsAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if !ctx.VCIsEnabled {
		return nil
	}

	if _, _, err := vc.Resolve(ctx, vc.Request{
		Scopes:    params.Scopes,
		Details:   params.AuthDetails,
		Resources: params.Resources,
	}); err != nil {
		return wrapRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid verifiable credentials request", params, err)
	}

	return nil
}

// clientWithRedirectURI creates a copy of the client with the given redirect URI.
func clientWithRedirectURI(c *goidc.Client, uri string) *goidc.Client {
	copied := *c
	copied.RedirectURIs = append(slices.Clone(c.RedirectURIs), uri)
	return &copied
}
