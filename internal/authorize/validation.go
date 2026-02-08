package authorize

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// validateRequest validates the parameters sent in an authorization request.
func validateRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	if c.IsFederated && c.FederationRegistrationType == goidc.ClientRegistrationTypeAutomatic {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "asymmetric cryptography must be used to authenticate requests when using automatic registration")
	}
	return validateParams(ctx, req.AuthorizationParameters, c)
}

// validateRequestWithPAR validates the parameters in an authorization request
// that includes a Pushed Authorization Request (PAR).
func validateRequestWithPAR(ctx oidc.Context, req request, as *goidc.AuthnSession, c *goidc.Client) error {
	if as.ClientID != req.ClientID {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "invalid client")
	}

	if as.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "the request_uri is expired")
	}

	if ctx.PARAllowUnregisteredRedirectURI && as.RedirectURI != "" {
		c.RedirectURIs = append(c.RedirectURIs, as.RedirectURI)
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
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed inside the request object", mergedParams)
	}

	if jar.RequestObject != "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "request is not allowed inside the request object", mergedParams)
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
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientID != c.ID {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "invalid client_id")
	}

	if jar.RequestObject != "" || jar.RequestURI != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidResquestObject, "request object is not allowed inside JAR")
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
	if c.IsFederated && c.FederationRegistrationType == goidc.ClientRegistrationTypeAutomatic {
		if c.TokenAuthnMethod != goidc.ClientAuthnPrivateKeyJWT && c.TokenAuthnMethod != goidc.ClientAuthnSelfSignedTLS {
			return goidc.NewError(goidc.ErrorCodeAccessDenied,
				"asymmetric cryptography must be used to authenticate requests when using automatic registration")
		}
	}
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
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "request_uri is not allowed during PAR")
	}

	if ctx.PARAllowUnregisteredRedirectURI && req.RedirectURI != "" {
		c.RedirectURIs = append(c.RedirectURIs, req.RedirectURI)
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
		if ctx.PKCEIsEnabled && req.CodeChallenge == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "code_challenge is required")
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
			return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams)
		}

		if inParams.ResponseType != "" && inParams.ResponseType != outParams.ResponseType {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_type", mergedParams)
		}

		if strutil.ContainsOpenID(inParams.Scopes) && !strutil.ContainsOpenID(outParams.Scopes) {
			return newRedirectionError(goidc.ErrorCodeInvalidScope, "scope openid is required", mergedParams)
		}
	}

	return nil
}

// validateParams validates the parameters of an authorization request.
func validateParams(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.RedirectURI == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "redirect_uri is required")
	}

	if err := validateParamsAsOptionals(ctx, params, c); err != nil {
		return err
	}

	if params.ResponseType == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "response_type is required", params)
	}

	if ctx.ResourceIndicatorsIsRequired && params.Resources == nil {
		return newRedirectionError(goidc.ErrorCodeInvalidTarget, "the resources parameter is required", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "scope openid is required", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "cannot request id_token without the scope openid", params)
	}

	if params.ResponseType.Contains(goidc.ResponseTypeIDToken) && params.Nonce == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "nonce is required when response type id_token is requested", params)
	}

	if err := validatePKCE(ctx, params, c); err != nil {
		return err
	}

	if ctx.Profile == goidc.ProfileFAPI1 {
		if !slices.Contains([]goidc.ResponseType{
			goidc.ResponseTypeCode,
			goidc.ResponseTypeCodeAndIDToken,
		}, params.ResponseType) {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"response_type not supported", params)
		}

		if params.ResponseType == goidc.ResponseTypeCode && params.ResponseMode != goidc.ResponseModeJWT {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"response_type code without jwt response_mode is not allowed", params)
		}

		if strutil.ContainsOpenID(params.Scopes) && params.Nonce == "" {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"nonce is required", params)
		}
	}

	if ctx.Profile == goidc.ProfileFAPI2 {
		if params.ResponseType != goidc.ResponseTypeCode {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest,
				"response_type not allowed", params)
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

	if err := validateAuthorizationDetailsAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateACRValuesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateResourcesAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateIDTokenHintAsOptional(ctx, params, c); err != nil {
		return err
	}

	if err := validateDisplayValueAsOptional(ctx, params, c); err != nil {
		return err
	}

	if params.RequestURI != "" && params.RequestObject != "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest,
			"cannot inform a request object and request_uri at the same time", params)
	}

	return nil
}

func validateRedirectURIAsOptional(_ oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if params.RedirectURI == "" {
		return nil
	}

	parsedURI, err := url.Parse(params.RedirectURI)
	if err != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "could not parse the redirect_uri")
	}

	// RFC 8252: Native apps can use loopback interface on any port.
	if host := parsedURI.Hostname(); c.ApplicationType == goidc.ApplicationTypeNative {
		if host == "::1" {
			host = "[::1]"
		}
		parsedURI.Host = host
	}

	if !slices.Contains(c.RedirectURIs, parsedURI.String()) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "redirect_uri not allowed")
	}

	return nil
}

func validateRequestURIAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, client *goidc.Client) error {
	if params.RequestURI == "" || strings.HasPrefix(params.RequestURI, parRequestURIPrefix) {
		return nil
	}

	if !ctx.JARByReferenceIsEnabled {
		return goidc.NewError(goidc.ErrorCodeRequestURINotSupported, "request_uri is not supported")
	}

	if ctx.JARRequestURIRegistrationIsRequired && !isRequestURIAllowed(client, params.RequestURI) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "request_uri not allowed")
	}

	if parsedURI, err := url.Parse(params.RequestURI); err != nil || parsedURI.Scheme != "https" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	return nil
}

func validateCodeChallengeMethodAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.CodeChallengeMethod == "" {
		return nil
	}

	if !slices.Contains(ctx.PKCEChallengeMethods, params.CodeChallengeMethod) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid code_challenge_method", params)
	}

	return nil
}

func validateDisplayValueAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {
	if params.Display == "" {
		return nil
	}

	if !slices.Contains(ctx.DisplayValues, params.Display) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid display value", params)
	}

	return nil
}

func validateScopesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {

	if params.Scopes == "" {
		return nil
	}

	if !client.AreScopesAllowed(ctx, c, params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidScope, "invalid scope", params)
	}

	if ctx.OpenIDIsRequired && !strutil.ContainsOpenID(params.Scopes) {
		return newRedirectionError(goidc.ErrorCodeInvalidScope, "scope openid is required", params)
	}

	return nil
}

func validatePKCE(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if ctx.PKCEIsEnabled && c.IsPublic() && params.CodeChallenge == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "pkce is required for public clients", params)
	}

	if ctx.PKCEIsRequired && params.CodeChallenge == "" {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "code_challenge is required", params)
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
		return newRedirectionError(goidc.ErrorCodeInvalidGrant, "response type code is not allowed", params)
	}

	if params.ResponseType.IsImplicit() && !slices.Contains(c.GrantTypes, goidc.GrantImplicit) {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "implicit response type is not allowed", params)
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
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode for the chosen response_type", params)
	}

	// If the client has defined a signature algorithm for JARM, then JARM is required.
	if c.JARMSigAlg != "" && params.ResponseMode.IsPlain() {
		return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid response_mode", params)
	}

	return nil
}

func validateAuthorizationDetailsAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) error {
	if !ctx.AuthDetailsIsEnabled || params.AuthDetails == nil {
		return nil
	}

	for _, authDetail := range params.AuthDetails {
		authDetailType := authDetail.Type()
		if !slices.Contains(ctx.AuthDetailTypes, authDetailType) || !isAuthDetailTypeAllowed(c, authDetailType) {
			return newRedirectionError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization detail type", params)
		}
	}

	return nil
}

func validateACRValuesAsOptional(ctx oidc.Context, params goidc.AuthorizationParameters, _ *goidc.Client) error {

	if params.ACRValues == "" {
		return nil
	}

	for _, acr := range strutil.SplitWithSpaces(params.ACRValues) {
		if !slices.Contains(ctx.ACRs, goidc.ACR(acr)) {
			return newRedirectionError(goidc.ErrorCodeInvalidRequest, "invalid acr value", params)
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
			return newRedirectionError(goidc.ErrorCodeInvalidTarget, "the resource "+resource+" is invalid", params)
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
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	if len(parsedIDToken.Headers) != 1 {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid id token hint")
	}

	publicKey, err := ctx.PublicJWK(parsedIDToken.Headers[0].KeyID)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	var claims jwt.Claims
	if err := parsedIDToken.Claims(publicKey.Key, &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      ctx.Issuer(),
		AnyAudience: []string{c.ID},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid id token hint", err)
	}

	return nil
}

func isRequestURIAllowed(c *goidc.Client, requestURI string) bool {
	return slices.Contains(c.RequestURIs, requestURI)
}

func isAuthDetailTypeAllowed(c *goidc.Client, authDetailType string) bool {
	// If the client didn't announce the authorization types it will use,
	// consider any value valid.
	if c.AuthDetailTypes == nil {
		return true
	}

	return slices.Contains(c.AuthDetailTypes, authDetailType)
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
