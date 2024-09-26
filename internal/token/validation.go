package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// TODO: Document it.
func validateBinding(
	ctx oidc.Context,
	client *goidc.Client,
	dpopOpts *dpop.ValidationOptions,
) error {
	if dpopOpts == nil {
		dpopOpts = &dpop.ValidationOptions{}
	}
	if err := validateBindingDPoP(ctx, client, *dpopOpts); err != nil {
		return err
	}

	if err := validateBindingTLS(ctx, client); err != nil {
		return err
	}

	return validateBindingIsRequired(ctx)
}

func validateBindingDPoP(
	ctx oidc.Context,
	client *goidc.Client,
	dpopOpts dpop.ValidationOptions,
) error {

	if !ctx.DPoPIsEnabled {
		return nil
	}

	dpopJWT, ok := dpop.JWT(ctx)
	// Return an error if the DPoP header was not informed and one of the below
	// applies:
	// 	* DPoP is required as a general configuration.
	// 	* The client requires DPoP.
	// 	* The JWK thumbprint was informed as a validation option.
	if !ok && (ctx.DPoPIsRequired || client.DPoPTokenBindingIsRequired || dpopOpts.JWKThumbprint != "") {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid dpop header")
	}

	// If the DPoP header was not informed, there's nothing to validate.
	if !ok {
		return nil
	}
	return dpop.ValidateJWT(ctx, dpopJWT, dpopOpts)
}

func validateBindingTLS(
	ctx oidc.Context,
	client *goidc.Client,
) error {
	if !ctx.MTLSTokenBindingIsEnabled {
		return nil
	}

	_, err := ctx.ClientCert()
	if err != nil && (ctx.MTLSTokenBindingIsRequired || client.TLSTokenBindingIsRequired) {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "invalid client certificate", err)
	}

	return nil
}

func validateBindingIsRequired(ctx oidc.Context) error {
	if !ctx.TokenBindingIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := dpop.JWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err == nil {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"token binding is required either with dpop or tls")
	}

	return nil
}

func validateResources(
	ctx oidc.Context,
	availableResources goidc.Resources,
	req request,
) error {
	if !ctx.ResourceIndicatorsIsEnabled {
		return nil
	}

	for _, resource := range req.resources {
		if !slices.Contains(availableResources, resource) {
			return goidc.NewError(goidc.ErrorCodeInvalidTarget,
				"the resource "+resource+" is invalid")
		}
	}

	return nil
}

func validateScopes(
	_ oidc.Context,
	req request,
	session *goidc.AuthnSession,
) error {
	if !containsAllScopes(session.GrantedScopes, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	return nil
}

func containsAllScopes(availableScopes string, requestedScopes string) bool {
	scopeSlice := strutil.SplitWithSpaces(availableScopes)
	for _, e := range strutil.SplitWithSpaces(requestedScopes) {
		if !slices.Contains(scopeSlice, e) {
			return false
		}
	}

	return true
}

func validatePkce(
	ctx oidc.Context,
	req request,
	_ *goidc.Client,
	session *goidc.AuthnSession,
) error {

	if !ctx.PKCEIsEnabled {
		return nil
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length
	// of 128 characters."
	codeVerifierLengh := len(req.codeVerifier)
	if req.codeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = ctx.PKCEDefaultChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code
	// challenge, the token request must contain the right code verifier.
	if session.CodeChallenge != "" && req.codeVerifier == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "code_verifier cannot be empty")
	}
	if session.CodeChallenge != "" &&
		!isPKCEValid(req.codeVerifier, session.CodeChallenge, codeChallengeMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
	}

	return nil
}

func isPKCEValid(codeVerifier string, codeChallenge string, codeChallengeMethod goidc.CodeChallengeMethod) bool {
	switch codeChallengeMethod {
	case goidc.CodeChallengeMethodPlain:
		return codeChallenge == codeVerifier
	case goidc.CodeChallengeMethodSHA256:
		return codeChallenge == hashBase64URLSHA256(codeVerifier)
	}

	return false
}
