package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func validateTokenBinding(ctx *oidc.Context, client *goidc.Client) error {
	if err := validateTokenBindingDPoP(ctx, client); err != nil {
		return err
	}

	if err := validateTokenBindingTLS(ctx, client); err != nil {
		return err
	}

	return validateTokenBindingIsRequired(ctx)
}

func validateTokenBindingDPoP(
	ctx *oidc.Context,
	client *goidc.Client,
) error {

	if !ctx.DPoPIsEnabled {
		return nil
	}

	dpopJWT, ok := dpopJWT(ctx)
	// Return an error if the DPoP header was not informed, but it's required
	// either in the general config or by the client.
	if !ok && (ctx.DPoPIsRequired || client.DPoPIsRequired) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid dpop header")
	}

	// If the DPoP header was not informed, there's nothing to validate.
	if !ok {
		return nil
	}
	return validateDPoPJWT(ctx, dpopJWT, dpopValidationOptions{})
}

func validateTokenBindingTLS(
	ctx *oidc.Context,
	client *goidc.Client,
) error {
	if !ctx.MTLSTokenBindingIsEnabled {
		return nil
	}

	_, err := ctx.ClientCert()
	if err != nil && (ctx.MTLSTokenBindingIsRequired || client.TLSBoundTokensIsRequired) {
		return oidcerr.Errorf(oidcerr.CodeInvalidRequest, "invalid client certificate", err)
	}

	return nil
}

func validateTokenBindingIsRequired(ctx *oidc.Context) error {
	if !ctx.TokenBindingIsRequired {
		return nil
	}

	tokenWillBeBound := false

	_, ok := dpopJWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		tokenWillBeBound = true
	}

	_, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err != nil {
		tokenWillBeBound = true
	}

	if !tokenWillBeBound {
		return oidcerr.New(oidcerr.CodeInvalidRequest,
			"token binding is required either with dpop or tls")
	}

	return nil
}

func validateResources(
	ctx *oidc.Context,
	availableResources goidc.Resources,
	req request,
) error {
	if !ctx.ResourceIndicatorsIsEnabled {
		return nil
	}

	for _, resource := range req.resources {
		if !slices.Contains(availableResources, resource) {
			return oidcerr.New(oidcerr.CodeInvalidTarget,
				"the resource "+resource+" is invalid")
		}
	}

	return nil
}

func validateScopes(
	_ *oidc.Context,
	req request,
	session *goidc.AuthnSession,
) error {
	if !containsAllScopes(session.GrantedScopes, req.scopes) {
		return oidcerr.New(oidcerr.CodeInvalidScope, "invalid scope")
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
	ctx *oidc.Context,
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
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = ctx.PKCEDefaultChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code
	// challenge, the token request must contain the right code verifier.
	if session.CodeChallenge != "" && req.codeVerifier == "" {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "code_verifier cannot be empty")
	}
	if session.CodeChallenge != "" &&
		!isPKCEValid(req.codeVerifier, session.CodeChallenge, codeChallengeMethod) {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "invalid code_verifier")
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
