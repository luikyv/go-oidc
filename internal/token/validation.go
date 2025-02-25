package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ValidateBinding checks both DPoP and TLS binding for issuing a token.
func ValidateBinding(
	ctx oidc.Context,
	client *goidc.Client,
	opts *bindindValidationsOptions,
) error {
	if opts == nil {
		opts = &bindindValidationsOptions{}
	}
	if err := validateBindingDPoP(ctx, client, *opts); err != nil {
		return err
	}

	if err := validateBindingTLS(ctx, client, *opts); err != nil {
		return err
	}

	return validateBindingIsRequired(ctx)
}

func validateBindingDPoP(
	ctx oidc.Context,
	client *goidc.Client,
	opts bindindValidationsOptions,
) error {

	if !ctx.DPoPIsEnabled {
		return nil
	}

	dpopJWT, ok := dpop.JWT(ctx)
	if !ok {
		// Return an error if the DPoP header was not informed and one of the
		// below applies:
		// 	* DPoP is required as a general configuration.
		// 	* The client requires DPoP.
		// 	* DPoP is required as a validation option.
		if ctx.DPoPIsRequired || client.DPoPTokenBindingIsRequired || opts.dpopIsRequired {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid dpop header")
		}
		return nil
	}

	return dpop.ValidateJWT(ctx, dpopJWT, opts.dpop)
}

func validateBindingTLS(
	ctx oidc.Context,
	client *goidc.Client,
	opts bindindValidationsOptions,
) error {
	if !ctx.MTLSTokenBindingIsEnabled {
		return nil
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		// Return an error if a valid certificate was not informed and one of the
		// below applies:
		// 	* TLS binding is required as a general configuration.
		// 	* The client requires TLS binding.
		// 	* TLS binding is required as a validation option.
		if ctx.MTLSTokenBindingIsRequired || client.TLSTokenBindingIsRequired || opts.tlsIsRequired {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "client certificate is required", err)
		}
	}

	if opts.tlsCertThumbprint != "" && opts.tlsCertThumbprint != hashutil.Thumbprint(string(cert.Raw)) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid client certificate")
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

func validateAuthDetails(
	ctx oidc.Context,
	grantedDetails []goidc.AuthorizationDetail,
	req request,
) error {
	if !shouldValidateAuthDetails(ctx, req) {
		return nil
	}

	if err := validateAuthDetailsTypes(ctx, req); err != nil {
		return err
	}

	if err := ctx.CompareAuthDetails(grantedDetails, req.authDetails); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails,
			"invalid authorization details", err)
	}

	return nil
}

func validateAuthDetailsTypes(
	ctx oidc.Context,
	req request,
) error {
	if !shouldValidateAuthDetails(ctx, req) {
		return nil
	}

	for _, detail := range req.authDetails {
		if !slices.Contains(ctx.AuthDetailTypes, detail.Type()) {
			return goidc.NewError(goidc.ErrorCodeInvalidAuthDetails,
				"invalid authorization details")
		}
	}

	return nil
}

func shouldValidateAuthDetails(ctx oidc.Context, req request) bool {
	return ctx.AuthDetailsIsEnabled && req.authDetails != nil
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

func validatePkce(ctx oidc.Context, req request, _ *goidc.Client, session *goidc.AuthnSession) error {

	if !ctx.PKCEIsEnabled {
		return nil
	}

	if session.CodeChallenge == "" {
		// RFC 9700. "...a token request containing a code_verifier parameter is
		// accepted only if a code_challenge parameter was present in the authorization request..."
		if req.codeVerifier != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
		}
		return nil
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = ctx.PKCEDefaultChallengeMethod
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length
	// of 128 characters."
	codeVerifierLengh := len(req.codeVerifier)
	if codeVerifierLengh < 43 || codeVerifierLengh > 128 {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
	}

	if !isPKCEValid(req.codeVerifier, session.CodeChallenge, codeChallengeMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
	}

	return nil
}

func isPKCEValid(codeVerifier, codeChallenge string, codeChallengeMethod goidc.CodeChallengeMethod) bool {
	switch codeChallengeMethod {
	case goidc.CodeChallengeMethodPlain:
		return codeChallenge == codeVerifier
	case goidc.CodeChallengeMethodSHA256:
		return codeChallenge == hashutil.Thumbprint(codeVerifier)
	}

	return false
}
