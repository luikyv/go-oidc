package token

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ValidateBinding checks both DPoP and TLS binding for issuing a token.
func ValidateBinding(ctx oidc.Context, c *goidc.Client, opts *bindindValidationOptions) error {
	if opts == nil {
		opts = &bindindValidationOptions{}
	}
	if err := validateBindingDPoP(ctx, c, *opts); err != nil {
		return err
	}

	if err := validateBindingTLS(ctx, c, *opts); err != nil {
		return err
	}

	return validateBindingRequirement(ctx)
}

func validateBindingDPoP(ctx oidc.Context, c *goidc.Client, opts bindindValidationOptions) error {

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
		if ctx.DPoPIsRequired || c.DPoPTokenBindingIsRequired || opts.dpopIsRequired {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid dpop header")
		}
		return nil
	}

	return dpop.ValidateJWT(ctx, dpopJWT, dpop.ValidationOptions{
		JWKThumbprint: opts.dpopJWKThumbprint,
	})
}

func validateBindingTLS(ctx oidc.Context, c *goidc.Client, opts bindindValidationOptions) error {
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
		if ctx.MTLSTokenBindingIsRequired || c.TLSTokenBindingIsRequired || opts.tlsIsRequired {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "client certificate is required", err)
		}
		return nil
	}

	if opts.tlsCertThumbprint != "" && opts.tlsCertThumbprint != hashutil.Thumbprint(string(cert.Raw)) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid client certificate")
	}

	return nil
}

func validateBindingRequirement(ctx oidc.Context) error {
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
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "token binding is required either with dpop or tls")
	}

	return nil
}

func validateResources(ctx oidc.Context, availableResources goidc.Resources, req request) error {
	if !ctx.ResourceIndicatorsIsEnabled {
		return nil
	}

	for _, resource := range req.resources {
		if !slices.Contains(availableResources, resource) {
			return goidc.NewError(goidc.ErrorCodeInvalidTarget, "the resource "+resource+" is invalid")
		}
	}

	return nil
}

// validateAuthDetails validates the auth details for the token request.
// Parameters:
//   - granted: The granted auth details. If nil, no auth details were previouly granted.
func validateAuthDetails(ctx oidc.Context, req request, c *goidc.Client, granted []goidc.AuthDetail) error {
	if !ctx.RARIsEnabled || req.authDetails != nil {
		return nil
	}

	for _, detail := range req.authDetails {
		if !slices.Contains(ctx.RARDetailTypes, detail.Type()) {
			return goidc.NewError(goidc.ErrorCodeInvalidAuthDetails, "authorization detail not allowed")
		}

		if c.AuthDetailTypes != nil && !slices.Contains(c.AuthDetailTypes, detail.Type()) {
			return goidc.NewError(goidc.ErrorCodeInvalidAuthDetails, "authorization detail not allowed")
		}

		if err := ctx.RARValidateDetail(detail); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization detail", err)
		}
	}

	if granted != nil {
		if err := ctx.RARCompareAuthDetails(req.authDetails, granted); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", err)
		}
	}

	return nil
}

func validateScopes(_ oidc.Context, req request, session *goidc.AuthnSession) error {
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

func validatePKCE(ctx oidc.Context, req request, _ *goidc.Client, as *goidc.AuthnSession) error {
	if !ctx.PKCEIsEnabled {
		return nil
	}

	if as.CodeChallenge == "" {
		// [RFC 9700] a token request containing a code_verifier parameter is
		// accepted only if a code_challenge parameter was present in the authorization request.
		if req.codeVerifier != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier",
				errors.New("code_verifier was informed in the request, but no code_challenge was provided previously"))
		}
		return nil
	}

	// [RFC 7636] with a minimum length of 43 characters and a maximum length of 128 characters.
	if verifierLengh := len(req.codeVerifier); verifierLengh < 43 || verifierLengh > 128 {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
	}

	method := ctx.PKCEDefaultChallengeMethod
	if as.CodeChallengeMethod != "" && slices.Contains(ctx.PKCEChallengeMethods, as.CodeChallengeMethod) {
		method = as.CodeChallengeMethod
	}

	switch verifier, challenge := req.codeVerifier, as.CodeChallenge; method {
	case goidc.CodeChallengeMethodPlain:
		if verifier != challenge {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
		}
	case goidc.CodeChallengeMethodSHA256:
		if hashutil.Thumbprint(verifier) != challenge {
			return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier")
		}
	default:
		return goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid code_verifier", fmt.Errorf("pkce method %s is not supported", method))
	}

	return nil
}
