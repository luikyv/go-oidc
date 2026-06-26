package token

import (
	"errors"

	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ValidatePoP validates that the context contains the information required to
// prove the client's possession of the token.
// If token is omitted, the validation of the claim 'ath' of DPoP JWTs is skipped.
func ValidatePoP(ctx oidc.Context, token string, cnf goidc.TokenConfirmation) error {
	if err := validateDPoP(ctx, token, cnf); err != nil {
		return err
	}

	return validateTLSPoP(ctx, cnf)
}

// validateDPoP validates that the context contains the information required to
// prove the client's possession of the access token with DPoP if applicable.
// If token is omitted, the validation of the claim 'ath' of DPoP JWTs is skipped.
func validateDPoP(ctx oidc.Context, token string, confirmation goidc.TokenConfirmation) error {
	if confirmation.JWKThumbprint == "" {
		return nil
	}
	if !ctx.DPoPEnabled {
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the token is bound to DPoP, but DPoP support is disabled"))
	}

	dpopJWT, ok := dpop.JWT(ctx)
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("a DPoP proof is required for this token"))
	}

	return dpop.ValidateJWT(ctx, dpopJWT, dpop.ValidationOptions{
		AccessToken:   token,
		JWKThumbprint: confirmation.JWKThumbprint,
	})
}

// validateDPoP validates that the context contains the information required to
// prove the client's possession of the access token with TLS binding if
// applicable.
func validateTLSPoP(ctx oidc.Context, confirmation goidc.TokenConfirmation) error {
	if confirmation.CertThumbprint == "" {
		return nil
	}
	if !ctx.MTLSTokenBindingEnabled {
		return goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token",
			errors.New("the token is bound to mutual TLS, but mutual TLS token binding support is disabled"))
	}

	clientCert, err := ctx.ClientCert()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token", err)
	}

	if confirmation.CertThumbprint != hashutil.Thumbprint(string(clientCert.Raw)) {
		return goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token",
			errors.New("the client certificate does not match the token binding thumbprint"))
	}

	return nil
}

// dpopThumbprint returns the DPoP JWK thumbprint from the request context,
// or an empty string if DPoP is not enabled or no DPoP JWT is present.
func dpopThumbprint(ctx oidc.Context) string {
	if !ctx.DPoPEnabled {
		return ""
	}
	if dpopJWT, ok := dpop.JWT(ctx); ok {
		return dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}
	return ""
}

// tlsThumbprint returns the client certificate thumbprint from the request
// context, or an empty string if mTLS token binding is not enabled or no
// certificate is present.
func tlsThumbprint(ctx oidc.Context) string {
	if !ctx.MTLSTokenBindingEnabled {
		return ""
	}
	clientCert, err := ctx.ClientCert()
	if err != nil {
		return ""
	}
	return hashutil.Thumbprint(string(clientCert.Raw))
}
