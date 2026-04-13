package token

import (
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

	dpopJWT, ok := dpop.JWT(ctx)
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
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

	clientCert, err := ctx.ClientCert()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidToken,
			"the client certificate is required", err)
	}

	if confirmation.CertThumbprint != hashutil.Thumbprint(string(clientCert.Raw)) {
		return goidc.NewError(goidc.ErrorCodeInvalidToken,
			"invalid client certificate")
	}

	return nil
}

// dpopThumbprint returns the DPoP JWK thumbprint from the request context,
// or an empty string if DPoP is not enabled or no DPoP JWT is present.
func dpopThumbprint(ctx oidc.Context) string {
	if dpopJWT, ok := dpop.JWT(ctx); ctx.DPoPIsEnabled && ok {
		return dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}
	return ""
}

// tlsThumbprint returns the client certificate thumbprint from the request
// context, or an empty string if mTLS token binding is not enabled or no
// certificate is present.
func tlsThumbprint(ctx oidc.Context) string {
	if clientCert, err := ctx.ClientCert(); ctx.MTLSTokenBindingIsEnabled && err == nil {
		return hashutil.Thumbprint(string(clientCert.Raw))
	}
	return ""
}
