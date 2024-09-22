package token

import (
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ValidatePoP validates that the context contains the information required to
// prove the client's possession of the token.
func ValidatePoP(
	ctx *oidc.Context,
	token string,
	tokenType goidc.TokenType,
	confirmation goidc.TokenConfirmation,
) error {
	if err := validateDPoP(ctx, token, tokenType, confirmation); err != nil {
		return err
	}

	return validateTLSPoP(ctx, confirmation)
}

// validateDPoP validates that the context contains the information required to
// prove the client's possession of the access token with DPoP if applicable.
func validateDPoP(
	ctx *oidc.Context,
	token string,
	tokenType goidc.TokenType,
	confirmation goidc.TokenConfirmation,
) error {

	if confirmation.JWKThumbprint == "" {
		if tokenType == goidc.TokenTypeDPoP {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not of
			// DPoP type, there is nothing to validate.
			return nil
		}
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
func validateTLSPoP(
	ctx *oidc.Context,
	confirmation goidc.TokenConfirmation,
) error {
	if confirmation.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, err := ctx.ClientCert()
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidToken,
			"the client certificate is required", err)
	}

	if confirmation.ClientCertificateThumbprint != hashBase64URLSHA256(string(clientCert.Raw)) {
		return goidc.NewError(goidc.ErrorCodeInvalidToken,
			"invalid client certificate")
	}

	return nil
}

// setPoP adds the available pop mechanisms to the grant info.
func setPoP(ctx *oidc.Context, grantInfo *goidc.GrantInfo) {
	dpopJWT, ok := dpop.JWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		grantInfo.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}

	clientCert, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err == nil {
		grantInfo.ClientCertThumbprint = hashBase64URLSHA256(string(clientCert.Raw))
	}
}
