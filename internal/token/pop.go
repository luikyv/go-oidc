package token

import (
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ValidatePoP validates that the context contains the information required to
// prove the client's possession of the token.
// If token is omitted, the validation of the claim 'ath' of DPoP JWTs is skipped.
func ValidatePoP(
	ctx oidc.Context,
	token string,
	cnf goidc.TokenConfirmation,
) error {
	if err := validateDPoP(ctx, token, cnf); err != nil {
		return err
	}

	return validateTLSPoP(ctx, cnf)
}

// validateDPoP validates that the context contains the information required to
// prove the client's possession of the access token with DPoP if applicable.
// If token is omitted, the validation of the claim 'ath' of DPoP JWTs is skipped.
func validateDPoP(
	ctx oidc.Context,
	token string,
	confirmation goidc.TokenConfirmation,
) error {

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
func validateTLSPoP(
	ctx oidc.Context,
	confirmation goidc.TokenConfirmation,
) error {
	if confirmation.ClientCertThumbprint == "" {
		return nil
	}

	clientCert, err := ctx.ClientCert()
	if err != nil {
		return goidc.Errorf(goidc.ErrorCodeInvalidToken,
			"the client certificate is required", err)
	}

	if confirmation.ClientCertThumbprint != hashBase64URLSHA256(string(clientCert.Raw)) {
		return goidc.NewError(goidc.ErrorCodeInvalidToken,
			"invalid client certificate")
	}

	return nil
}

// // validateDPoP validates that the context contains the information required to
// // prove the client's possession of the access token with TLS binding.
// func validateTLSPoP(
// 	ctx oidc.Context,
// 	certThumbprint string,
// ) error {

// 	clientCert, err := ctx.ClientCert()
// 	if err != nil {
// 		return goidc.Errorf(goidc.ErrorCodeInvalidToken,
// 			"the client certificate is required", err)
// 	}

// 	if hashBase64URLSHA256(string(clientCert.Raw)) != certThumbprint {
// 		return goidc.NewError(goidc.ErrorCodeInvalidToken,
// 			"invalid client certificate")
// 	}

// 	return nil
// }

// setPoP adds the available pop mechanisms to the grant info.
func setPoP(ctx oidc.Context, grantInfo *goidc.GrantInfo) {
	dpopJWT, ok := dpop.JWT(ctx)
	if ctx.DPoPIsEnabled && ok {
		grantInfo.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}

	clientCert, err := ctx.ClientCert()
	if ctx.MTLSTokenBindingIsEnabled && err == nil {
		grantInfo.ClientCertThumbprint = hashBase64URLSHA256(string(clientCert.Raw))
	}
}
