package authorize

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func redirectError(ctx oidc.Context, err error, c *goidc.Client) error {
	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		return err
	}

	ctx.NotifyError(err)

	redirectParams := response{
		errorCode:        redirectErr.Code(),
		errorDescription: redirectErr.Description(),
		state:            redirectErr.State,
		errorURI:         ctx.ErrorURI,
	}
	return redirectResponse(
		ctx,
		c,
		redirectErr.AuthorizationParameters,
		redirectParams,
	)
}

func redirectResponse(ctx oidc.Context, c *goidc.Client, params goidc.AuthorizationParameters, redirectParams response) error {

	if ctx.IssuerRespParamIsEnabled {
		redirectParams.issuer = ctx.Issuer()
	}

	responseMode := responseMode(params)
	if responseMode.IsJARM() || c.JARMSigAlg != "" {
		responseJWT, err := createJARMResponse(ctx, c, redirectParams)
		if err != nil {
			return err
		}
		redirectParams.response = responseJWT
	}

	redirectParamsMap := redirectParams.parameters()
	switch responseMode {
	case goidc.ResponseModeFragment, goidc.ResponseModeFragmentJWT:
		redirectURL := strutil.URLWithFragmentParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	case goidc.ResponseModeFormPost, goidc.ResponseModeFormPostJWT:
		redirectParamsMap["redirect_uri"] = params.RedirectURI
		if err := ctx.WriteHTML(formPostResponseTemplate, redirectParamsMap); err != nil {
			return fmt.Errorf("could not render the html for the form_post response mode: %w", err)
		}
	case goidc.ResponseModeJSON, goidc.ResponseModeJSONJWT:
		if err := ctx.Write(redirectParamsMap, http.StatusOK); err != nil {
			return fmt.Errorf("could not write the json response: %w", err)
		}
	default:
		redirectURL := strutil.URLWithQueryParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	}

	return nil
}

// responseMode returns the response mode based on the response type.
// According to "5. Definitions of Multiple-Valued Response Type Combinations"
// of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
// TODO: What if the response mode is not valid? The only func that calls it already
// handles this, but it's better to handle it here.
func responseMode(params goidc.AuthorizationParameters) goidc.ResponseMode {
	if params.ResponseMode == "" {
		if params.ResponseType.IsImplicit() {
			return goidc.ResponseModeFragment
		}
		return goidc.ResponseModeQuery
	}

	if params.ResponseMode == goidc.ResponseModeJWT {
		if params.ResponseType.IsImplicit() {
			return goidc.ResponseModeFragmentJWT
		}
		return goidc.ResponseModeQueryJWT
	}

	return params.ResponseMode
}

func createJARMResponse(ctx oidc.Context, c *goidc.Client, redirectParams response) (string, error) {
	responseJWT, err := signJARMResponse(ctx, c, redirectParams)
	if err != nil {
		return "", err
	}

	if !ctx.JARMEncIsEnabled || c.JARMKeyEncAlg == "" {
		return responseJWT, nil
	}

	return encryptJARMResponse(ctx, responseJWT, c)
}

func signJARMResponse(ctx oidc.Context, client *goidc.Client, redirectParams response) (string, error) {
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: client.ID,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.JARMLifetimeSecs,
	}
	for k, v := range redirectParams.parameters() {
		claims[k] = v
	}

	alg := ctx.JARMDefaultSigAlg
	if client.JARMSigAlg != "" {
		alg = client.JARMSigAlg
	}
	resp, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the response object: %w", err)
	}
	return resp, nil
}

func encryptJARMResponse(ctx oidc.Context, responseJWT string, c *goidc.Client) (string, error) {
	jwk, err := client.JWKByAlg(ctx, c, string(c.JARMKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not fetch the client encryption jwk for jarm", err)
	}

	contentEncAlg := c.JARMContentEncAlg
	if contentEncAlg == "" {
		contentEncAlg = ctx.JARMDefaultContentEncAlg
	}
	jwe, err := joseutil.Encrypt(responseJWT, jwk, contentEncAlg)
	if err != nil {
		return "", err
	}

	return jwe, nil
}
