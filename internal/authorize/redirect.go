package authorize

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

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

	// [OAuth 2.0 Multiple Response Type Encoding Practices §5] Find the response mode based on the response type.
	responseMode := func() goidc.ResponseMode {
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
	}()
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

func createJARMResponse(ctx oidc.Context, c *goidc.Client, redirectParams response) (string, error) {
	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: c.ID,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.JARMLifetimeSecs,
	}
	for k, v := range redirectParams.parameters() {
		claims[k] = v
	}

	alg := ctx.JARMDefaultSigAlg
	if slices.Contains(ctx.JARMSigAlgs, c.JARMSigAlg) && c.JARMSigAlg != "" {
		alg = c.JARMSigAlg
	}
	responseJWT, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the response object: %w", err)
	}

	if !ctx.JARMEncIsEnabled || c.JARMKeyEncAlg == "" || !slices.Contains(ctx.JARMKeyEncAlgs, c.JARMKeyEncAlg) {
		return responseJWT, nil
	}

	jwk, err := client.JWKByAlg(ctx, c, string(c.JARMKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not fetch the client encryption jwk for jarm", err)
	}

	contentEncAlg := ctx.JARMDefaultContentEncAlg
	if slices.Contains(ctx.JARMContentEncAlgs, c.JARMContentEncAlg) && c.JARMContentEncAlg != "" {
		contentEncAlg = c.JARMContentEncAlg
	}
	responseJWE, err := joseutil.Encrypt(responseJWT, jwk, contentEncAlg)
	if err != nil {
		return "", fmt.Errorf("could not encrypt the response object: %w", err)
	}

	return responseJWE, nil
}
