package authorize

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/jwtutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func redirectError(
	ctx *oidc.Context,
	err error,
	c *goidc.Client,
) error {
	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectParams := response{
		errorCode:        redirectErr.code,
		errorDescription: redirectErr.desc,
		state:            redirectErr.State,
	}
	return redirectResponse(
		ctx,
		c,
		redirectErr.AuthorizationParameters,
		redirectParams,
	)
}

func redirectResponse(
	ctx *oidc.Context,
	c *goidc.Client,
	params goidc.AuthorizationParameters,
	redirectParams response,
) error {

	if ctx.IssuerRespParamIsEnabled {
		redirectParams.issuer = ctx.Host
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
		redirectURL := urlWithFragmentParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	case goidc.ResponseModeFormPost, goidc.ResponseModeFormPostJWT:
		redirectParamsMap["redirect_uri"] = params.RedirectURI
		if err := ctx.RenderHTML(formPostResponseTemplate, redirectParamsMap); err != nil {
			return oidcerr.Errorf(oidcerr.CodeInternalError,
				"could not render the html for the form_post response mode", err)
		}
	default:
		redirectURL := urlWithQueryParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	}

	return nil
}

// responseMode returns the response mode based on the response type.
// According to "5. Definitions of Multiple-Valued Response Type Combinations"
// of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
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

func createJARMResponse(
	ctx *oidc.Context,
	c *goidc.Client,
	redirectParams response,
) (
	string,
	error,
) {
	responseJWT, err := signJARMResponse(ctx, c, redirectParams)
	if err != nil {
		return "", err
	}

	if c.JARMKeyEncAlg != "" {
		responseJWT, err = encryptJARMResponse(ctx, responseJWT, c)
		if err != nil {
			return "", err
		}
	}

	return responseJWT, nil
}

func signJARMResponse(
	ctx *oidc.Context,
	c *goidc.Client,
	redirectParams response,
) (
	string,
	error,
) {
	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimAudience: c.ID,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.JARMLifetimeSecs,
	}
	for k, v := range redirectParams.parameters() {
		claims[k] = v
	}

	jwk := ctx.JARMSigKey(c)
	resp, err := jwtutil.Sign(claims, jwk,
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID))
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not sign the response object", err)
	}

	return resp, nil
}

func encryptJARMResponse(
	_ *oidc.Context,
	responseJWT string,
	c *goidc.Client,
) (
	string,
	error,
) {
	jwk, err := clientutil.JWKByAlg(c, string(c.JARMKeyEncAlg))
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInvalidRequest,
			"could not fetch the client encryption jwk for jarm", err)
	}

	jwe, err := jwtutil.Encrypt(responseJWT, jwk, c.JARMContentEncAlg)
	if err != nil {
		return "", oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not encrypt the response object", err)
	}

	return jwe, nil
}

func urlWithQueryParams(redirectURI string, params map[string]string) string {
	if len(params) == 0 {
		return redirectURI
	}

	parsedURL, _ := url.Parse(redirectURI)
	query := parsedURL.Query()
	for param, value := range params {
		query.Set(param, value)
	}
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func urlWithFragmentParams(redirectURI string, params map[string]string) string {
	if len(params) == 0 {
		return redirectURI
	}

	urlParams := url.Values{}
	for param, value := range params {
		urlParams.Set(param, value)
	}
	return fmt.Sprintf("%s#%s", redirectURI, urlParams.Encode())
}
