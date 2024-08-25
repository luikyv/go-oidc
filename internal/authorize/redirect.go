package authorize

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func redirectError(
	ctx *oidc.Context,
	err error,
	client *goidc.Client,
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
	return redirectResponse(ctx, client, redirectErr.AuthorizationParameters, redirectParams)
}

func redirectResponse(
	ctx *oidc.Context,
	client *goidc.Client,
	params goidc.AuthorizationParameters,
	redirectParams response,
) error {

	if ctx.IssuerRespParamIsEnabled {
		redirectParams.issuer = ctx.Host
	}

	responseMode := responseMode(params)
	if responseMode.IsJARM() || client.JARMSigAlg != "" {
		responseJWT, err := createJARMResponse(ctx, client, redirectParams)
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
			return oidcerr.New(oidcerr.CodeInternalError, "could not render the html")
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
	client *goidc.Client,
	redirectParams response,
) (
	string,
	error,
) {
	responseJWT, err := signJARMResponse(ctx, client, redirectParams)
	if err != nil {
		return "", err
	}

	if client.JARMKeyEncAlg != "" {
		responseJWT, err = encryptJARMResponse(ctx, responseJWT, client)
		if err != nil {
			return "", err
		}
	}

	return responseJWT, nil
}

func signJARMResponse(
	ctx *oidc.Context,
	client *goidc.Client,
	redirectParams response,
) (
	string,
	error,
) {
	jwk := ctx.JARMSignatureKey(client)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInternalError,
			"could not sign the response object")
	}

	createdAtTimestamp := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimAudience: client.ID,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.JARM.LifetimeSecs,
	}
	for k, v := range redirectParams.parameters() {
		claims[k] = v
	}

	response, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInternalError,
			"could not sign the response object")
	}

	return response, nil
}

func encryptJARMResponse(
	ctx *oidc.Context,
	responseJWT string,
	client *goidc.Client,
) (
	string,
	error,
) {
	jwk, err := client.JARMEncryptionJWK()
	if err != nil {
		return "", oidcerr.New(oidcerr.CodeInvalidRequest,
			"could not fetch the client encryption jwk for jarm")
	}

	encryptedResponseJWT, oauthErr := token.EncryptJWT(ctx, responseJWT, jwk, client.JARMContentEncAlg)
	if oauthErr != nil {
		return "", oauthErr
	}

	return encryptedResponseJWT, nil
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
