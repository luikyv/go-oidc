package authorize

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func redirectError(
	ctx *oidc.Context,
	err oidc.Error,
	client *goidc.Client,
) oidc.Error {
	var oauthErr redirectionError
	if !errors.As(err, &oauthErr) {
		return err
	}

	redirectParams := authorizationResponse{
		Error:            oauthErr.ErrorCode,
		ErrorDescription: oauthErr.ErrorDescription,
		State:            oauthErr.State,
	}
	return redirectResponse(ctx, client, oauthErr.AuthorizationParameters, redirectParams)
}

func redirectResponse(
	ctx *oidc.Context,
	client *goidc.Client,
	params goidc.AuthorizationParameters,
	redirectParams authorizationResponse,
) oidc.Error {

	if ctx.IssuerResponseParameterIsEnabled {
		redirectParams.Issuer = ctx.Host
	}

	responseMode := responseMode(params)
	if responseMode.IsJARM() || client.JARMSignatureAlgorithm != "" {
		responseJWT, err := createJARMResponse(ctx, client, redirectParams)
		if err != nil {
			return err
		}
		redirectParams.Response = responseJWT
	}

	redirectParamsMap := redirectParams.Parameters()
	switch responseMode {
	case goidc.ResponseModeFragment, goidc.ResponseModeFragmentJWT:
		redirectURL := urlWithFragmentParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	case goidc.ResponseModeFormPost, goidc.ResponseModeFormPostJWT:
		redirectParamsMap["redirect_uri"] = params.RedirectURI
		if err := ctx.RenderHTML(formPostResponseTemplate, redirectParamsMap); err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
	default:
		redirectURL := urlWithQueryParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	}

	return nil
}

// responseMode returns the response mode based on the response type.
// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations.
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
	redirectParams authorizationResponse,
) (
	string,
	oidc.Error,
) {
	responseJWT, err := signJARMResponse(ctx, client, redirectParams)
	if err != nil {
		return "", err
	}

	if client.JARMKeyEncryptionAlgorithm != "" {
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
	redirectParams authorizationResponse,
) (
	string,
	oidc.Error,
) {
	jwk := ctx.JARMSignatureKey(client)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	createdAtTimestamp := time.Now().Unix()
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Host,
		goidc.ClaimAudience: client.ID,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.JARMLifetimeSecs,
	}
	for k, v := range redirectParams.Parameters() {
		claims[k] = v
	}

	response, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return response, nil
}

func encryptJARMResponse(
	ctx *oidc.Context,
	responseJWT string,
	client *goidc.Client,
) (
	string,
	oidc.Error,
) {
	jwk, err := client.JARMEncryptionJWK()
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInvalidRequest, err.Error())
	}

	encryptedResponseJWT, err := token.EncryptJWT(ctx, responseJWT, jwk, client.JARMContentEncryptionAlgorithm)
	if err != nil {
		return "", oidc.NewError(oidc.ErrorCodeInvalidRequest, err.Error())
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

var formPostResponseTemplate string = `
	<!-- This HTML document is intended to be used as the response mode "form_post". -->
	<!-- The parameters that are usually sent to the client via redirect will be sent by posting a form to the client's redirect URI. -->
	<html>
	<body onload="javascript:document.forms[0].submit()">
		<form id="form" method="post" action="{{ .redirect_uri }}">
			<input type="hidden" name="code" value="{{ .code }}"/>
			<input type="hidden" name="state" value="{{ .state }}"/>
			<input type="hidden" name="access_token" value="{{ .access_token }}"/>
			<input type="hidden" name="token_type" value="{{ .token_type }}"/>
			<input type="hidden" name="id_token" value="{{ .id_token }}"/>
			<input type="hidden" name="response" value="{{ .response }}"/>
			<input type="hidden" name="error" value="{{ .error }}"/>
			<input type="hidden" name="error_description" value="{{ .error_description }}"/>
		</form>
	</body>

	<script>
		var form = document.getElementByID('form');
		form.addEventListener('formdata', function(event) {
			let formData = event.formData;
			for (let [name, value] of Array.from(formData.entries())) {
				if (value === '') formData.delete(name);
			}
		});
	</script>

	</html>
`
