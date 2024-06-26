package authorize

import (
	"errors"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func redirectError(
	ctx utils.Context,
	err goidc.OAuthError,
	client goidc.Client,
) goidc.OAuthError {
	var oauthErr goidc.OAuthRedirectError
	if !errors.As(err, &oauthErr) {
		return err
	}

	redirectParams := utils.AuthorizationResponse{
		Error:            oauthErr.ErrorCode,
		ErrorDescription: oauthErr.ErrorDescription,
		State:            oauthErr.State,
	}
	return redirectResponse(ctx, client, oauthErr.AuthorizationParameters, redirectParams)
}

func redirectResponse(
	ctx utils.Context,
	client goidc.Client,
	params goidc.AuthorizationParameters,
	redirectParams utils.AuthorizationResponse,
) goidc.OAuthError {

	if ctx.IssuerResponseParameterIsEnabled {
		redirectParams.Issuer = ctx.Host
	}

	responseMode := params.GetResponseMode()
	if responseMode.IsJARM() || client.JARMSignatureAlgorithm != "" {
		responseJWT, err := createJARMResponse(ctx, client, redirectParams)
		if err != nil {
			return err
		}
		redirectParams.Response = responseJWT
	}

	redirectParamsMap := redirectParams.GetParameters()
	switch responseMode {
	case goidc.FragmentResponseMode, goidc.FragmentJWTResponseMode:
		redirectURL := utils.GetURLWithFragmentParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	case goidc.FormPostResponseMode, goidc.FormPostJWTResponseMode:
		redirectParamsMap["redirect_uri"] = params.RedirectURI
		ctx.RenderHtml(formPostResponseTemplate, redirectParamsMap)
	default:
		redirectURL := utils.GetURLWithQueryParams(params.RedirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	}

	return nil
}

func createJARMResponse(
	ctx utils.Context,
	client goidc.Client,
	redirectParams utils.AuthorizationResponse,
) (
	string,
	goidc.OAuthError,
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
	ctx utils.Context,
	client goidc.Client,
	redirectParams utils.AuthorizationResponse,
) (
	string,
	goidc.OAuthError,
) {
	jwk := ctx.GetJARMSignatureKey(client)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.GetAlgorithm()), Key: jwk.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.GetKeyID()),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	createdAtTimestamp := goidc.GetTimestampNow()
	claims := map[string]any{
		goidc.IssuerClaim:   ctx.Host,
		goidc.AudienceClaim: client.ID,
		goidc.IssuedAtClaim: createdAtTimestamp,
		goidc.ExpiryClaim:   createdAtTimestamp + ctx.JARMLifetimeSecs,
	}
	for k, v := range redirectParams.GetParameters() {
		claims[k] = v
	}

	response, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return response, nil
}

func encryptJARMResponse(
	ctx utils.Context,
	responseJWT string,
	client goidc.Client,
) (
	string,
	goidc.OAuthError,
) {
	jwk, err := client.GetJARMEncryptionJWK()
	if err != nil {
		return "", err
	}

	encryptedResponseJWT, err := utils.EncryptJWT(ctx, responseJWT, jwk, client.JARMContentEncryptionAlgorithm)
	if err != nil {
		return "", err
	}

	return encryptedResponseJWT, nil
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
