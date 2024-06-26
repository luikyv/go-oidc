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
	if responseMode.IsJarm() || client.JarmSignatureAlgorithm != "" {
		responseJwt, err := createJarmResponse(ctx, client, redirectParams)
		if err != nil {
			return err
		}
		redirectParams.Response = responseJwt
	}

	redirectParamsMap := redirectParams.GetParameters()
	switch responseMode {
	case goidc.FragmentResponseMode, goidc.FragmentJwtResponseMode:
		redirectUrl := utils.GetUrlWithFragmentParams(params.RedirectUri, redirectParamsMap)
		ctx.Redirect(redirectUrl)
	case goidc.FormPostResponseMode, goidc.FormPostJwtResponseMode:
		redirectParamsMap["redirect_uri"] = params.RedirectUri
		ctx.RenderHtml(formPostResponseTemplate, redirectParamsMap)
	default:
		redirectUrl := utils.GetUrlWithQueryParams(params.RedirectUri, redirectParamsMap)
		ctx.Redirect(redirectUrl)
	}

	return nil
}

func createJarmResponse(
	ctx utils.Context,
	client goidc.Client,
	redirectParams utils.AuthorizationResponse,
) (
	string,
	goidc.OAuthError,
) {
	responseJwt, err := signJarmResponse(ctx, client, redirectParams)
	if err != nil {
		return "", err
	}

	if client.JarmKeyEncryptionAlgorithm != "" {
		responseJwt, err = encryptJarmResponse(ctx, responseJwt, client)
		if err != nil {
			return "", err
		}
	}

	return responseJwt, nil
}

func signJarmResponse(
	ctx utils.Context,
	client goidc.Client,
	redirectParams utils.AuthorizationResponse,
) (
	string,
	goidc.OAuthError,
) {
	jwk := ctx.GetJarmSignatureKey(client)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.GetAlgorithm()), Key: jwk.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.GetKeyId()),
	)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	createdAtTimestamp := goidc.GetTimestampNow()
	claims := map[string]any{
		goidc.IssuerClaim:   ctx.Host,
		goidc.AudienceClaim: client.Id,
		goidc.IssuedAtClaim: createdAtTimestamp,
		goidc.ExpiryClaim:   createdAtTimestamp + ctx.JarmLifetimeSecs,
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

func encryptJarmResponse(
	ctx utils.Context,
	responseJwt string,
	client goidc.Client,
) (
	string,
	goidc.OAuthError,
) {
	jwk, err := client.GetJarmEncryptionJwk()
	if err != nil {
		return "", err
	}

	encryptedResponseJwt, err := utils.EncryptJwt(ctx, responseJwt, jwk, client.JarmContentEncryptionAlgorithm)
	if err != nil {
		return "", err
	}

	return encryptedResponseJwt, nil
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
		var form = document.getElementById('form');
		form.addEventListener('formdata', function(event) {
			let formData = event.formData;
			for (let [name, value] of Array.from(formData.entries())) {
				if (value === '') formData.delete(name);
			}
		});
	</script>

	</html>
`
