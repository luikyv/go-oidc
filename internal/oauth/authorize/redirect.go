package authorize

import (
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func redirectError(
	ctx utils.Context,
	err models.OAuthError,
	client models.Client,
) models.OAuthError {
	var oauthErr models.OAuthRedirectError
	if !errors.As(err, &oauthErr) {
		return err
	}

	redirectParams := models.RedirectParameters{
		Error:            oauthErr.ErrorCode,
		ErrorDescription: oauthErr.ErrorDescription,
		State:            oauthErr.State,
	}
	redirectResponse(ctx, client, oauthErr.AuthorizationParameters, redirectParams)
	return nil
}

func redirectResponse(
	ctx utils.Context,
	client models.Client,
	params models.AuthorizationParameters,
	redirectParams models.RedirectParameters,
) {

	if ctx.IssuerResponseParameterIsEnabled {
		redirectParams.Issuer = ctx.Host
	}

	responseMode := unit.GetResponseModeOrDefault(params.ResponseMode, params.ResponseType)
	if responseMode.IsJarm() || client.JarmSignatureAlgorithm != "" {
		redirectParams.Response = createJarmResponse(ctx, client, redirectParams)
	}

	redirectParamsMap := redirectParams.GetParams()
	switch responseMode {
	case constants.FragmentResponseMode, constants.FragmentJwtResponseMode:
		redirectUrl := unit.GetUrlWithFragmentParams(params.RedirectUri, redirectParamsMap)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	case constants.FormPostResponseMode, constants.FormPostJwtResponseMode:
		redirectParamsMap["redirect_uri"] = params.RedirectUri
		ctx.RequestContext.HTML(http.StatusOK, "internal_form_post.html", redirectParamsMap)
	default:
		redirectUrl := unit.GetUrlWithQueryParams(params.RedirectUri, redirectParamsMap)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	}
}

func createJarmResponse(
	ctx utils.Context,
	client models.Client,
	redirectParams models.RedirectParameters,
) string {
	jwk := ctx.GetJarmSignatureKey(client)
	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
	)

	claims := map[string]any{
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.AudienceClaim): client.Id,
		string(constants.IssuedAtClaim): createdAtTimestamp,
		string(constants.ExpiryClaim):   createdAtTimestamp + ctx.JarmLifetimeSecs,
	}
	for k, v := range redirectParams.GetParams() {
		claims[k] = v
	}
	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return response
}
