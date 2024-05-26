package authorize

import (
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func redirectError(
	ctx utils.Context,
	err issues.OAuthError,
	client models.Client,
) issues.OAuthError {
	var oauthErr issues.OAuthRedirectError
	if !errors.As(err, &oauthErr) {
		return err
	}

	params := map[string]string{
		"error":             string(oauthErr.GetCode()),
		"error_description": oauthErr.Error(),
	}
	if oauthErr.State != "" {
		params["state"] = oauthErr.State
	}

	redirectResponse(ctx, client, oauthErr.RedirectUri, oauthErr.ResponseMode, params)
	return nil
}

func redirectResponse(
	ctx utils.Context,
	client models.Client,
	redirectUri string,
	responseMode constants.ResponseMode,
	params map[string]string,
) {

	if ctx.IssuerResponseParameterIsEnabled {
		params[string(constants.IssuerClaim)] = ctx.Host
	}

	if responseMode.IsJarm() {
		params = map[string]string{
			"response": createJarmResponse(ctx, client, params),
		}
	}

	switch responseMode {
	case constants.FragmentResponseMode, constants.FragmentJwtResponseMode:
		redirectUrl := unit.GetUrlWithFragmentParams(redirectUri, params)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	case constants.FormPostResponseMode, constants.FormPostJwtResponseMode:
		params["redirect_uri"] = redirectUri
		ctx.RequestContext.HTML(http.StatusOK, "internal_form_post.html", params)
	default:
		redirectUrl := unit.GetUrlWithQueryParams(redirectUri, params)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	}
}

func createJarmResponse(
	ctx utils.Context,
	client models.Client,
	params map[string]string,
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
	for k, v := range params {
		claims[k] = v
	}
	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return response
}
