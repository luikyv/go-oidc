package authorize

import (
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func redirectResponse(ctx utils.Context, redirectResponse models.RedirectResponse) {

	if ctx.IssuerResponseParameterIsEnabled {
		redirectResponse.Parameters[string(constants.IssuerClaim)] = ctx.Host
	}

	if redirectResponse.ResponseMode.IsJarm() {
		redirectResponse.Parameters = map[string]string{
			"response": createJarmResponse(ctx, redirectResponse.ClientId, redirectResponse.Parameters),
		}
	}

	switch redirectResponse.ResponseMode {
	case constants.FragmentResponseMode, constants.FragmentJwtResponseMode:
		redirectUrl := unit.GetUrlWithFragmentParams(redirectResponse.RedirectUri, redirectResponse.Parameters)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	case constants.FormPostResponseMode, constants.FormPostJwtResponseMode:
		redirectResponse.Parameters["redirect_uri"] = redirectResponse.RedirectUri
		ctx.RequestContext.HTML(http.StatusOK, "internal_form_post.html", redirectResponse.Parameters)
	default:
		redirectUrl := unit.GetUrlWithQueryParams(redirectResponse.RedirectUri, redirectResponse.Parameters)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	}
}

func createJarmResponse(
	ctx utils.Context,
	clientId string,
	params map[string]string,
) string {
	jwk := ctx.GetJarmPrivateKey()
	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
	)

	claims := map[string]any{
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.AudienceClaim): clientId,
		string(constants.IssuedAtClaim): createdAtTimestamp,
		string(constants.ExpiryClaim):   createdAtTimestamp + ctx.JarmLifetimeSecs,
	}
	for k, v := range params {
		claims[k] = v
	}
	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return response
}
