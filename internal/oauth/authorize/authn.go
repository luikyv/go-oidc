package authorize

import (
	"maps"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func authenticate(ctx utils.Context, session *models.AuthnSession) issues.OAuthError {

	status := constants.Success
	var err error
	for status == constants.Success && len(session.StepIdsLeft) > 0 {
		currentStep := utils.GetStep(session.StepIdsLeft[0])
		status, err = currentStep.AuthnFunc(ctx, session)

		if status == constants.Success {
			// If the step finished with success, it can be removed from the remaining ones.
			session.SetAuthnSteps(session.StepIdsLeft[1:])
		}
	}

	if status == constants.Failure {
		ctx.AuthnSessionManager.Delete(session.Id)
		return newRedirectErrorFromSession(constants.AccessDenied, err.Error(), *session)
	}

	if status == constants.InProgress {
		ctx.AuthnSessionManager.CreateOrUpdate(*session)
		return nil
	}

	// At this point, the status can only be success and there are no more steps left.
	finishFlowSuccessfully(ctx, session)
	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		ctx.AuthnSessionManager.Delete(session.Id)
	}

	ctx.AuthnSessionManager.CreateOrUpdate(*session)
	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) {

	params := make(map[string]string)

	// Generate the authorization code if the client requested it.
	if session.ResponseType.Contains(constants.CodeResponse) {
		session.InitAuthorizationCode()
		params[string(constants.CodeResponse)] = session.AuthorizationCode
	}

	// Add implict parameters.
	if session.ResponseType.IsImplict() {
		implictParams, _ := generateImplictParams(ctx, *session)
		maps.Copy(params, implictParams)
	}

	// Echo the state parameter.
	if session.State != "" {
		params["state"] = session.State
	}

	redirectResponse(ctx, models.NewRedirectResponseFromSession(*session, params))
}

func generateImplictParams(
	ctx utils.Context,
	session models.AuthnSession,
) (
	map[string]string,
	error,
) {
	grantModel, _ := ctx.GrantModelManager.Get(session.GrantModelId)
	implictParams := make(map[string]string)

	// Generate a token if the client requested it.
	if session.ResponseType.Contains(constants.TokenResponse) {
		grantSession := grantModel.GenerateGrantSession(models.NewImplictGrantOptions(session))
		err := ctx.GrantSessionManager.CreateOrUpdate(grantSession)
		if err != nil {
			return map[string]string{}, err
		}
		implictParams["access_token"] = grantSession.Token
		implictParams["token_type"] = string(constants.BearerTokenType)
	}

	// Generate an ID token if the client requested it.
	if unit.ScopeContainsOpenId(session.Scope) && session.ResponseType.Contains(constants.IdTokenResponse) {
		implictParams["id_token"] = grantModel.GenerateIdToken(
			models.NewImplictGrantOptionsForIdToken(session, models.IdTokenOptions{
				AccessToken:             implictParams["access_token"],
				AuthorizationCode:       session.AuthorizationCode,
				State:                   session.State,
				Nonce:                   session.Nonce,
				AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
			}),
		)
	}

	return implictParams, nil
}
