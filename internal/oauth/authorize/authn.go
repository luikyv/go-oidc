package authorize

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func authenticate(ctx utils.Context, session *models.AuthnSession) models.OAuthError {
	policy := ctx.GetPolicyById(session.PolicyId)
	status := constants.Success
	// The loop breaks when the status is no longer sucess OR there are no more steps left.
	for status == constants.Success && session.AuthnSequenceIndex < len(policy.AuthnSequence) {
		currentAuthnFunc := policy.AuthnSequence[session.AuthnSequenceIndex]
		status = currentAuthnFunc(ctx, session)

		if status == constants.Success {
			// If the step finished with success, we can move to the next one.
			session.AuthnSequenceIndex++
		}
	}

	if status == constants.Failure {
		return finishFlowWithFailure(ctx, session)
	}

	if status == constants.InProgress {
		return stopFlowInProgress(ctx, session)
	}

	// At this point, the status can only be success and there are no more steps left.
	return finishFlowSuccessfully(ctx, session)
}

func finishFlowWithFailure(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if err := ctx.AuthnSessionManager.Delete(session.Id); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return session.NewRedirectError(constants.AccessDenied, "access_denied")
}

func stopFlowInProgress(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) models.OAuthError {

	client, err := ctx.ClientManager.Get(session.ClientId)
	if err != nil {
		return session.NewRedirectError(constants.InternalError, err.Error())
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return err
	}

	redirectParams := models.RedirectParameters{
		AuthorizationCode: session.AuthorizationCode,
		State:             session.State,
	}
	if session.ResponseType.Contains(constants.TokenResponse) {
		grantOptions := newImplicitGrantOptions(ctx, client, *session)
		token := utils.MakeToken(ctx, client, grantOptions)
		redirectParams.AccessToken = token.Value
		redirectParams.TokenType = token.Type
		if err := generateImplicitGrantSession(ctx, token, grantOptions); err != nil {
			return err
		}
	}

	if session.ResponseType.Contains(constants.IdTokenResponse) {
		idTokenOptions := session.GetIdTokenOptions()
		idTokenOptions.AccessToken = redirectParams.AccessToken
		idTokenOptions.AuthorizationCode = session.AuthorizationCode
		idTokenOptions.State = session.State
		redirectParams.IdToken = utils.MakeIdToken(ctx, client, models.GrantOptions{
			GrantType:      constants.ImplicitGrant,
			Subject:        session.Subject,
			ClientId:       session.ClientId,
			IdTokenOptions: idTokenOptions,
		})
	}

	redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
	return nil
}

func authorizeAuthnSession(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		if err := ctx.AuthnSessionManager.Delete(session.Id); err != nil {
			return models.NewOAuthError(constants.InternalError, err.Error())
		}
	}

	session.InitAuthorizationCode()
	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func shouldGenerateImplicitGrantSession(_ utils.Context, grantOptions models.GrantOptions) bool {
	return grantOptions.TokenFormat == constants.OpaqueTokenFormat ||
		unit.ScopesContainsOpenId(grantOptions.GrantedScopes)
}

func generateImplicitGrantSession(
	ctx utils.Context,
	token models.Token,
	grantOptions models.GrantOptions,
) models.OAuthError {
	if !shouldGenerateImplicitGrantSession(ctx, grantOptions) {
		return nil
	}

	grantSession := models.NewGrantSession(grantOptions, token)
	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func newImplicitGrantOptions(ctx utils.Context, client models.Client, session models.AuthnSession) models.GrantOptions {
	tokenOptions := ctx.GetTokenOptions(client, session.Scopes)
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:      constants.ImplicitGrant,
		GrantedScopes:  session.GrantedScopes,
		Subject:        session.Subject,
		ClientId:       session.ClientId,
		TokenOptions:   tokenOptions,
		IdTokenOptions: session.GetIdTokenOptions(),
	}
}
