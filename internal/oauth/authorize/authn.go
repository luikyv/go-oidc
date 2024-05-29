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
	var err error
	for status == constants.Success && session.AuthnSequenceIndex < len(policy.AuthnSequence) {
		currentAuthnFunc := policy.AuthnSequence[session.AuthnSequenceIndex]
		status, err = currentAuthnFunc(ctx, session)

		if status == constants.Success {
			// If the step finished with success, we can move to the next one.
			session.AuthnSequenceIndex++
		}
	}

	if status == constants.Failure {
		ctx.AuthnSessionManager.Delete(session.Id)
		return session.NewRedirectError(constants.AccessDenied, err.Error())
	}

	if status == constants.InProgress {
		ctx.AuthnSessionManager.CreateOrUpdate(*session)
		return nil
	}

	// At this point, the status can only be success and there are no more steps left.
	if err := finishFlowSuccessfully(ctx, session); err != nil {
		return err
	}

	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		ctx.AuthnSessionManager.Delete(session.Id)
	}

	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}
	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) models.OAuthError {
	redirectParams := models.RedirectParameters{
		State: session.State,
	}
	client, err := ctx.ClientManager.Get(session.ClientId)
	if err != nil {
		return session.NewRedirectError(constants.InternalError, err.Error())
	}

	if session.ResponseType.Contains(constants.CodeResponse) {
		redirectParams.AuthorizationCode = session.InitAuthorizationCode()
	}

	if session.ResponseType.Contains(constants.TokenResponse) {
		addImplicitToken(ctx, client, *session, &redirectParams)
	}

	if session.ResponseType.Contains(constants.IdTokenResponse) {
		addImplicitIdToken(ctx, client, *session, &redirectParams)
	}

	redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
	return nil
}

func addImplicitIdToken(
	ctx utils.Context,
	client models.Client,
	session models.AuthnSession,
	redirectParams *models.RedirectParameters,
) {
	redirectParams.IdToken = utils.MakeIdToken(ctx, client, models.GrantOptions{
		GrantType: constants.ImplicitGrant,
		Subject:   session.Subject,
		ClientId:  session.ClientId,
		IdTokenOptions: models.IdTokenOptions{
			AccessToken:             redirectParams.AccessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	})
}

func addImplicitToken(
	ctx utils.Context,
	client models.Client,
	session models.AuthnSession,
	redirectParams *models.RedirectParameters,
) models.OAuthError {
	grantOptions := newImplicitGrantOptions(ctx, client, session)
	token := utils.MakeToken(ctx, client, grantOptions)
	redirectParams.AccessToken = token.Value
	redirectParams.TokenType = token.Type

	if !shouldGenerateImplicitGrantSession(ctx, grantOptions) {
		return nil
	}

	_, err := generateImplicitGrantSession(ctx, token, grantOptions)
	return err
}

func shouldGenerateImplicitGrantSession(_ utils.Context, grantOptions models.GrantOptions) bool {
	return grantOptions.TokenFormat == constants.OpaqueTokenFormat || unit.ScopesContainsOpenId(grantOptions.Scopes)
}

func generateImplicitGrantSession(
	ctx utils.Context,
	token models.Token,
	grantOptions models.GrantOptions,
) (models.GrantSession, models.OAuthError) {
	grantSession := models.NewGrantSession(grantOptions, token)
	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		return models.GrantSession{}, models.NewOAuthError(constants.InternalError, err.Error())
	}

	return grantSession, nil
}

func newImplicitGrantOptions(ctx utils.Context, client models.Client, session models.AuthnSession) models.GrantOptions {
	tokenOptions := ctx.GetTokenOptions(client, session.Scopes)
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:    constants.ImplicitGrant,
		Scopes:       session.GrantedScopes,
		Subject:      session.Subject,
		ClientId:     session.ClientId,
		TokenOptions: tokenOptions,
		IdTokenOptions: models.IdTokenOptions{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}
