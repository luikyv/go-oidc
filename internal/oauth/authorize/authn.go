package authorize

import (
	"github.com/luikymagno/auth-server/internal/models"
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

	ctx.AuthnSessionManager.CreateOrUpdate(*session)
	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) models.OAuthError {
	client, err := ctx.ClientManager.Get(session.ClientId)
	if err != nil {
		return session.NewRedirectError(constants.InternalError, "could not load the client")
	}

	params := make(map[string]string)

	if session.ResponseType.Contains(constants.CodeResponse) {
		params["code"] = session.InitAuthorizationCode()
	}

	if session.ResponseType.Contains(constants.TokenResponse) {
		grantSession := utils.GenerateGrantSession(ctx, client, NewImplicitGrantOptions(ctx, *session))
		params["access_token"] = grantSession.Token
		params["token_type"] = string(grantSession.TokenType)
	}

	if session.ResponseType.Contains(constants.IdTokenResponse) {
		// TODO: Do I need to create the id token again?
		params["id_token"] = utils.MakeIdToken(ctx, client, models.GrantOptions{
			GrantType: constants.ImplicitGrant,
			Subject:   session.Subject,
			ClientId:  session.ClientId,
			IdTokenOptions: models.IdTokenOptions{
				AccessToken:             params["access_token"],
				AuthorizationCode:       session.AuthorizationCode,
				State:                   session.State,
				Nonce:                   session.Nonce,
				AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
			},
		})

	}

	// Echo the state parameter.
	if session.State != "" {
		params["state"] = session.State
	}

	redirectResponse(ctx, client, session.AuthorizationParameters, params)
	return nil
}

func NewImplicitGrantOptions(ctx utils.Context, session models.AuthnSession) models.GrantOptions {
	tokenOptions := ctx.GetTokenOptions(session.ClientAttributes, session.Scopes)
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:    constants.ImplicitGrant,
		Scopes:       session.Scopes,
		Subject:      session.Subject,
		ClientId:     session.ClientId,
		TokenOptions: tokenOptions,
		IdTokenOptions: models.IdTokenOptions{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}
