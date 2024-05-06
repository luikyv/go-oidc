package oauth

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//---------------------------------------------------------- Authentication ----------------------------------------------------------//

func InitAuth(ctx utils.Context, req models.AuthorizationRequest) issues.OAuthError {
	if err := initAuth(ctx, req); err != nil {
		return handleAuthError(ctx, err)
	}
	return nil
}

func ContinueAuth(ctx utils.Context, callbackId string) issues.OAuthError {
	if err := continueAuth(ctx, callbackId); err != nil {
		return handleAuthError(ctx, err)
	}
	return nil
}

func initAuth(ctx utils.Context, req models.AuthorizationRequest) issues.OAuthError {

	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}

	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return newRedirectErrorFromSession(constants.InvalidRequest, "no policy available", session)
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.SetAuthnSteps(policy.StepIdSequence)
	session.Init()

	return authenticate(ctx, &session)
}

func continueAuth(ctx utils.Context, callbackId string) issues.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	return authenticate(ctx, &session)
}

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

//---------------------------------------------------------- Init Session ----------------------------------------------------------//

func initAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	if ctx.ParIsRequired || req.RequestUri != "" {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initAuthnSessionWithPar(ctx, req, client)
	}

	if req.RequestObject != "" {
		ctx.Logger.Info("initiating authorization request with JAR")
		return initAuthnSessionWithJar(ctx, req, client)
	}

	return initSimpleAuthnSession(ctx, req, client)
}

func initAuthnSessionWithPar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	session, err := getSessionCreatedWithPar(ctx, req)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	if err := validateAuthorizationRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func initAuthnSessionWithJar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	jar, err := extractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateAuthorizationRequestWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSession(jar.AuthorizationParameters, client)
	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func initSimpleAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	ctx.Logger.Info("initiating simple authorization request")
	if err := validateAuthorizationRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, err
	}
	return models.NewSession(req.AuthorizationParameters, client), nil
}

//--------------------------------------------------------- Helper Functions ---------------------------------------------------------//

func getClient(ctx utils.Context, req models.AuthorizationRequest) (models.Client, issues.OAuthError) {
	if req.ClientId == "" {
		return models.Client{}, issues.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return models.Client{}, issues.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	return client, nil
}

func getSessionCreatedWithPar(ctx utils.Context, req models.AuthorizationRequest) (models.AuthnSession, issues.OAuthError) {
	if req.RequestUri == "" {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "request_uri is required")
	}

	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	return session, nil
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

func generateImplictParams(ctx utils.Context, session models.AuthnSession) (map[string]string, error) {
	grantModel, _ := ctx.GrantModelManager.Get(session.GrantModelId)
	implictParams := make(map[string]string)

	// Generate a token if the client requested it.
	if session.ResponseType.Contains(constants.TokenResponse) {
		grantSession := grantModel.GenerateGrantSession(models.NewImplictGrantContext(session))
		err := ctx.GrantSessionManager.CreateOrUpdate(grantSession)
		if err != nil {
			return map[string]string{}, err
		}
		implictParams["access_token"] = grantSession.Token
		implictParams["token_type"] = string(constants.Bearer)
	}

	// Generate an ID token if the client requested it.
	if slices.Contains(unit.SplitStringWithSpaces(session.Scope), constants.OpenIdScope) && session.ResponseType.Contains(constants.IdTokenResponse) {
		implictParams["id_token"] = grantModel.GenerateIdToken(
			models.NewImplictGrantContextForIdToken(session, models.IdTokenContext{
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

func redirectResponse(ctx utils.Context, redirectResponse models.RedirectResponse) {

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

func createJarmResponse(ctx utils.Context, clientId string, params map[string]string) string {
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
		string(constants.ExpiryClaim):   createdAtTimestamp + constants.JarmResponseLifetimeSecs,
	}
	for k, v := range params {
		claims[k] = v
	}
	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return response
}

//--------------------------------------------------------- Error Handling ---------------------------------------------------------//

func handleAuthError(ctx utils.Context, err issues.OAuthError) issues.OAuthError {
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
}

func newRedirectErrorFromSession(
	errorCode constants.ErrorCode,
	errorDescription string,
	session models.AuthnSession,
) issues.OAuthError {
	return issues.NewOAuthRedirectError(errorCode, errorDescription, session.ClientId, session.RedirectUri, session.ResponseMode, session.State)
}

func convertErrorIfRedirectable(
	oauthErr issues.OAuthError,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	responseMode := unit.GetDefaultResponseMode(params.ResponseType, params.ResponseMode)
	if client.IsRedirectUriAllowed(params.RedirectUri) && client.IsResponseModeAllowed(responseMode) {
		return issues.NewOAuthRedirectError(oauthErr.GetCode(), oauthErr.Error(), client.Id, params.RedirectUri, responseMode, params.State)
	}

	return oauthErr
}

func convertErrorIfRedirectableWithPriorities(
	oauthErr issues.OAuthError,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	redirectUri := unit.GetNonEmptyOrDefault(prioritaryParams.RedirectUri, params.RedirectUri)
	responseType := unit.GetNonEmptyOrDefault(prioritaryParams.ResponseType, params.ResponseType)
	state := unit.GetNonEmptyOrDefault(prioritaryParams.State, params.State)
	responseMode := unit.GetNonEmptyOrDefault(prioritaryParams.ResponseMode, params.ResponseMode)
	responseMode = unit.GetDefaultResponseMode(responseType, responseMode)

	if client.IsRedirectUriAllowed(redirectUri) && client.IsResponseModeAllowed(responseMode) {
		return issues.NewOAuthRedirectError(oauthErr.GetCode(), oauthErr.Error(), client.Id, redirectUri, responseMode, state)
	}

	return oauthErr
}
