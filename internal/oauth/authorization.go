package oauth

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"time"

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

	if req.RequestUri != "" {
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
	// The session was already created by the client in the PAR endpoint.
	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	if err := validateRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateWithRequest(req)
	return session, nil
}

func initAuthnSessionWithJar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	jar, err := extractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateRequestWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSession(jar.AuthorizationParameters, client)
	session.UpdateWithRequest(req)
	return session, nil
}

func initSimpleAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {
	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequest(req)

	ctx.Logger.Info("initiating simple authorization request")
	if err := validateRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, convertError(err, req, client)
	}
	return models.NewSession(req.AuthorizationParameters, client), nil
}

//-------------------------------------------------------------- Validators --------------------------------------------------------------//

func validateRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) issues.OAuthError {
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	if session.IsPushedRequestExpired() {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri is expired")
	}

	return validateRequestWithDefaultValues(ctx, req, session.AuthorizationParameters, client)
}

func validateRequestWithJar(ctx utils.Context, req models.AuthorizationRequest, jar models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request is not allowed inside the request object")
	}

	if err := validateBaseRequestNonEmptyFields(jar.AuthorizationParameters, client); err != nil {
		return err
	}

	return validateRequestWithDefaultValues(ctx, req, jar.AuthorizationParameters, client)
}

func validateRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreRequest(ctx, req, client)
	default:
		return validateOAuthCoreRequest(ctx, req, client)
	}
}

func validateRequestWithDefaultValues(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreRequestWithDefaultValues(ctx, req, defaultValues, client)
	default:
		return validateOAuthCoreRequestWithDefaultValues(ctx, req, defaultValues, client)
	}
}

func validateOpenIdCoreRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if req.Scope == "" || !slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateOAuthCoreRequest(ctx, req, client)
}

func validateOAuthCoreRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) issues.OAuthError {

	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "response_type is required")
	}

	if client.PkceIsRequired && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}

	return validateBaseRequestNonEmptyFields(req.AuthorizationParameters, client)
}

func validateOpenIdCoreRequestWithDefaultValues(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if req.Scope == "" || !slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return validateOAuthCoreRequestWithDefaultValues(ctx, req, defaultValues, client)
}

func validateOAuthCoreRequestWithDefaultValues(ctx utils.Context, req models.AuthorizationRequest, defaultValues models.AuthorizationParameters, client models.Client) issues.OAuthError {

	if defaultValues.RedirectUri == "" && req.RedirectUri == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.RequestUri != "" && req.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}

	if defaultValues.ResponseType != "" && req.ResponseType != "" && defaultValues.ResponseType != req.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	responseType := defaultValues.ResponseType
	if responseType == "" {
		responseType = req.ResponseType
	}
	responseMode := defaultValues.ResponseMode
	if responseMode == "" {
		responseMode = req.ResponseMode
	}
	if responseType.IsImplict() && responseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if client.PkceIsRequired && defaultValues.CodeChallenge == "" && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "PKCE is required")
	}

	return validateBaseRequestNonEmptyFields(req.AuthorizationParameters, client)
}

func validateBaseRequestNonEmptyFields(req models.AuthorizationParameters, client models.Client) issues.OAuthError {

	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}

	if req.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	if req.ResponseType != "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}

	return nil
}

//--------------------------------------------------------- Helper Functions ---------------------------------------------------------//

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

func getDefaultProfileForAuthorizationRequest(req models.AuthorizationRequest) constants.Profile {
	if slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func getDefaultProfileForRequestWithSupportingSession(req models.AuthorizationRequest, session models.AuthnSession) constants.Profile {
	scope := fmt.Sprintf("%s %s", session.Scope, req.Scope)
	if slices.Contains(unit.SplitStringWithSpaces(scope), constants.OpenIdScope) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
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

func generateImplictParams(ctx utils.Context, session models.AuthnSession) (map[string]string, error) {
	grantModel, _ := ctx.GrantModelManager.Get(session.GrantModelId)
	implictParams := make(map[string]string)

	// Generate a token if the client requested it.
	if session.ResponseType.Contains(constants.TokenResponseResponse) {
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

func extractJarFromRequestObject(ctx utils.Context, reqObject string, client models.Client) (models.AuthorizationRequest, issues.OAuthError) {
	parsedToken, err := jwt.ParseSigned(reqObject, client.GetSigningAlgorithms())
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 0 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	keys := client.PublicJwks.Key(parsedToken.Headers[0].KeyID)
	if len(keys) == 0 {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid kid header")
	}

	jwk := keys[0]
	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request")
	}

	return jarReq, nil
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

func newRedirectErrorFromSession(errorCode constants.ErrorCode, errorDescription string, session models.AuthnSession) issues.OAuthError {
	return issues.NewOAuthRedirectError(errorCode, errorDescription, session.ClientId, session.RedirectUri, session.ResponseMode, session.State)
}

func convertError(oauthErr issues.OAuthError, req models.AuthorizationRequest, client models.Client) issues.OAuthError {
	if client.IsRedirectUriAllowed(req.RedirectUri) && (req.ResponseMode == "" || client.IsResponseModeAllowed(req.ResponseMode)) {
		return issues.NewOAuthRedirectError(oauthErr.GetCode(), oauthErr.Error(), req.ClientId, req.RedirectUri, req.ResponseMode, req.State)
	}

	return oauthErr
}

func convertErrorWithSession(oauthErr issues.OAuthError, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {

	redirectUri := session.RedirectUri
	if redirectUri == "" {
		redirectUri = req.RedirectUri
	}

	responseMode := session.ResponseMode
	if responseMode != "" {
		responseMode = req.ResponseMode
	}

	state := session.State
	if state != "" {
		state = req.State
	}

	if client.IsRedirectUriAllowed(redirectUri) && (req.ResponseMode == "" || client.IsResponseModeAllowed(responseMode)) {
		return issues.NewOAuthRedirectError(oauthErr.GetCode(), oauthErr.Error(), req.ClientId, redirectUri, responseMode, state)
	}

	return oauthErr
}

func shouldRedirectError(req models.AuthorizationRequest, client models.Client) bool {
	return client.IsRedirectUriAllowed(req.RedirectUri) && (req.ResponseMode == "" || client.IsResponseModeAllowed(req.ResponseMode))
}

func getClient(ctx utils.Context, req models.AuthorizationRequest) (models.Client, issues.OAuthError) {
	if req.ClientId == "" {
		return models.Client{}, issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return models.Client{}, issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	return client, nil
}
