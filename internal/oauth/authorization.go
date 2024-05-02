package oauth

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func InitAuthentication(ctx utils.Context, req models.AuthorizationRequest) error {
	if err := initAuthentication(ctx, req); err != nil {
		return handleAuthorizationError(ctx, err)
	}
	return nil
}

func ContinueAuthentication(ctx utils.Context, callbackId string) error {
	if err := continueAuthentication(ctx, callbackId); err != nil {
		return handleAuthorizationError(ctx, err)
	}
	return nil
}

//---------------------------------------- Init Authentication ----------------------------------------//

func initAuthentication(ctx utils.Context, req models.AuthorizationRequest) error {
	if req.ClientId == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client ID")
	}
	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client ID")
	}

	session, err := initAuthnSession(ctx, client, req)
	if err != nil {
		return err
	}

	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return newRedirectErrorFromSession(ctx, constants.InvalidRequest, "no policy available", session)
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.SetAuthnSteps(policy.StepIdSequence)

	return authenticate(ctx, &session)
}

func initAuthnSession(ctx utils.Context, client models.Client, req models.AuthorizationRequest) (models.AuthnSession, error) {

	if req.RequestUri != "" {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initAuthnSessionWithPar(ctx, req, client)
	}

	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequest(req)

	ctx.Logger.Info("initiating authorization request")
	if err := validateSimpleAuthorizationRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, err
	}
	return models.NewSessionForAuthorizationRequest(req, client), nil

}

func getDefaultProfileForAuthorizationRequest(req models.AuthorizationRequest) constants.Profile {
	if slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) || req.ResponseType.Contains(constants.IdTokenResponse) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func initAuthnSessionWithPar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	// The session was already created by the client in the PAR endpoint.
	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequestWithPar(req, session)

	if err := validateAuthorizationRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateAfterPar(req)
	return session, nil
}

func getDefaultProfileForAuthorizationRequestWithPar(req models.AuthorizationRequest, session models.AuthnSession) constants.Profile {
	// We cannot prioritize the scopes passed during par or authorize in order to choose the profile.
	// Then, we'll choose the profile based on all available scopes.
	scopes := slices.Concat(session.Scopes, unit.SplitStringWithSpaces(req.Scope))
	if slices.Contains(scopes, constants.OpenIdScope) || session.ResponseType.Contains(constants.IdTokenResponse) || req.ResponseType.Contains(constants.IdTokenResponse) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func getProfileForAuthorizationRequest(req models.AuthorizationRequest, session models.AuthnSession) constants.Profile {
	// We cannot prioritize the scopes passed during par or authorize in order to choose the profile.
	// Then, we'll choose the profile based on all available scopes.
	scopes := slices.Concat(session.Scopes, unit.SplitStringWithSpaces(req.Scope))
	if slices.Contains(scopes, constants.OpenIdScope) || session.ResponseType.Contains(constants.IdTokenResponse) || req.ResponseType.Contains(constants.IdTokenResponse) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

//---------------------------------------- Validations ----------------------------------------//

func validateAuthorizationRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreAuthorizationRequestWithPar(ctx, req, session, client)
	default:
		return validateOAuthCoreAuthorizationRequestWithPar(ctx, req, session, client)
	}
}

func validateOpenIdCoreAuthorizationRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {

	// redirect_uri is required.
	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if err := validateOAuthCoreAuthorizationRequestWithPar(ctx, req, session, client); err != nil {
		return err
	}

	// response_type is required.
	if req.ResponseType != "" {
		return newRedirectErrorForRequest(constants.InvalidRequest, "invalid response_type", req, client)
	}

	// scope is required and must contain openid.
	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return newRedirectErrorForRequest(constants.InvalidScope, "invalid scope", req, client)
	}

	return nil
}

func validateOAuthCoreAuthorizationRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	// Make sure the client which created the PAR request is the same one trying to authorize.
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	// If informed, redirect_uri must be valid.
	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	// If the client has multiple redirect_uri's, it must inform one during par or authorize.
	if session.RedirectUri == "" && req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri must be provided")
	}

	// If the response mode was informed, it must be valid.
	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "response_mode not supported")
	}

	// The client must have access to all the requested response types.
	if req.ResponseType != "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "response type not allowed", req, session, client)
	}

	// response_type is mandatory. It must be passed during par or authorize.
	if session.ResponseType == "" && req.ResponseType == "" {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "invalid response_type", req, session, client)
	}

	// Implict response types cannot be sent via query parameteres.
	if (session.ResponseType.IsImplict() || req.ResponseType.IsImplict()) && (session.ResponseMode.IsQuery() || req.ResponseMode.IsQuery()) {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "invalid response_mode for the chosen response_type", req, session, client)
	}

	scopes := unit.SplitStringWithSpaces(req.Scope)
	// scope is optional, but if informed, the client must have access to all requested scopes.
	if !client.AreScopesAllowed(scopes) {
		return newRedirectErrorForRequestWithPar(constants.InvalidScope, "invalid scopes", req, session, client)
	}

	// If PKCE is required, the client must inform the code_challenge either during par or authorize.
	if client.PkceIsRequired && session.CodeChallenge == "" && req.CodeChallenge == "" {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "PKCE is required", req, session, client)
	}

	// If informed, the code_challenge_method must be valid.
	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "invalid code_challenge_method", req, session, client)
	}

	if session.IsPushedRequestExpired() {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "the request_uri is expired", req, session, client)
	}

	if req.Request != "" {
		return newRedirectErrorForRequestWithPar(constants.InvalidRequest, "request is not allowed", req, session, client)
	}

	return nil
}

func validateSimpleAuthorizationRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreSimpleAuthorizationRequest(ctx, req, client)
	default:
		return validateOAuthCoreSimpleAuthorizationRequest(ctx, req, client)
	}
}

func validateOpenIdCoreSimpleAuthorizationRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// redirect_uri is required.
	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	if err := validateOAuthCoreSimpleAuthorizationRequest(ctx, req, client); err != nil {
		return err
	}

	// scope is required and must contain openid.
	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return newRedirectErrorForRequest(constants.InvalidScope, "invalid scope", req, client)
	}

	return nil
}

func validateOAuthCoreSimpleAuthorizationRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// If informed, the redirect_uri must be valid.
	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	// If the client has multiple redirect_uri's, it must inform one.
	if req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri must be provided")
	}

	// If the response mode was informed, it must be valid.
	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "response_mode not supported")
	}

	// The client must have access to all the requested response types.
	if !client.IsResponseTypeAllowed(req.ResponseType) {
		return newRedirectErrorForRequest(constants.InvalidRequest, "response type not allowed", req, client)
	}

	// Implict response types cannot be sent via query parameteres.
	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return errors.New("invalid response mode for the chosen response type")
	}

	// scope is optional, but if informed, the client must have access to all requested scopes.
	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return newRedirectErrorForRequest(constants.InvalidScope, "invalid scope", req, client)
	}

	// The code challenge must be informed when PKCE required.
	if client.PkceIsRequired && req.CodeChallenge == "" {
		return newRedirectErrorForRequest(constants.InvalidRequest, "PKCE is required", req, client)
	}

	// If informed, the code_challenge_method must be valid.
	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return newRedirectErrorForRequest(constants.InvalidRequest, "invalid code_challenge_method", req, client)
	}

	return nil
}

//---------------------------------------- Authentication ----------------------------------------//

func continueAuthentication(ctx utils.Context, callbackId string) error {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return err
	}

	return authenticate(ctx, &session)
}

func authenticate(ctx utils.Context, session *models.AuthnSession) error {

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
		return newRedirectErrorFromSession(ctx, constants.AccessDenied, err.Error(), *session)
	}

	if status == constants.InProgress {
		return ctx.AuthnSessionManager.CreateOrUpdate(*session)
	}

	// At this point, the status can only be success and there are no more steps left.
	finishFlowSuccessfully(ctx, session)
	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		return ctx.AuthnSessionManager.Delete(session.Id)
	}
	return ctx.AuthnSessionManager.CreateOrUpdate(*session)
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
	if session.ResponseType.Contains(constants.IdTokenResponse) {
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

//---------------------------------------- Redirect Response ----------------------------------------//

func handleAuthorizationError(ctx utils.Context, err error) error {
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
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

func newRedirectErrorForRequestWithPar(errorCode constants.ErrorCode, errorDescription string, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) issues.OAuthRedirectError {
	redirectUri := session.RedirectUri
	if redirectUri == "" {
		redirectUri = req.RedirectUri
	}
	if redirectUri == "" {
		redirectUri = client.RedirectUris[0]
	}

	responseMode := session.ResponseMode
	if responseMode != "" {
		responseMode = req.ResponseMode
	}

	state := session.State
	if state != "" {
		state = req.State
	}

	return issues.NewOAuthRedirectErrorFrom(errorCode, errorDescription, session.ClientId, redirectUri, responseMode, state)
}

func newRedirectErrorForRequest(errorCode constants.ErrorCode, errorDescription string, req models.AuthorizationRequest, client models.Client) issues.OAuthRedirectError {
	redirectUri := req.RedirectUri
	if redirectUri == "" {
		redirectUri = client.RedirectUris[0]
	}
	return issues.NewOAuthRedirectErrorFrom(errorCode, errorDescription, client.Id, redirectUri, req.ResponseMode, req.State)
}

func newRedirectErrorFromSession(ctx utils.Context, errorCode constants.ErrorCode, errorDescription string, session models.AuthnSession) issues.OAuthRedirectError {
	redirectUri := session.RedirectUri
	if redirectUri == "" {
		client, _ := ctx.ClientManager.Get(session.ClientId)
		redirectUri = client.RedirectUris[0]
	}
	return issues.NewOAuthRedirectErrorFrom(errorCode, errorDescription, session.ClientId, redirectUri, session.ResponseMode, session.State)
}

//---------------------------------------- Helper Functions ----------------------------------------//

func extractJarFromRequestObject(ctx utils.Context, req models.BaseAuthorizationRequest, client models.Client) (models.AuthorizationRequest, error) {
	parsedToken, err := jwt.ParseSigned(req.Request, client.GetSigningAlgorithms())
	if err != nil {
		return models.AuthorizationRequest{}, err
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 0 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, errors.New("invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	keys := client.PublicJwks.Key(parsedToken.Headers[0].KeyID)
	if len(keys) == 0 {
		return models.AuthorizationRequest{}, errors.New("invalid kid header")
	}

	jwk := keys[0]
	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, errors.New("invalid kid header")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, err
	}

	return jarReq, nil
}
