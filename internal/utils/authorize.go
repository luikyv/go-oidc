package utils

// import (
// 	"errors"
// 	"log/slog"
// 	"maps"
// 	"net/http"
// 	"slices"
// 	"time"

// 	"github.com/go-jose/go-jose/v4"
// 	"github.com/go-jose/go-jose/v4/jwt"
// 	"github.com/luikymagno/auth-server/internal/issues"
// 	"github.com/luikymagno/auth-server/internal/models"
// 	"github.com/luikymagno/auth-server/internal/unit"
// 	"github.com/luikymagno/auth-server/internal/unit/constants"
// )

// func InitAuthentication(ctx Context, req models.AuthorizationRequest) error {
// 	if err := initAuthentication(ctx, req); err != nil {
// 		return handleAuthorizationError(ctx, err)
// 	}
// 	return nil
// }

// func initAuthentication(ctx Context, req models.AuthorizationRequest) error {
// 	if err := preValidateAuthorizationRequest(req); err != nil {
// 		return err
// 	}

// 	client, err := ctx.ClientManager.Get(req.ClientId)
// 	if err != nil {
// 		return issues.NewWrappingOAuthError(err, constants.InvalidRequest, "invalid client ID")
// 	}

// 	session, err := initValidAuthenticationSession(ctx, client, req)
// 	if err != nil {
// 		return err
// 	}

// 	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
// 	if !policyIsAvailable {
// 		ctx.Logger.Info("no policy available")
// 		return newRedirectOAuthErrorFromSession(session, constants.InvalidRequest, "no policy available")
// 	}

// 	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
// 	session.SetAuthnSteps(policy.StepIdSequence)

// 	return authenticate(ctx, &session)
// }

// func preValidateAuthorizationRequest(req models.AuthorizationRequest) error {
// 	if req.ClientId == "" {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid client ID")
// 	}

// 	return nil
// }

// func initValidAuthenticationSession(ctx Context, client models.Client, req models.AuthorizationRequest) (models.AuthnSession, error) {

// 	if req.RequestUri != "" {
// 		ctx.Logger.Info("initiating authorization request with PAR")
// 		return initValidAuthenticationSessionWithPar(ctx, req)
// 	}

// 	if req.RequestObject != "" {
// 		ctx.Logger.Info("initiating authorization request with JAR")
// 		return initValidAuthenticationSessionWithJar(ctx, client, req)
// 	}

// 	ctx.Logger.Info("initiating authorization request")
// 	if err := validateAuthorizationRequest(ctx, req, client); err != nil {
// 		return models.AuthnSession{}, err
// 	}
// 	return models.NewSessionFromAuthorizationRequest(req, client), nil

// }

// func initValidAuthenticationSessionWithPar(ctx Context, req models.AuthorizationRequest) (models.AuthnSession, error) {
// 	// The session was already created by the client in the PAR endpoint.
// 	// Fetch it using the request URI.
// 	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
// 	if err != nil {
// 		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
// 	}

// 	if err := validateAuthorizationRequestWithPar(req, session); err != nil {
// 		// If any of the parameters is invalid, we delete the session right away.
// 		ctx.AuthnSessionManager.Delete(session.Id)
// 		return models.AuthnSession{}, err
// 	}

// 	// FIXME: Treating the request_uri as one-time use will cause problems when the user refreshes the page.
// 	session.RequestUri = ""
// 	session.CallbackId = unit.GenerateCallbackId()
// 	return session, nil
// }

// func initValidAuthenticationSessionWithJar(ctx Context, client models.Client, req models.AuthorizationRequest) (models.AuthnSession, error) {

// 	jarReq, err := extractJarFromRequestObject(ctx, req, client)
// 	if err != nil {
// 		return models.AuthnSession{}, err
// 	}

// 	if err := validateAuthorizationRequestWithJar(ctx, req, jarReq, client); err != nil {
// 		return models.AuthnSession{}, err
// 	}

// 	return models.NewSessionFromAuthorizationRequest(req, client), nil

// }

// func validateAuthorizationRequestWithPar(req models.AuthorizationRequest, session models.AuthnSession) error {
// 	// If the request URI is passed, all the other parameters must be empty.
// 	if unit.AnyNonEmpty(req.RequestObject, req.RedirectUri, req.State, req.Scope, string(req.ResponseType), string(req.ResponseMode), req.CodeChallenge, string(req.CodeChallengeMethod)) {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter when using PAR")
// 	}

// 	if session.IsPushedRequestExpired() {
// 		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri expired")
// 	}

// 	// Make sure the client who created the PAR request is the same one trying to authorize.
// 	if session.ClientId != req.ClientId {
// 		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
// 	}

// 	return nil
// }

// func extractJarFromRequestObject(ctx Context, req models.AuthorizationRequest, client models.Client) (models.AuthorizationRequest, error) {
// 	parsedToken, err := jwt.ParseSigned(req.RequestObject, client.GetSigningAlgorithms())
// 	if err != nil {
// 		return models.AuthorizationRequest{}, err
// 	}

// 	// Verify that the assertion indicates the key ID.
// 	if len(parsedToken.Headers) != 0 && parsedToken.Headers[0].KeyID == "" {
// 		return models.AuthorizationRequest{}, errors.New("invalid kid header")
// 	}

// 	// Verify that the key ID belongs to the client.
// 	keys := client.PublicJwks.Key(parsedToken.Headers[0].KeyID)
// 	if len(keys) == 0 {
// 		return models.AuthorizationRequest{}, errors.New("invalid kid header")
// 	}

// 	jwk := keys[0]
// 	var claims jwt.Claims
// 	var jarReq models.AuthorizationRequest
// 	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
// 		return models.AuthorizationRequest{}, errors.New("invalid kid header")
// 	}

// 	err = claims.ValidateWithLeeway(jwt.Expected{
// 		Issuer:      req.ClientId,
// 		AnyAudience: []string{ctx.Host},
// 	}, time.Duration(0))
// 	if err != nil {
// 		return models.AuthorizationRequest{}, err
// 	}

// 	return jarReq, nil
// }

// func validateAuthorizationRequestWithJar(ctx Context, req models.AuthorizationRequest, jarReq models.AuthorizationRequest, client models.Client) error {

// 	if req.ClientId != jarReq.ClientId {
// 		return issues.NewOAuthError(constants.InvalidClient, "invalid client ID")
// 	}

// 	if err := validateAuthorizationRequest(ctx, jarReq, client); err != nil {
// 		return err
// 	}

// 	// https://datatracker.ietf.org/doc/rfc9101/.
// 	// "..."request" and "request_uri" parameters MUST NOT be included in Request Objects...."
// 	if unit.AnyNonEmpty(jarReq.RequestObject, jarReq.RequestUri) {
// 		return newRedirectErrorFromRequest(jarReq, client, constants.InvalidScope, "the JAR can neither contain the request nor the request_uri parameters")
// 	}

// 	if unit.AnyNonEmpty(req.RedirectUri, req.State, req.Scope, string(req.ResponseType), string(req.ResponseMode), req.CodeChallenge, string(req.CodeChallengeMethod), req.RequestUri) {
// 		return newRedirectErrorFromRequest(jarReq, client, constants.InvalidRequest, "The request cannot pass parameters outside the JAR")
// 	}

// 	return nil
// }

// func validateAuthorizationRequest(ctx Context, req models.AuthorizationRequest, client models.Client) error {

// 	profile := ctx.GetProfile(client, unit.SplitStringWithSpaces(req.Scope))

// 	var err error
// 	switch profile {
// 	case constants.OpenIdCoreProfile:
// 		err = validateOpenIdSpecificRulesForAuthorizationRequest(ctx, req, client)
// 	default:
// 		err = validateOAuthSpecificRulesAuthorizationRequest(ctx, req, client)
// 	}
// 	if err != nil {
// 		return err
// 	}

// 	if !client.IsResponseModeAllowed(req.ResponseMode) {
// 		return errors.New("response mode not allowed")
// 	}

// 	// Implict response types cannot be sent via query parameteres.
// 	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
// 		return errors.New("invalid response mode for the chosen response type")
// 	}

// 	// Validate PKCE parameters.
// 	if client.PkceIsRequired && req.CodeChallenge == "" {
// 		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "PKCE is required")
// 	}
// 	// The code challenge cannot be informed without the method and vice versa.
// 	if (req.CodeChallenge != "" && req.CodeChallengeMethod == "") || (req.CodeChallenge == "" && req.CodeChallengeMethod != "") {
// 		return errors.New("invalid parameters for PKCE")
// 	}

// 	return nil
// }

// func validateOAuthSpecificRulesAuthorizationRequest(_ Context, req models.AuthorizationRequest, client models.Client) error {
// 	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
// 	if req.RedirectUri == "" && len(client.RedirectUris) != 1 {
// 		return issues.NewOAuthError(constants.InvalidRequest, "the redirect_uri must be provided")
// 	}

// 	if !client.IsRedirectUriAllowed(req.RedirectUri) {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
// 	}

// 	if req.ResponseType.Contains(constants.IdTokenResponse) || !client.IsResponseTypeAllowed(req.ResponseType) {
// 		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "response type not allowed")
// 	}

// 	return nil
// }

// func validateOpenIdSpecificRulesForAuthorizationRequest(_ Context, req models.AuthorizationRequest, client models.Client) error {

// 	if !client.IsRedirectUriAllowed(req.RedirectUri) {
// 		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
// 	}

// 	scopes := unit.SplitStringWithSpaces(req.Scope)
// 	if !slices.Contains(scopes, constants.OpenIdScope) || !client.AreScopesAllowed(scopes) {
// 		return newRedirectErrorFromRequest(req, client, constants.InvalidScope, "invalid scope")
// 	}

// 	if !client.IsResponseTypeAllowed(req.ResponseType) {
// 		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "response type not allowed")
// 	}

// 	return nil
// }

// func ContinueAuthentication(ctx Context, callbackId string) error {
// 	if err := continueAuthentication(ctx, callbackId); err != nil {
// 		return handleAuthorizationError(ctx, err)
// 	}
// 	return nil
// }

// func continueAuthentication(ctx Context, callbackId string) error {

// 	// Fetch the session using the callback ID.
// 	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
// 	if err != nil {
// 		return err
// 	}

// 	return authenticate(ctx, &session)
// }

// // Execute the authentication steps.
// func authenticate(ctx Context, session *models.AuthnSession) error {

// 	status := constants.Success
// 	var err error
// 	for status == constants.Success && len(session.StepIdsLeft) > 0 {
// 		currentStep := GetStep(session.StepIdsLeft[0])
// 		status, err = currentStep.AuthnFunc(ctx, session)

// 		if status == constants.Success {
// 			// If the step finished with success, it can be removed from the remaining ones.
// 			session.SetAuthnSteps(session.StepIdsLeft[1:])
// 		}
// 	}

// 	if status == constants.Failure {
// 		ctx.AuthnSessionManager.Delete(session.Id)
// 		return newRedirectOAuthErrorFromSession(*session, constants.AccessDenied, err.Error())
// 	}

// 	if status == constants.InProgress {
// 		return ctx.AuthnSessionManager.CreateOrUpdate(*session)
// 	}

// 	// At this point, the status can only be success and there are no more steps left.
// 	finishFlowSuccessfully(ctx, session)
// 	if !session.ResponseType.Contains(constants.CodeResponse) {
// 		// The client didn't request an authorization code to later exchange it for an access token,
// 		// so we don't keep the session anymore.
// 		return ctx.AuthnSessionManager.Delete(session.Id)
// 	}
// 	return ctx.AuthnSessionManager.CreateOrUpdate(*session)
// }

// func finishFlowSuccessfully(ctx Context, session *models.AuthnSession) {

// 	params := make(map[string]string)

// 	// Generate the authorization code if the client requested it.
// 	if session.ResponseType.Contains(constants.CodeResponse) {
// 		session.InitAuthorizationCode()
// 		params[string(constants.CodeResponse)] = session.AuthorizationCode
// 	}

// 	// Add implict parameters.
// 	if session.ResponseType.IsImplict() {
// 		implictParams, _ := generateImplictParams(ctx, *session)
// 		maps.Copy(params, implictParams)
// 	}

// 	// Echo the state parameter.
// 	if session.State != "" {
// 		params["state"] = session.State
// 	}

// 	redirectResponse(ctx, models.NewRedirectResponseFromSession(*session, params))
// }

// func generateImplictParams(ctx Context, session models.AuthnSession) (map[string]string, error) {
// 	grantModel, _ := ctx.GrantModelManager.Get(session.GrantModelId)
// 	implictParams := make(map[string]string)

// 	// Generate a token if the client requested it.
// 	if session.ResponseType.Contains(constants.TokenResponseResponse) {
// 		grantSession := grantModel.GenerateGrantSession(models.NewImplictGrantContext(session))
// 		err := ctx.GrantSessionManager.CreateOrUpdate(grantSession)
// 		if err != nil {
// 			return map[string]string{}, err
// 		}
// 		implictParams["access_token"] = grantSession.Token
// 		implictParams["token_type"] = string(constants.Bearer)
// 	}

// 	// Generate an ID token if the client requested it.
// 	if session.ResponseType.Contains(constants.IdTokenResponse) {
// 		implictParams["id_token"] = grantModel.GenerateIdToken(
// 			models.NewImplictGrantContextForIdToken(session, models.IdTokenContext{
// 				AccessToken:             implictParams["access_token"],
// 				AuthorizationCode:       session.AuthorizationCode,
// 				State:                   session.State,
// 				Nonce:                   session.Nonce,
// 				AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
// 			}),
// 		)
// 	}

// 	return implictParams, nil
// }

// func handleAuthorizationError(ctx Context, err error) error {
// 	var redirectErr issues.OAuthRedirectError
// 	if !errors.As(err, &redirectErr) {
// 		return err
// 	}

// 	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
// 	return nil
// }

// func redirectResponse(ctx Context, redirectResponse models.RedirectResponse) {

// 	// If either an empty or the "jwt" response modes are passed, we must find the default value based on the response type.
// 	if redirectResponse.ResponseMode == "" {
// 		redirectResponse.ResponseMode = getDefaultResponseMode(redirectResponse.ResponseType)
// 	}
// 	if redirectResponse.ResponseMode == constants.JwtResponseMode {
// 		redirectResponse.ResponseMode = getDefaultJarmResponseMode(redirectResponse.ResponseType)
// 	}

// 	if redirectResponse.ResponseMode.IsJarm() {
// 		redirectResponse.Parameters = map[string]string{
// 			"response": createJarmResponse(ctx, redirectResponse.ClientId, redirectResponse.Parameters),
// 		}
// 	}

// 	// TODO https://openid.net/specs/openid-connect-core-1_0.html#AuthError
// 	// "...If the Response Mode value is not supported, the Authorization Server returns an HTTP response code of 400 (Bad Request) without Error Response parameters, since understanding the Response Mode is necessary to know how to return those parameters...."
// 	switch redirectResponse.ResponseMode {
// 	case constants.FragmentResponseMode, constants.FragmentJwtResponseMode:
// 		redirectUrl := unit.GetUrlWithFragmentParams(redirectResponse.RedirectUri, redirectResponse.Parameters)
// 		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
// 	case constants.FormPostResponseMode, constants.FormPostJwtResponseMode:
// 		redirectResponse.Parameters["redirect_uri"] = redirectResponse.RedirectUri
// 		ctx.RequestContext.HTML(http.StatusOK, "internal_form_post.html", redirectResponse.Parameters)
// 	default:
// 		redirectUrl := unit.GetUrlWithQueryParams(redirectResponse.RedirectUri, redirectResponse.Parameters)
// 		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
// 	}
// }

// func createJarmResponse(ctx Context, clientId string, params map[string]string) string {
// 	jwk := ctx.GetJarmPrivateKey()
// 	createdAtTimestamp := unit.GetTimestampNow()
// 	signer, _ := jose.NewSigner(
// 		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
// 		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
// 	)

// 	claims := map[string]any{
// 		string(constants.IssuerClaim):   ctx.Host,
// 		string(constants.AudienceClaim): clientId,
// 		string(constants.IssuedAtClaim): createdAtTimestamp,
// 		string(constants.ExpiryClaim):   createdAtTimestamp + constants.JarmResponseLifetimeSecs,
// 	}
// 	for k, v := range params {
// 		claims[k] = v
// 	}
// 	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

// 	return response
// }

// func getDefaultResponseMode(responseType constants.ResponseType) constants.ResponseMode {
// 	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html.
// 	if responseType.IsImplict() {
// 		return constants.FragmentResponseMode
// 	}

// 	return constants.QueryResponseMode
// }

// func getDefaultJarmResponseMode(responseType constants.ResponseType) constants.ResponseMode {
// 	defaultResponseMode := getDefaultResponseMode(responseType)
// 	return constants.ResponseMode(string(defaultResponseMode) + "." + string(constants.JwtResponseMode))
// }

// func newRedirectOAuthErrorFromSession(session models.AuthnSession, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {
// 	return issues.OAuthRedirectError{
// 		OAuthBaseError: issues.NewOAuthError(errorCode, errorDescription),
// 		ClientId:       session.ClientId,
// 		RedirectUri:    session.RedirectUri,
// 		ResponseType:   session.ResponseType,
// 		ResponseMode:   session.ResponseMode,
// 		State:          session.State,
// 	}
// }

// func newRedirectErrorFromRequest(req models.AuthorizationRequest, client models.Client, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {

// 	redirectUri := req.RedirectUri
// 	if redirectUri == "" {
// 		redirectUri = client.RedirectUris[0]
// 	}
// 	return issues.OAuthRedirectError{
// 		OAuthBaseError: issues.NewOAuthError(errorCode, errorDescription),
// 		ClientId:       client.Id,
// 		RedirectUri:    redirectUri,
// 		ResponseType:   req.ResponseType,
// 		ResponseMode:   req.ResponseMode,
// 		State:          req.State,
// 	}
// }
