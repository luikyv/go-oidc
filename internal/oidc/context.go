package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Context struct {
	Response http.ResponseWriter
	Request  *http.Request
	context  context.Context
	*Configuration
}

func NewHTTPContext(w http.ResponseWriter, r *http.Request, config *Configuration) Context {
	return Context{
		Configuration: config,
		Response:      w,
		Request:       r,
	}
}

func NewContext(ctx context.Context, config *Configuration) Context {
	return Context{
		Configuration: config,
		context:       ctx,
	}
}

func Handler(config *Configuration, exec func(ctx Context)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exec(NewHTTPContext(w, r, config))
	}
}

func (ctx Context) TokenAuthnSigAlgs() []goidc.SignatureAlgorithm {
	return ctx.clientAuthnSigAlgs(ctx.TokenAuthnMethods)
}

func (ctx Context) IsClientAllowedTokenIntrospection(c *goidc.Client, info goidc.TokenInfo) bool {
	if ctx.IsClientAllowedTokenIntrospectionFunc == nil {
		return false
	}

	return ctx.IsClientAllowedTokenIntrospectionFunc(c, info)
}

func (ctx Context) TokenIntrospectionAuthnSigAlgs() []goidc.SignatureAlgorithm {
	return ctx.clientAuthnSigAlgs(ctx.TokenIntrospectionAuthnMethods)
}

func (ctx Context) IsClientAllowedTokenRevocation(c *goidc.Client) bool {
	if ctx.IsClientAllowedTokenRevocationFunc == nil {
		return false
	}

	return ctx.IsClientAllowedTokenRevocationFunc(c)
}

func (ctx Context) TokenRevocationAuthnSigAlgs() []goidc.SignatureAlgorithm {
	return ctx.clientAuthnSigAlgs(ctx.TokenRevocationAuthnMethods)
}

func (ctx Context) ClientAuthnSigAlgs() []goidc.SignatureAlgorithm {
	return append(ctx.PrivateKeyJWTSigAlgs, ctx.ClientSecretJWTSigAlgs...)
}

func (ctx Context) clientAuthnSigAlgs(methods []goidc.ClientAuthnType) []goidc.SignatureAlgorithm {
	var sigAlgs []goidc.SignatureAlgorithm

	if slices.Contains(methods, goidc.ClientAuthnPrivateKeyJWT) {
		sigAlgs = append(sigAlgs, ctx.PrivateKeyJWTSigAlgs...)
	}

	if slices.Contains(methods, goidc.ClientAuthnSecretJWT) {
		sigAlgs = append(sigAlgs, ctx.ClientSecretJWTSigAlgs...)
	}

	return sigAlgs
}

func (ctx Context) ClientCert() (*x509.Certificate, error) {

	if ctx.ClientCertFunc == nil {
		return nil, errors.New("the client certificate function was not defined")
	}

	return ctx.ClientCertFunc(ctx.Request)
}

func (ctx Context) ValidateInitalAccessToken(token string) error {
	if ctx.ValidateInitialAccessTokenFunc == nil {
		return nil
	}

	return ctx.ValidateInitialAccessTokenFunc(ctx.Request, token)
}

func (ctx Context) HandleDynamicClient(id string, c *goidc.ClientMeta) error {
	if ctx.HandleDynamicClientFunc == nil {
		return nil
	}

	return ctx.HandleDynamicClientFunc(ctx.Request, id, c)
}

func (ctx Context) ClientID() string {
	if ctx.ClientIDFunc == nil {
		return "dc-" + strutil.Random(30)
	}

	return ctx.ClientIDFunc(ctx)
}

func (ctx Context) CheckJTI(jti string) error {
	if ctx.CheckJTIFunc == nil {
		return nil
	}

	return ctx.CheckJTIFunc(ctx, jti)
}

func (ctx Context) RenderError(err error) error {
	if ctx.RenderErrorFunc == nil {
		// No need to notify error here, since this error will end up being
		// passed to WriteError which already calls it.
		return err
	}

	ctx.NotifyError(err)
	return ctx.RenderErrorFunc(ctx.Response, ctx.Request, err)
}

func (ctx Context) NotifyError(err error) {
	if ctx.NotifyErrorFunc == nil {
		return
	}

	ctx.NotifyErrorFunc(ctx, err)
}

func (ctx Context) Issuer() string {
	return ctx.Host
}

func (ctx Context) TokenURL() string {
	return ctx.BaseURL() + ctx.TokenEndpoint
}

func (ctx Context) TokenMTLSURL() string {
	return ctx.MTLSBaseURL() + ctx.TokenEndpoint
}

func (ctx Context) RequestURL() string {
	return ctx.Issuer() + ctx.Request.RequestURI
}

func (ctx Context) RequestMTLSURL() string {
	return ctx.MTLSHost + ctx.Request.RequestURI
}

func (ctx Context) Policy(id string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.AuthnPolicy{}
}

func (ctx Context) LogoutPolicy(id string) goidc.LogoutPolicy {
	for _, policy := range ctx.LogoutPolicies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.LogoutPolicy{}
}

func (ctx Context) AvailablePolicy(c *goidc.Client, as *goidc.AuthnSession) (policy goidc.AuthnPolicy, ok bool) {
	for _, policy = range ctx.Policies {
		if ok = policy.SetUp(ctx.Request, c, as); ok {
			return policy, true
		}
	}

	return goidc.AuthnPolicy{}, false
}

func (ctx Context) AvailableLogoutPolicy(ls *goidc.LogoutSession) (policy goidc.LogoutPolicy, ok bool) {
	for _, policy = range ctx.LogoutPolicies {
		if ok = policy.SetUp(ctx.Request, ls); ok {
			return policy, true
		}
	}

	return goidc.LogoutPolicy{}, false
}

func (ctx Context) CompareAuthDetails(granted, requested []goidc.AuthorizationDetail) error {
	if ctx.CompareAuthDetailsFunc == nil {
		return errors.New("auth details comparing function is not defined")
	}
	return ctx.CompareAuthDetailsFunc(granted, requested)
}

func (ctx Context) InitBackAuth(session *goidc.AuthnSession) error {
	if ctx.InitBackAuthFunc == nil {
		return errors.New("ciba init back auth function is not set")
	}
	return ctx.InitBackAuthFunc(ctx, session)
}

func (ctx Context) ValidateBackAuth(session *goidc.AuthnSession) error {
	if ctx.ValidateBackAuthFunc == nil {
		return errors.New("ciba validate back auth function is not set")
	}
	return ctx.ValidateBackAuthFunc(ctx, session)
}

func (ctx Context) OpenIDFedRequiredTrustMarks(client *goidc.Client) []string {
	if ctx.OpenIDFedRequiredTrustMarksFunc == nil {
		return nil
	}

	return ctx.OpenIDFedRequiredTrustMarksFunc(ctx, client)
}

func (ctx Context) HandleDefaultPostLogout(session *goidc.LogoutSession) error {
	if ctx.HandleDefaultPostLogoutFunc == nil {
		return errors.New("default post logout handler function is not defined")
	}

	return ctx.HandleDefaultPostLogoutFunc(ctx.Response, ctx.Request, session)
}

func (ctx Context) LogoutSessionID() string {
	if ctx.LogoutSessionIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.LogoutSessionIDFunc(ctx)
}

func (ctx Context) AuthnSessionID() string {
	if ctx.AuthnSessionGenerateIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.AuthnSessionGenerateIDFunc(ctx)
}

func (ctx Context) GrantSessionID() string {
	if ctx.GrantSessionIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.GrantSessionIDFunc(ctx)
}

func (ctx Context) JWTID() string {
	if ctx.JWTIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.JWTIDFunc(ctx)
}

func (ctx Context) AuthorizationCode() string {
	if ctx.AuthorizationCodeFunc == nil {
		return strutil.Random(30)
	}

	return ctx.AuthorizationCodeFunc(ctx)
}

func (ctx Context) CallbackID() string {
	if ctx.CallbackIDFunc == nil {
		return strutil.Random(30)
	}

	return ctx.CallbackIDFunc(ctx)
}

func (ctx Context) CIBAAuthReqID() string {
	if ctx.CIBAAuthReqIDFunc == nil {
		return strutil.Random(50)
	}

	return ctx.CIBAAuthReqIDFunc(ctx)
}

func (ctx Context) PARID() string {
	if ctx.PARIDFunc == nil {
		return strutil.Random(30)
	}

	return ctx.PARIDFunc(ctx)
}

func (ctx Context) SaveClient(client *goidc.Client) error {
	return ctx.ClientManager.Save(ctx, client)
}

func (ctx Context) Client(id string) (*goidc.Client, error) {
	if client := ctx.staticClient(id); client != nil {
		return client, nil
	}

	if ctx.OpenIDFedIsEnabled {
		return ctx.OpenIDFedClientFunc(ctx, id)
	}
	return ctx.ClientManager.Client(ctx, id)
}

func (ctx Context) staticClient(id string) *goidc.Client {
	for _, c := range ctx.StaticClients {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (ctx Context) DeleteClient(id string) error {
	return ctx.ClientManager.Delete(ctx, id)
}

func (ctx Context) SaveGrantSession(session *goidc.GrantSession) error {
	return ctx.GrantSessionManager.Save(ctx, session)
}

func (ctx Context) GrantSessionByTokenID(id string) (*goidc.GrantSession, error) {
	return ctx.GrantSessionManager.SessionByTokenID(ctx, id)
}

func (ctx Context) GrantSessionByRefreshToken(id string) (*goidc.GrantSession, error) {
	return ctx.GrantSessionManager.SessionByRefreshToken(ctx, id)
}

func (ctx Context) DeleteGrantSession(id string) error {
	return ctx.GrantSessionManager.Delete(ctx, id)
}

func (ctx Context) DeleteGrantSessionByAuthorizationCode(code string) error {
	return ctx.GrantSessionManager.DeleteByAuthCode(ctx, code)
}

func (ctx Context) SaveAuthnSession(session *goidc.AuthnSession) error {
	numberOfIndexes := 0
	if session.CallbackID != "" || session.PushedAuthReqID != "" {
		numberOfIndexes++
	}
	if session.AuthCode != "" {
		numberOfIndexes++
	}
	if session.CIBAAuthID != "" {
		numberOfIndexes++
	}

	if numberOfIndexes != 1 {
		return errors.New("invalid authn session indexing")
	}

	return ctx.AuthnSessionManager.Save(ctx, session)
}

func (ctx Context) AuthnSessionByCallbackID(id string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.SessionByCallbackID(ctx, id)
}

func (ctx Context) AuthnSessionByAuthCode(code string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.SessionByAuthCode(ctx, code)
}

func (ctx Context) AuthnSessionByRequestURI(uri string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.SessionByPushedAuthReqID(ctx, uri)
}

func (ctx Context) AuthnSessionByAuthReqID(id string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.SessionByCIBAAuthID(ctx, id)
}

func (ctx Context) DeleteAuthnSession(id string) error {
	return ctx.AuthnSessionManager.Delete(ctx, id)
}

func (ctx Context) SaveLogoutSession(session *goidc.LogoutSession) error {
	return ctx.LogoutSessionManager.Save(ctx, session)
}

func (ctx Context) LogoutSessionByCallbackID(id string) (*goidc.LogoutSession, error) {
	return ctx.LogoutSessionManager.SessionByCallbackID(ctx, id)
}

func (ctx Context) DeleteLogoutSession(id string) error {
	return ctx.LogoutSessionManager.Delete(ctx, id)
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx Context) BaseURL() string {
	return ctx.Issuer() + ctx.EndpointPrefix
}

func (ctx Context) MTLSBaseURL() string {
	return ctx.MTLSHost + ctx.EndpointPrefix
}

func (ctx Context) BearerToken() (string, bool) {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.TokenTypeBearer {
		return "", false
	}

	return token, true
}

func (ctx Context) AuthorizationToken() (token string, tokenType goidc.TokenType, ok bool) {
	tokenHeader, ok := ctx.Header("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], goidc.TokenType(tokenParts[0]), true
}

func (ctx Context) Header(name string) (string, bool) {
	value := ctx.Request.Header.Get(name)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx Context) RequestMethod() string {
	return ctx.Request.Method
}

func (ctx Context) WriteStatus(status int) {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return
	default:
	}

	ctx.Response.WriteHeader(status)
}

// Write responds the current request writing obj as JSON.
func (ctx Context) Write(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(status)
	if err := json.NewEncoder(ctx.Response).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteJWT(token string, status int) error {
	return ctx.WriteJWTWithType(token, status, "application/jwt")
}

func (ctx Context) WriteJWTWithType(token string, status int, contentType string) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", contentType)
	ctx.Response.WriteHeader(status)

	if _, err := ctx.Response.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteError(err error) {

	ctx.NotifyError(err)

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		oidcErr = goidc.NewError(goidc.ErrorCodeInternalError, "internal error")
	}

	oidcErr = oidcErr.WithURI(ctx.ErrorURI)
	if err := ctx.Write(oidcErr, oidcErr.StatusCode()); err != nil {
		ctx.Response.WriteHeader(http.StatusInternalServerError)
	}
}

func (ctx Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Response, ctx.Request, redirectURL, http.StatusSeeOther)
}

func (ctx Context) WriteHTML(html string, params any) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "text/html")
	ctx.Response.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	return tmpl.Execute(ctx.Response, params)
}

func (ctx Context) UserInfoSigAlgsContainsNone() bool {
	return slices.Contains(ctx.UserInfoSigAlgs, goidc.None)
}

func (ctx Context) IDTokenSigAlgsContainsNone() bool {
	return slices.Contains(ctx.IDTokenSigAlgs, goidc.None)
}

func (ctx Context) ShouldIssueRefreshToken(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
	if ctx.ShouldIssueRefreshTokenFunc == nil ||
		!slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) ||
		grantInfo.GrantType == goidc.GrantClientCredentials {
		return false
	}

	return ctx.ShouldIssueRefreshTokenFunc(ctx, client, grantInfo)
}

func (ctx Context) TokenOptions(grantInfo goidc.GrantInfo, client *goidc.Client) goidc.TokenOptions {

	opts := ctx.TokenOptionsFunc(ctx, grantInfo, client)

	if shouldSwitchToOpaque(ctx, grantInfo, client, opts) {
		opts = goidc.NewOpaqueTokenOptions(goidc.DefaultOpaqueTokenLength, opts.LifetimeSecs)
	}

	// Opaque access tokens cannot be the same size of refresh tokens.
	if opts.OpaqueLength == goidc.RefreshTokenLength {
		opts.OpaqueLength++
	}

	return opts
}

func shouldSwitchToOpaque(
	ctx Context,
	grantInfo goidc.GrantInfo,
	client *goidc.Client,
	opts goidc.TokenOptions,
) bool {

	// There is no need to switch if the token is already opaque.
	if opts.Format == goidc.TokenFormatOpaque {
		return false
	}

	// Use an opaque token format if the subject identifier type is pairwise.
	// This prevents potential information leakage that could occur if the JWT
	// token was decoded by clients.
	return ctx.shouldGeneratePairwiseSub(client) &&
		// The pairwise subject type doesn't apply for client credentials.
		grantInfo.GrantType != goidc.GrantClientCredentials
}

func (ctx Context) shouldGeneratePairwiseSub(client *goidc.Client) bool {
	return client.SubIdentifierType == goidc.SubIdentifierPairwise ||
		(client.SubIdentifierType == "" && ctx.DefaultSubIdentifierType == goidc.SubIdentifierPairwise)
}

func (ctx Context) HandleGrant(grantInfo *goidc.GrantInfo) error {
	if ctx.HandleGrantFunc == nil {
		return nil
	}

	return ctx.HandleGrantFunc(ctx.Request, grantInfo)
}

func (ctx Context) HandleJWTBearerGrantAssertion(assertion string) (goidc.JWTBearerGrantInfo, error) {
	return ctx.HandleJWTBearerGrantAssertionFunc(ctx.Request, assertion)
}

func (ctx Context) HTTPClient() *http.Client {
	if ctx.HTTPClientFunc == nil {
		return http.DefaultClient
	}

	return ctx.HTTPClientFunc(ctx)
}

// TODO.
// ExportableSubject returns a subject identifier for the given client based on
// its subject identifier type.
// If the subject identifier type is "public", it returns the provided subject.
// If the subject identifier type is "pairwise", it generates a pairwise
// identifier using the sector URI or a redirect URI.
func (ctx Context) ExportableSubject(sub string, client *goidc.Client) string {
	if ctx.GeneratePairwiseSubIDFunc == nil || !ctx.shouldGeneratePairwiseSub(client) {
		return sub
	}

	return ctx.GeneratePairwiseSubIDFunc(ctx, sub, client)
}

func (ctx Context) HandlePARSession(as *goidc.AuthnSession, client *goidc.Client) error {
	if ctx.HandlePARSessionFunc == nil {
		return nil
	}

	return ctx.HandlePARSessionFunc(ctx.Request, as, client)
}

//---------------------------------------- context.Context ----------------------------------------//

func (ctx Context) Context() context.Context {
	if ctx.context != nil {
		return ctx.context
	}
	return ctx.Request.Context()
}

func (ctx Context) Deadline() (deadline time.Time, ok bool) {
	return ctx.Context().Deadline()
}

func (ctx Context) Done() <-chan struct{} {
	return ctx.Context().Done()
}

func (ctx Context) Err() error {
	return ctx.Context().Err()
}

func (ctx Context) Value(key any) any {
	return ctx.Context().Value(key)
}

//---------------------------------------- SSF ----------------------------------------//

func (ctx Context) SSFJWKS() (goidc.JSONWebKeySet, error) {
	return ctx.SSFJWKSFunc(ctx)
}

func (ctx Context) SSFPublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) SSFCreateEventStream(stream *goidc.SSFEventStream) error {
	return ctx.SSFEventStreamManager.Create(ctx, stream)
}

func (ctx Context) SSFUpdateEventStream(stream *goidc.SSFEventStream) error {
	return ctx.SSFEventStreamManager.Update(ctx, stream)
}

func (ctx Context) SSFEventStream(id string) (*goidc.SSFEventStream, error) {
	return ctx.SSFEventStreamManager.EventStream(ctx, id)
}

func (ctx Context) SSFEventStreams(receiverID string) ([]*goidc.SSFEventStream, error) {
	return ctx.SSFEventStreamManager.EventStreams(ctx, receiverID)
}

func (ctx Context) SSFDeleteEventStream(id string) error {
	return ctx.SSFEventStreamManager.Delete(ctx, id)
}

func (ctx Context) SSFAddSubject(id string, subject goidc.SSFSubject, opts goidc.SSFSubjectOptions) error {
	return ctx.SSFEventStreamSubjectManager.Add(ctx, id, subject, opts)
}

func (ctx Context) SSFRemoveSubject(id string, subject goidc.SSFSubject) error {
	return ctx.SSFEventStreamSubjectManager.Remove(ctx, id, subject)
}

func (ctx Context) SSFEventStreamID() string {
	if ctx.SSFEventStreamIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.SSFEventStreamIDFunc(ctx)
}

func (ctx Context) SSFAuthenticatedReceiver() (goidc.SSFReceiver, error) {
	if ctx.SSFAuthenticatedReceiverFunc == nil {
		return goidc.SSFReceiver{}, errors.New("authenticated receiver function is not defined")
	}

	return ctx.SSFAuthenticatedReceiverFunc(ctx)
}

func (ctx Context) SSFJWTID() string {
	if ctx.SSFJWTIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.SSFJWTIDFunc(ctx)
}

func (ctx Context) SSFSign(claims any, opts *jose.SignerOptions) (string, error) {

	if ctx.SSFSignerFunc == nil {
		jwk, err := ctx.SSFJWKByAlg(ctx.SSFSignatureAlgorithm)
		if err != nil {
			return "", fmt.Errorf("could not load the signing jwk: %w", err)
		}
		return joseutil.Sign(claims, jose.SigningKey{Algorithm: ctx.SSFSignatureAlgorithm, Key: jwk}, opts)
	}

	keyID, key, err := ctx.SSFSignerFunc(ctx, ctx.SSFSignatureAlgorithm)
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: ctx.SSFSignatureAlgorithm,
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: ctx.SSFSignatureAlgorithm,
			Signer:    key,
		},
	}, opts)
}

func (ctx Context) SSFJWKByAlg(alg goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.KeyByAlg(string(alg))
}

func (ctx Context) SSFSaveEvent(streamID string, event goidc.SSFEvent) error {
	return ctx.SSFEventPollManager.Save(ctx, streamID, event)
}

func (ctx Context) SSFPollEvents(streamID string, opts goidc.SSFPollOptions) (goidc.SSFEvents, error) {
	return ctx.SSFEventPollManager.Poll(ctx, streamID, opts)
}

func (ctx Context) SSFAcknowledgeEvents(streamID string, jtis []string, opts goidc.SSFAcknowledgementOptions) error {
	return ctx.SSFEventPollManager.Acknowledge(ctx, streamID, jtis, opts)
}

func (ctx Context) SSFAcknowledgeErrors(streamID string, errs map[string]goidc.SSFEventError, opts goidc.SSFAcknowledgementOptions) error {
	return ctx.SSFEventPollManager.AcknowledgeErrors(ctx, streamID, errs, opts)
}

func (ctx Context) SSFScheduleVerificationEvent(streamID string, opts goidc.SSFStreamVerificationOptions) error {
	return ctx.SSFEventStreamVerificationManager.Schedule(ctx, streamID, opts)
}

func (ctx Context) SSFHTTPClient() *http.Client {
	if ctx.SSFHTTPClientFunc == nil {
		return ctx.HTTPClient()
	}

	return ctx.SSFHTTPClientFunc(ctx)
}

func (ctx Context) SSFHandleExpiredEventStream(stream *goidc.SSFEventStream) error {
	if ctx.SSFHandleExpiredEventStreamFunc == nil {
		return nil
	}

	return ctx.SSFHandleExpiredEventStreamFunc(ctx, stream)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx Context) JWKS() (goidc.JSONWebKeySet, error) {
	return ctx.JWKSFunc(ctx)
}

func (ctx Context) PublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) OpenIDFedJWKS() (goidc.JSONWebKeySet, error) {
	return ctx.OpenIDFedJWKSFunc(ctx)
}

func (ctx Context) OpenIDFedPublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.OpenIDFedJWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) OpenIDFedEntityJWKS(id string) (goidc.JSONWebKeySet, error) {
	if ctx.OpenIDFedEntityJWKSFunc == nil {
		return goidc.JSONWebKeySet{}, errors.New("fetch federation entity jwks function is not set")
	}

	return ctx.OpenIDFedEntityJWKSFunc(ctx, id)
}

func (ctx Context) SigAlgs() ([]goidc.SignatureAlgorithm, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return nil, err
	}

	var algorithms []goidc.SignatureAlgorithm
	for _, jwk := range jwks.Keys {
		if inferKeyUsage(jwk) == goidc.KeyUsageSignature {
			algorithms = append(algorithms, goidc.SignatureAlgorithm(jwk.Algorithm))
		}
	}

	return algorithms, nil
}

func (ctx Context) PublicJWK(kid string) (goidc.JSONWebKey, error) {
	key, err := ctx.JWK(kid)
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return key.Public(), nil
}

func (ctx Context) JWK(kid string) (goidc.JSONWebKey, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.Key(kid)
}

// JWKByAlg searches a key that matches the signature algorithm from the JWKS.
func (ctx Context) JWKByAlg(alg goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.KeyByAlg(string(alg))
}

func (ctx Context) Sign(claims any, alg goidc.SignatureAlgorithm, opts *jose.SignerOptions) (string, error) {

	if ctx.SignerFunc == nil {
		jwk, err := ctx.JWKByAlg(alg)
		if err != nil {
			return "", fmt.Errorf("could not load the signing jwk: %w", err)
		}
		return joseutil.Sign(claims, jose.SigningKey{Algorithm: alg, Key: jwk}, opts)
	}

	keyID, key, err := ctx.SignerFunc(ctx, alg)
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: alg,
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: alg,
			Signer:    key,
		},
	}, opts)
}

func (ctx Context) Decrypt(
	jwe string,
	keyAlgs []goidc.KeyEncryptionAlgorithm,
	cntAlgs []goidc.ContentEncryptionAlgorithm,
) (
	string,
	error,
) {
	parseJWE, err := jose.ParseEncrypted(jwe, keyAlgs, cntAlgs)
	if err != nil {
		return "", fmt.Errorf("could not parse the jwe: %w", err)
	}

	keyID := parseJWE.Header.KeyID
	if keyID == "" {
		return "", errors.New("invalid jwe key ID")
	}

	var key any
	if ctx.DecrypterFunc != nil {
		alg := goidc.KeyEncryptionAlgorithm(parseJWE.Header.Algorithm)
		decrypter, err := ctx.DecrypterFunc(ctx, keyID, alg)
		if err != nil {
			return "", fmt.Errorf("could not load the decrypter: %w", err)
		}
		key = joseutil.OpaqueDecrypter{Algorithm: alg, Decrypter: decrypter}
	} else {
		jwk, err := ctx.JWK(keyID)
		if err != nil || inferKeyUsage(jwk) != goidc.KeyUsageEncryption {
			return "", errors.New("invalid jwk used for encryption")
		}
		key = jwk
	}

	jws, err := parseJWE.Decrypt(key)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the jwe: %w", err)
	}

	return string(jws), nil
}

func (ctx Context) OpenIDFedSign(claims any, opts *jose.SignerOptions) (string, error) {

	jwks, err := ctx.OpenIDFedJWKS()
	if err != nil {
		return "", fmt.Errorf("could not load the signing jwk: %w", err)
	}
	// TODO: Add config to pick the algorithm to find the right key.
	jwk := jwks.Keys[0]

	if ctx.OpenIDFedSignerFunc == nil {
		return joseutil.Sign(claims, jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
			Key:       jwk,
		}, opts)
	}

	keyID, key, err := ctx.OpenIDFedSignerFunc(ctx, goidc.SignatureAlgorithm(jwk.Algorithm))
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
			Signer:    key,
		},
	}, opts)
}

func inferKeyUsage(key goidc.JSONWebKey) goidc.KeyUsage {
	if key.Use != "" {
		return goidc.KeyUsage(key.Use)
	}

	switch key.Algorithm {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512":
		return goidc.KeyUsageSignature
	case "RSA1_5", "RSA_OAEP", "RSA_OAEP_256":
		return goidc.KeyUsageEncryption
	default:
		return ""
	}
}
