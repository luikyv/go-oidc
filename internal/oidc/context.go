package oidc

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Context struct {
	Req  *http.Request
	Resp http.ResponseWriter
	Configuration
}

func NewContext(
	w http.ResponseWriter,
	r *http.Request,
	config Configuration,
) *Context {
	return &Context{
		Configuration: config,
		Req:           r,
		Resp:          w,
	}
}

func Handler(
	config *Configuration,
	exec func(ctx *Context),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exec(NewContext(w, r, *config))
	}
}

func (ctx *Context) ClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	return append(
		ctx.PrivateKeyJWTSigAlgs,
		ctx.ClientSecretJWTSigAlgs...,
	)
}

func (ctx *Context) IntrospectionClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	var signatureAlgorithms []jose.SignatureAlgorithm

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT) {
		signatureAlgorithms = append(
			signatureAlgorithms,
			ctx.PrivateKeyJWTSigAlgs...,
		)
	}

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.ClientAuthnSecretJWT) {
		signatureAlgorithms = append(
			signatureAlgorithms,
			ctx.ClientSecretJWTSigAlgs...,
		)
	}

	return signatureAlgorithms
}

// DPoPJWT gets the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func (ctx *Context) DPoPJWT() (string, bool) {
	// Consider case insensitive headers by canonicalizing them.
	canonicalizedDPoPHeader := textproto.CanonicalMIMEHeaderKey(goidc.HeaderDPoP)
	canonicalizedHeaders := textproto.MIMEHeader(ctx.Req.Header)

	values := canonicalizedHeaders[canonicalizedDPoPHeader]
	if values == nil || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// TODO: return an error.
func (ctx *Context) ClientCert() (*x509.Certificate, bool) {

	if ctx.ClientCertFunc == nil {
		return nil, false
	}

	return ctx.ClientCertFunc(ctx.Request())
}

func (ctx *Context) HandleDynamicClient(c *goidc.ClientMetaInfo) error {
	if ctx.HandleDynamicClientFunc == nil {
		return nil
	}

	return ctx.HandleDynamicClientFunc(ctx.Request(), c)
}

func (ctx *Context) RenderError(err error) error {
	if ctx.RenderErrorFunc == nil {
		return err
	}

	return ctx.RenderErrorFunc(ctx.Response(), ctx.Request(), err)
}

// Audiences returns the host names trusted by the server to validate assertions.
func (ctx *Context) Audiences() []string {

	audiences := []string{
		ctx.Host,
		ctx.Host + ctx.Request().RequestURI,
	}
	if ctx.MTLSIsEnabled {
		audiences = append(
			audiences,
			ctx.MTLSHost,
			ctx.MTLSHost+ctx.Request().RequestURI,
		)
	}
	return audiences
}

func (ctx *Context) Policy(policyID string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.ID == policyID {
			return policy
		}
	}
	return goidc.AuthnPolicy{}
}

func (ctx *Context) FindAvailablePolicy(client *goidc.Client, session *goidc.AuthnSession) (
	policy goidc.AuthnPolicy,
	ok bool,
) {
	for _, policy = range ctx.Policies {
		if ok = policy.SetUp(ctx.Request(), client, session); ok {
			return policy, true
		}
	}

	return goidc.AuthnPolicy{}, false
}

//---------------------------------------- CRUD ----------------------------------------//

func (ctx *Context) SaveClient(client *goidc.Client) error {
	return ctx.ClientManager.Save(ctx.Request().Context(), client)
}

func (ctx *Context) Client(clientID string) (*goidc.Client, error) {
	for _, staticClient := range ctx.StaticClients {
		if staticClient.ID == clientID {
			return staticClient, nil
		}
	}

	return ctx.ClientManager.Get(ctx.Request().Context(), clientID)
}

func (ctx *Context) DeleteClient(id string) error {
	return ctx.ClientManager.Delete(ctx.Request().Context(), id)
}

func (ctx *Context) SaveGrantSession(session *goidc.GrantSession) error {
	return ctx.GrantSessionManager.Save(
		ctx.Request().Context(),
		session,
	)
}

func (ctx *Context) GrantSessionByTokenID(
	id string,
) (
	*goidc.GrantSession,
	error,
) {
	return ctx.GrantSessionManager.GetByTokenID(
		ctx.Request().Context(),
		id,
	)
}

func (ctx *Context) GrantSessionByRefreshToken(
	token string,
) (
	*goidc.GrantSession,
	error,
) {
	return ctx.GrantSessionManager.GetByRefreshToken(
		ctx.Request().Context(),
		token,
	)
}

func (ctx *Context) DeleteGrantSession(id string) error {
	return ctx.GrantSessionManager.Delete(ctx.Request().Context(), id)
}

func (ctx *Context) SaveAuthnSession(session *goidc.AuthnSession) error {
	return ctx.AuthnSessionManager.Save(ctx.Request().Context(), session)
}

func (ctx *Context) AuthnSessionByCallbackID(
	id string,
) (
	*goidc.AuthnSession,
	error,
) {
	return ctx.AuthnSessionManager.GetByCallbackID(ctx.Request().Context(), id)
}

func (ctx *Context) AuthnSessionByAuthorizationCode(
	code string,
) (
	*goidc.AuthnSession,
	error,
) {
	return ctx.AuthnSessionManager.GetByAuthorizationCode(
		ctx.Request().Context(),
		code,
	)
}

func (ctx *Context) AuthnSessionByRequestURI(
	uri string,
) (
	*goidc.AuthnSession,
	error,
) {
	return ctx.AuthnSessionManager.GetByRequestURI(ctx.Request().Context(), uri)
}

func (ctx *Context) DeleteAuthnSession(id string) error {
	return ctx.AuthnSessionManager.Delete(ctx.Request().Context(), id)
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx *Context) BaseURL() string {
	return ctx.Host + ctx.EndpointPrefix
}

func (ctx *Context) MTLSBaseURL() string {
	return ctx.MTLSHost + ctx.EndpointPrefix
}

func (ctx *Context) Request() *http.Request {
	return ctx.Req
}

func (ctx *Context) Response() http.ResponseWriter {
	return ctx.Resp
}

func (ctx *Context) BearerToken() (string, bool) {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.TokenTypeBearer {
		return "", false
	}

	return token, true
}

func (ctx *Context) AuthorizationToken() (
	token string,
	tokenType goidc.TokenType,
	ok bool,
) {
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

func (ctx *Context) Header(name string) (string, bool) {
	value := ctx.Req.Header.Get(name)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx *Context) RequestMethod() string {
	return ctx.Req.Method
}

func (ctx *Context) FormParam(param string) string {

	if err := ctx.Req.ParseForm(); err != nil {
		return ""
	}

	return ctx.Req.PostFormValue(param)
}

func (ctx *Context) FormData() map[string]any {

	if err := ctx.Req.ParseForm(); err != nil {
		return map[string]any{}
	}

	formData := make(map[string]any)
	for param, values := range ctx.Req.PostForm {
		formData[param] = values[0]
	}
	return formData
}

// Write responds the current request writing obj as JSON.
func (ctx *Context) Write(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Request().Context().Done():
		return nil
	default:
	}

	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(status)
	if err := json.NewEncoder(ctx.Resp).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) WriteJWT(token string, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Request().Context().Done():
		return nil
	default:
	}

	ctx.Resp.Header().Set("Content-Type", "application/jwt")
	ctx.Resp.WriteHeader(status)

	if _, err := ctx.Resp.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) WriteError(err error) {

	var oidcErr oidcerr.Error
	if !errors.As(err, &oidcErr) {
		if err := ctx.Write(map[string]any{
			"error":             oidcerr.CodeInternalError,
			"error_description": "internal error",
		}, http.StatusInternalServerError); err != nil {
			ctx.Response().WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	if err := ctx.Write(oidcErr, oidcErr.Code.StatusCode()); err != nil {
		ctx.Response().WriteHeader(http.StatusInternalServerError)
	}
}

func (ctx *Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Resp, ctx.Req, redirectURL, http.StatusSeeOther)
}

func (ctx *Context) RenderHTML(
	html string,
	params any,
) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Request().Context().Done():
		return nil
	default:
	}

	ctx.Resp.Header().Set("Content-Type", "text/html")
	ctx.Resp.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	return tmpl.Execute(ctx.Resp, params)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx *Context) SignatureAlgorithms() []jose.SignatureAlgorithm {
	var algorithms []jose.SignatureAlgorithm
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		if privateKey.Use == string(goidc.KeyUsageSignature) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}

func (ctx *Context) PublicKeys() jose.JSONWebKeySet {
	publicKeys := []jose.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		publicKeys = append(publicKeys, privateKey.Public())
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func (ctx *Context) PublicKey(keyID string) (jose.JSONWebKey, bool) {
	key, ok := ctx.PrivateKey(keyID)
	if !ok {
		return jose.JSONWebKey{}, false
	}

	return key.Public(), true
}

func (ctx *Context) PrivateKey(keyID string) (jose.JSONWebKey, bool) {
	keys := ctx.PrivateJWKS.Key(keyID)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx *Context) TokenSignatureKey(tokenOptions goidc.TokenOptions) jose.JSONWebKey {
	return ctx.privateKey(tokenOptions.JWTSignatureKeyID)
}

func (ctx *Context) UserInfoSignatureKey(client *goidc.Client) jose.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(
		client.UserInfoSigAlg,
		ctx.UserDefaultSigKeyID,
		ctx.UserSigKeyIDs,
	)
}

func (ctx *Context) IDTokenSignatureKey(client *goidc.Client) jose.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(
		client.IDTokenSigAlg,
		ctx.UserDefaultSigKeyID,
		ctx.UserSigKeyIDs,
	)
}

func (ctx *Context) JARMSignatureKey(client *goidc.Client) jose.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(
		client.JARMSigAlg,
		ctx.JARMDefaultSigKeyID,
		ctx.JARMSigKeyIDs,
	)
}

func (ctx *Context) UserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.signatureAlgorithms(ctx.UserSigKeyIDs)
}

func (ctx *Context) JARMSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.signatureAlgorithms(ctx.JARMSigKeyIDs)
}

func (ctx *Context) JARKeyEncryptionAlgorithms() []jose.KeyAlgorithm {
	return ctx.keyEncryptionAlgorithms(ctx.JARKeyEncIDs)
}

func (ctx *Context) keyEncryptionAlgorithms(keyIDs []string) []jose.KeyAlgorithm {
	var algorithms []jose.KeyAlgorithm
	for _, keyID := range keyIDs {
		key := ctx.privateKey(keyID)
		algorithms = append(algorithms, jose.KeyAlgorithm(key.Algorithm))
	}
	return algorithms
}

func (ctx *Context) signatureAlgorithms(keyIDs []string) []jose.SignatureAlgorithm {
	var algorithms []jose.SignatureAlgorithm
	for _, keyID := range keyIDs {
		key := ctx.privateKey(keyID)
		algorithms = append(algorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	return algorithms
}

// privateKeyBasedOnAlgorithmOrDefault tries to find a key that matches signatureAlgorithm
// from the subset of keys defined by keyIDs.
// If no key is found, return the key associated to defaultKeyID.
func (ctx *Context) privateKeyBasedOnAlgorithmOrDefault(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyID string,
	keyIDs []string,
) jose.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyID := range keyIDs {
			return ctx.privateKey(keyID)
		}
	}

	return ctx.privateKey(defaultKeyID)
}

// privateKey returns a private JWK based on the key ID.
// This is intended to be used with key IDs we're sure are present in the server JWKS.
func (ctx *Context) privateKey(keyID string) jose.JSONWebKey {
	keys := ctx.PrivateJWKS.Key(keyID)
	return keys[0]
}

func (ctx *Context) TokenOptions(client *goidc.Client, scopes string) (goidc.TokenOptions, error) {
	opts, err := ctx.Configuration.TokenOptions(client, scopes)
	if err != nil {
		return goidc.TokenOptions{}, oidcerr.Errorf(oidcerr.CodeAccessDenied,
			"access denied", err)
	}

	return opts, nil
}

//---------------------------------------- Context ----------------------------------------//

func (ctx *Context) Deadline() (deadline time.Time, ok bool) {
	return ctx.Request().Context().Deadline()
}

func (ctx *Context) Done() <-chan struct{} {
	return ctx.Req.Context().Done()
}

func (ctx *Context) Err() error {
	return ctx.Request().Context().Err()
}

func (ctx *Context) Value(key any) any {
	return ctx.Request().Context().Value(key)
}
