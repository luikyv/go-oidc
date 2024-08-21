package oidc

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html/template"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Context struct {
	Req  *http.Request
	Resp http.ResponseWriter
	Configuration
}

func NewContext(
	configuration Configuration,
	req *http.Request,
	resp http.ResponseWriter,
) *Context {
	return &Context{
		Configuration: configuration,
		Req:           req,
		Resp:          resp,
	}
}

func (ctx *Context) ClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	return append(
		ctx.ClientAuthn.PrivateKeyJWTSignatureAlgorithms,
		ctx.ClientAuthn.ClientSecretJWTSignatureAlgorithms...,
	)
}

func (ctx *Context) IntrospectionClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	var signatureAlgorithms []jose.SignatureAlgorithm

	if slices.Contains(ctx.Introspection.ClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT) {
		signatureAlgorithms = append(
			signatureAlgorithms,
			ctx.ClientAuthn.PrivateKeyJWTSignatureAlgorithms...,
		)
	}

	if slices.Contains(ctx.Introspection.ClientAuthnMethods, goidc.ClientAuthnSecretJWT) {
		signatureAlgorithms = append(
			signatureAlgorithms,
			ctx.ClientAuthn.ClientSecretJWTSignatureAlgorithms...,
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

func (ctx *Context) ClientCertificate() (*x509.Certificate, bool) {

	if ctx.MTLS.ClientCertFunc != nil {
		return ctx.MTLS.ClientCertFunc(ctx)
	}

	rawClientCert, ok := ctx.Header(goidc.HeaderClientCertificate)
	if !ok {
		return nil, false
	}

	rawClientCertDecoded, err := url.QueryUnescape(rawClientCert)
	if err != nil {
		return nil, false
	}

	clientCertPEM, _ := pem.Decode([]byte(rawClientCertDecoded))
	if clientCertPEM == nil {
		return nil, false
	}

	clientCert, err := x509.ParseCertificate(clientCertPEM.Bytes)
	if err != nil {
		return nil, false
	}

	return clientCert, true
}

func (ctx *Context) ExecuteDCRPlugin(clientInfo *goidc.ClientMetaInfo) {
	if ctx.DCR.Plugin == nil {
		return
	}
	ctx.DCR.Plugin(ctx, clientInfo)
}

func (ctx *Context) ExecuteAuthorizeErrorPlugin(oidcErr Error) Error {
	if ctx.AuthorizeErrorPlugin == nil {
		return oidcErr
	}

	if err := ctx.AuthorizeErrorPlugin(ctx, oidcErr); err != nil {
		return oidcErr
	}

	return nil
}

// Audiences returns the host names trusted by the server to validate assertions.
func (ctx *Context) Audiences() []string {

	audiences := []string{
		ctx.Host,
		ctx.Host + ctx.Request().RequestURI,
	}
	if ctx.MTLS.IsEnabled {
		audiences = append(
			audiences,
			ctx.MTLS.Host,
			ctx.MTLS.Host+ctx.Request().RequestURI,
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
		if ok = policy.SetUp(ctx, client, session); ok {
			return policy, true
		}
	}

	return goidc.AuthnPolicy{}, false
}

//---------------------------------------- CRUD ----------------------------------------//

func (ctx *Context) SaveClient(client *goidc.Client) Error {
	if err := ctx.Storage.Client.Save(ctx.Request().Context(), client); err != nil {
		return NewError(ErrorCodeInternalError, "could not save the client")
	}
	return nil
}

func (ctx *Context) Client(clientID string) (*goidc.Client, Error) {
	for _, staticClient := range ctx.StaticClients {
		if staticClient.ID == clientID {
			return staticClient, nil
		}
	}

	client, err := ctx.Storage.Client.Get(ctx.Request().Context(), clientID)
	if err != nil {
		return nil, NewError(ErrorCodeInternalError, "could not load the client")
	}

	return client, nil
}

func (ctx *Context) DeleteClient(id string) Error {
	if err := ctx.Storage.Client.Delete(ctx.Request().Context(), id); err != nil {
		return NewError(ErrorCodeInternalError, "could not delete the client")
	}

	return nil
}

func (ctx *Context) SaveGrantSession(session *goidc.GrantSession) Error {
	// TODO: Flag to avoid saving jwt tokens?
	if err := ctx.Storage.GrantSession.Save(ctx.Request().Context(), session); err != nil {
		return NewError(ErrorCodeInternalError, "could not save the grant session")
	}
	return nil
}

func (ctx *Context) GrantSessionByTokenID(tokenID string) (*goidc.GrantSession, Error) {
	session, err := ctx.Storage.GrantSession.GetByTokenID(ctx.Request().Context(), tokenID)
	if err != nil {
		return nil, NewError(ErrorCodeInternalError, "could not load the grant session")
	}

	return session, nil
}

func (ctx *Context) GrantSessionByRefreshToken(refreshToken string) (*goidc.GrantSession, Error) {
	session, err := ctx.Storage.GrantSession.GetByRefreshToken(ctx.Request().Context(), refreshToken)
	if err != nil {
		return nil, NewError(ErrorCodeInternalError, "could not load the grant session")
	}

	return session, nil
}

func (ctx *Context) DeleteGrantSession(id string) Error {
	if err := ctx.Storage.GrantSession.Delete(ctx.Request().Context(), id); err != nil {
		return NewError(ErrorCodeInternalError, "could not delete the grant session")
	}
	return nil
}

func (ctx *Context) SaveAuthnSession(session *goidc.AuthnSession) Error {
	if err := ctx.Storage.AuthnSession.Save(ctx.Request().Context(), session); err != nil {
		return NewError(ErrorCodeInternalError, "could not save the authentication session")
	}
	return nil
}

func (ctx *Context) AuthnSessionByCallbackID(callbackID string) (*goidc.AuthnSession, Error) {
	session, err := ctx.Storage.AuthnSession.GetByCallbackID(ctx.Request().Context(), callbackID)
	if err != nil {
		return nil, NewError(ErrorCodeInternalError, "could not load the authentication session")
	}

	return session, nil
}

func (ctx *Context) AuthnSessionByAuthorizationCode(code string) (*goidc.AuthnSession, Error) {
	session, err := ctx.Storage.AuthnSession.GetByAuthorizationCode(ctx.Request().Context(), code)
	if err != nil {
		return nil, NewError(ErrorCodeInternalError, "could not load the authentication session")
	}

	return session, nil
}

func (ctx *Context) AuthnSessionByRequestURI(requestURI string) (*goidc.AuthnSession, Error) {
	session, err := ctx.Storage.AuthnSession.GetByRequestURI(ctx.Request().Context(), requestURI)
	if err != nil {
		return nil, NewError(ErrorCodeInternalError, "could not load the authentication session")
	}

	return session, nil
}

func (ctx *Context) DeleteAuthnSession(id string) Error {
	if err := ctx.Storage.AuthnSession.Delete(ctx.Request().Context(), id); err != nil {
		return NewError(ErrorCodeInternalError, "could not delete the authentication session")
	}
	return nil
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx *Context) BaseURL() string {
	return ctx.Host + ctx.Endpoint.Prefix
}

func (ctx *Context) MTLSBaseURL() string {
	return ctx.MTLS.Host + ctx.Endpoint.Prefix
}

func (ctx *Context) Request() *http.Request {
	return ctx.Req
}

func (ctx *Context) Response() http.ResponseWriter {
	return ctx.Resp
}

func (ctx *Context) BearerToken() string {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return ""
	}

	if tokenType != goidc.TokenTypeBearer {
		return ""
	}

	return token
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

	var oidcErr Error
	if !errors.As(err, &oidcErr) {
		if err := ctx.Write(map[string]any{
			"error":             ErrorCodeInternalError,
			"error_description": "internal error",
		}, http.StatusInternalServerError); err != nil {
			ctx.Response().WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	errorCode := oidcErr.Code()
	if err := ctx.Write(oidcErr, errorCode.StatusCode()); err != nil {
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
		client.UserInfoSignatureAlgorithm,
		ctx.User.DefaultSignatureKeyID,
		ctx.User.SignatureKeyIDs,
	)
}

func (ctx *Context) IDTokenSignatureKey(client *goidc.Client) jose.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(
		client.IDTokenSignatureAlgorithm,
		ctx.User.DefaultSignatureKeyID,
		ctx.User.SignatureKeyIDs,
	)
}

func (ctx *Context) JARMSignatureKey(client *goidc.Client) jose.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(
		client.JARMSignatureAlgorithm,
		ctx.JARM.DefaultSignatureKeyID,
		ctx.JARM.SignatureKeyIDs,
	)
}

func (ctx *Context) UserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.signatureAlgorithms(ctx.User.SignatureKeyIDs)
}

func (ctx *Context) JARMSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.signatureAlgorithms(ctx.JARM.SignatureKeyIDs)
}

func (ctx *Context) JARKeyEncryptionAlgorithms() []jose.KeyAlgorithm {
	return ctx.keyEncryptionAlgorithms(ctx.JAR.KeyEncryptionIDs)
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

func (ctx *Context) TokenOptions(client *goidc.Client, scopes string) (goidc.TokenOptions, Error) {
	opts, err := ctx.Configuration.TokenOptions(client, scopes)
	if err != nil {
		return goidc.TokenOptions{}, NewError(ErrorCodeAccessDenied, "access denied")
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

type Configuration struct {
	Profile goidc.Profile
	// Host is the domain where the server runs. This value will be used as the
	// authorization server issuer.
	Host string
	// PrivateJWKS contains the server JWKS with private and public information.
	// When exposing it, the private information is removed.
	PrivateJWKS             jose.JSONWebKeySet
	TokenOptions            goidc.TokenOptionsFunc
	Policies                []goidc.AuthnPolicy
	Scopes                  []goidc.Scope
	OpenIDIsRequired        bool
	GrantTypes              []goidc.GrantType
	ResponseTypes           []goidc.ResponseType
	ResponseModes           []goidc.ResponseMode
	AuthnSessionTimeoutSecs int64
	ACRs                    []goidc.ACR
	DisplayValues           []goidc.DisplayValue
	// Claims defines the user claims that can be returned in the userinfo
	// endpoint or in ID tokens.
	// This will be published in the /.well-known/openid-configuration endpoint.
	Claims                 []string
	ClaimTypes             []goidc.ClaimType
	SubjectIdentifierTypes []goidc.SubjectIdentifierType
	StaticClients          []*goidc.Client
	// IssuerResponseParameterIsEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerResponseParameterIsEnabled bool
	// ClaimsParameterIsEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParameterIsEnabled bool
	// TokenBindingIsRequired indicates that at least one mechanism of sender
	// contraining tokens is required, either DPoP or client TLS.
	TokenBindingIsRequired bool
	AuthorizeErrorPlugin   goidc.AuthorizeErrorFunc
	// OutterAuthParamsRequired indicates that the required authorization params
	// must be informed as query parameters during the request to the
	// authorization endpoint even if they were informed previously during PAR
	// or inside JAR.
	OutterAuthParamsRequired bool

	Endpoint struct {
		WellKnown           string
		JWKS                string
		Token               string
		Authorize           string
		PushedAuthorization string
		DCR                 string
		UserInfo            string
		Introspection       string
		Prefix              string
	}

	Storage struct {
		Client       goidc.ClientManager
		GrantSession goidc.GrantSessionManager
		AuthnSession goidc.AuthnSessionManager
	}

	User struct {
		// DefaultSignatureKeyID defines the default key used to sign ID
		// tokens and the user info endpoint response.
		// The key can be overridden depending on the client properties
		// "id_token_signed_response_alg" and "userinfo_signed_response_alg".
		DefaultSignatureKeyID string
		// SignatureKeyIDs contains the IDs of the keys used to sign ID tokens
		// and the user info endpoint response.
		// There should be at most one per algorithm, in other words, there should
		// not be two key IDs that point to two keys that have the same algorithm.
		SignatureKeyIDs                   []string
		EncryptionIsEnabled               bool
		KeyEncryptionAlgorithms           []jose.KeyAlgorithm
		DefaultContentEncryptionAlgorithm jose.ContentEncryption
		ContentEncryptionAlgorithms       []jose.ContentEncryption
		// IDTokenExpiresInSecs defines the expiry time of ID tokens.
		IDTokenExpiresInSecs int64
	}

	ClientAuthn struct {
		Methods []goidc.ClientAuthnType
		// PrivateKeyJWTSignatureAlgorithms contains algorithms accepted for signing
		// client assertions during private_key_jwt.
		PrivateKeyJWTSignatureAlgorithms []jose.SignatureAlgorithm
		// PrivateKeyJWTAssertionLifetimeSecs is used to validate that the assertion
		// will expire in the near future during private_key_jwt.
		PrivateKeyJWTAssertionLifetimeSecs int64
		// ClientSecretJWTSignatureAlgorithms constains algorithms accepted for
		// signing client assertions during client_secret_jwt.
		ClientSecretJWTSignatureAlgorithms []jose.SignatureAlgorithm
		// It is used to validate that the assertion will expire in the near future
		// during client_secret_jwt.
		ClientSecretJWTAssertionLifetimeSecs int64
	}

	DCR struct {
		IsEnabled              bool
		TokenRotationIsEnabled bool
		Plugin                 goidc.DCRFunc
	}

	Introspection struct {
		IsEnabled          bool
		ClientAuthnMethods []goidc.ClientAuthnType
	}

	RefreshToken struct {
		RotationIsEnabled bool
		LifetimeSecs      int64
	}

	JARM struct {
		IsEnabled                         bool
		DefaultSignatureKeyID             string
		SignatureKeyIDs                   []string
		LifetimeSecs                      int64
		EncryptionIsEnabled               bool
		KeyEncrytionAlgorithms            []jose.KeyAlgorithm
		DefaultContentEncryptionAlgorithm jose.ContentEncryption
		ContentEncryptionAlgorithms       []jose.ContentEncryption
	}

	JAR struct {
		IsEnabled                         bool
		IsRequired                        bool
		SignatureAlgorithms               []jose.SignatureAlgorithm
		LifetimeSecs                      int64
		EncryptionIsEnabled               bool
		KeyEncryptionIDs                  []string
		DefaultContentEncryptionAlgorithm jose.ContentEncryption
		ContentEncryptionAlgorithms       []jose.ContentEncryption
	}

	PAR struct {
		// IsEnabled allows client to push authorization requests.
		IsEnabled bool
		// IsRequired indicates that authorization requests can only be made if
		// they were pushed.
		IsRequired                   bool
		LifetimeSecs                 int64
		AllowUnregisteredRedirectURI bool
	}

	MTLS struct {
		IsEnabled             bool
		Host                  string
		TokenBindingIsEnabled bool
		ClientCertFunc        goidc.ClientCertFunc
	}

	DPoP struct {
		IsEnabled           bool
		IsRequired          bool
		LifetimeSecs        int
		SignatureAlgorithms []jose.SignatureAlgorithm
	}

	PKCE struct {
		IsEnabled                  bool
		IsRequired                 bool
		DefaultCodeChallengeMethod goidc.CodeChallengeMethod
		CodeChallengeMethods       []goidc.CodeChallengeMethod
	}

	AuthorizationDetails struct {
		IsEnabled bool
		Types     []string
	}

	ResourceIndicators struct {
		IsEnabled  bool // TODO.
		IsRequired bool
		Resources  []string
	}
}
