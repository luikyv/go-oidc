package utils

import (
	"crypto/x509"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GetTokenOptionsFunc func(client models.Client, scopes string) (models.TokenOptions, error)

type DcrPluginFunc func(ctx Context, dynamicClient *models.DynamicClientRequest)

type Configuration struct {
	Profile constants.Profile
	// Host where the server runs. This value will be used the auth server issuer.
	Host                string
	MtlsIsEnabled       bool
	MtlsHost            string
	Scopes              []string
	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	// The server JWKS containing private and public information.
	// When exposing it, the private information is removed.
	PrivateJwks jose.JSONWebKeySet
	// The default key used to sign access tokens. The key can be overridden with the TokenOptions.
	DefaultTokenSignatureKeyId      string
	GrantTypes                      []constants.GrantType
	ResponseTypes                   []constants.ResponseType
	ResponseModes                   []constants.ResponseMode
	ClientAuthnMethods              []constants.ClientAuthnType
	IntrospectionIsEnabled          bool
	IntrospectionClientAuthnMethods []constants.ClientAuthnType
	// The algorithms accepted for signing client assertions during private_key_jwt.
	PrivateKeyJwtSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during private_key_jwt.
	PrivateKeyJwtAssertionLifetimeSecs int
	// The algorithms accepted for signing client assertions during client_secret_jwt.
	ClientSecretJwtSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during client_secret_jwt.
	ClientSecretJwtAssertionLifetimeSecs int
	OpenIdScopeIsRequired                bool
	// The default key used to sign ID tokens.
	// The key can be overridden depending on the client property "id_token_signed_response_alg".
	DefaultIdTokenSignatureKeyId string
	// It defines the expiry time of ID tokens.
	IdTokenExpiresInSecs int
	// The IDs of the keys used to sign ID tokens. There should be at most one per algorithm.
	// In other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
	IdTokenSignatureKeyIds             []string
	IdTokenEncryptionIsEnabled         bool
	IdTokenEncryptionIsRequired        bool
	IdTokenKeyEncryptionAlgorithms     []jose.KeyAlgorithm
	IdTokenContentEncryptionAlgorithms []jose.ContentEncryption // TODO: Validate that A128CBC-HS256 is supported for openid.
	ShouldRotateRefreshTokens          bool
	RefreshTokenLifetimeSecs           int
	// The user claims that can be returned in the userinfo endpoint or in the ID token.
	// This will be transmitted in the /.well-known/openid-configuration endpoint.
	UserClaims []string
	// The claim types supported by the server.
	ClaimTypes []constants.ClaimType
	// If true, the "iss" parameter will be returned when redirecting the user back to the client application.
	IssuerResponseParameterIsEnabled bool
	// It informs the clients whether the server accepts the "claims" parameter.
	// This will be transmitted in the /.well-known/openid-configuration endpoint.
	ClaimsParameterIsEnabled  bool
	JarmIsEnabled             bool
	JarmLifetimeSecs          int
	DefaultJarmSignatureKeyId string
	JarmSignatureKeyIds       []string
	JarIsEnabled              bool
	JarIsRequired             bool
	JarSignatureAlgorithms    []jose.SignatureAlgorithm
	JarLifetimeSecs           int
	// It allows client to push authorization requests.
	ParIsEnabled bool
	// If true, authorization requests can only be made if they were pushed.
	ParIsRequired                    bool
	ParLifetimeSecs                  int
	DpopIsEnabled                    bool
	DpopIsRequired                   bool
	DpopLifetimeSecs                 int
	DpopSignatureAlgorithms          []jose.SignatureAlgorithm
	PkceIsEnabled                    bool
	PkceIsRequired                   bool
	CodeChallengeMethods             []constants.CodeChallengeMethod
	SubjectIdentifierTypes           []constants.SubjectIdentifierType
	Policies                         []AuthnPolicy
	GetTokenOptions                  GetTokenOptionsFunc
	DcrIsEnabled                     bool
	ShouldRotateRegistrationTokens   bool
	DcrPlugin                        DcrPluginFunc
	AuthenticationSessionTimeoutSecs int
	TlsBoundTokensIsEnabled          bool
	CorrelationIdHeader              string
	AuthenticationContextReferences  []constants.AuthenticationContextReference
	DisplayValues                    []constants.DisplayValue
	// If true, at least one mechanism of sender contraining tokens is required, either DPoP or client TLS.
	SenderConstrainedTokenIsRequired bool
}

type Context struct {
	Configuration
	Request  *http.Request
	Response http.ResponseWriter
	Logger   *slog.Logger
}

func NewContext(
	configuration Configuration,
	req *http.Request,
	resp http.ResponseWriter,
) Context {

	// Create the logger.
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)

	// Set shared information.
	correlationId := req.Context().Value(constants.CorrelationIdKey).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(string(constants.CorrelationIdKey), correlationId),
	)

	return Context{
		Configuration: configuration,
		Request:       req,
		Response:      resp,
		Logger:        logger,
	}
}

func (ctx Context) GetPrivateKey(keyId string) (jose.JSONWebKey, bool) {
	keys := ctx.PrivateJwks.Key(keyId)
	if len(keys) != 1 {
		return jose.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx Context) GetPublicKey(keyId string) (jose.JSONWebKey, bool) {
	privateKey, ok := ctx.GetPrivateKey(keyId)
	if !ok {
		return jose.JSONWebKey{}, false
	}

	publicKey := privateKey.Public()
	if publicKey.KeyID == "" {
		return jose.JSONWebKey{}, false
	}

	return publicKey, true
}

func (ctx Context) GetPublicKeys() jose.JSONWebKeySet {
	publicKeys := []jose.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJwks.Keys {
		publicKey := privateKey.Public()
		if publicKey.Valid() {
			publicKeys = append(publicKeys, publicKey)
		}
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func (ctx Context) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, privateKey := range ctx.PrivateJwks.Keys {
		if privateKey.Use == string(constants.KeySignatureUsage) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}

func (ctx Context) GetTokenSignatureKey(tokenOptions models.TokenOptions) jose.JSONWebKey {
	keyId := tokenOptions.JwtSignatureKeyId
	if keyId == "" {
		keyId = ctx.DefaultTokenSignatureKeyId
	}
	key, _ := ctx.GetPrivateKey(keyId)
	return key
}

func (ctx Context) GetUserInfoSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getSignatureKey(client.UserInfoSignatureAlgorithm, ctx.DefaultIdTokenSignatureKeyId, ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetUserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetIdTokenSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getSignatureKey(client.IdTokenSignatureAlgorithm, ctx.DefaultIdTokenSignatureKeyId, ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetIdTokenSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetJarmSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getSignatureKey(client.JarmSignatureAlgorithm, ctx.DefaultJarmSignatureKeyId, ctx.JarmSignatureKeyIds)
}

func (ctx Context) GetJarmSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.JarmSignatureKeyIds)
}

func (ctx Context) getSignatureAlgorithms(keyIds []string) []jose.SignatureAlgorithm {
	signatureAlgorithms := []jose.SignatureAlgorithm{}
	for _, keyId := range keyIds {
		key, _ := ctx.GetPrivateKey(keyId)
		signatureAlgorithms = append(signatureAlgorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	return signatureAlgorithms
}

// From the subset of keys defined by keyIds, try to find a key that matches signatureAlgorithm.
// If no key is found, return the key associated to defaultKeyId.
func (ctx Context) getSignatureKey(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyId string,
	keyIds []string,
) jose.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyId := range keyIds {
			key, _ := ctx.GetPrivateKey(keyId)
			if key.Algorithm == string(signatureAlgorithm) && key.Use == string(constants.KeySignatureUsage) {
				return key
			}
		}
	}

	key, _ := ctx.GetPrivateKey(defaultKeyId)
	return key
}

func (ctx Context) GetClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	return append(ctx.PrivateKeyJwtSignatureAlgorithms, ctx.ClientSecretJwtSignatureAlgorithms...)
}

func (ctx Context) GetIntrospectionClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	var signatureAlgorithms []jose.SignatureAlgorithm

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, constants.PrivateKeyJwtAuthn) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.PrivateKeyJwtSignatureAlgorithms...)
	}

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, constants.ClientSecretJwt) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.ClientSecretJwtSignatureAlgorithms...)
	}

	return signatureAlgorithms
}

func (ctx Context) GetBearerToken() (token string, ok bool) {
	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != constants.BearerTokenType {
		return "", false
	}

	return token, true
}

func (ctx Context) GetAuthorizationToken() (
	token string,
	tokenType constants.TokenType,
	ok bool,
) {
	tokenHeader, ok := ctx.GetHeader("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], constants.TokenType(tokenParts[0]), true
}

// Get the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func (ctx Context) GetDpopJwt() (string, bool) {
	// Consider case insensitive headers by canonicalizing them.
	canonicalizedDpopHeader := textproto.CanonicalMIMEHeaderKey(constants.DpopHeader)
	canonicalizedHeaders := textproto.MIMEHeader(ctx.Request.Header)

	values := canonicalizedHeaders[canonicalizedDpopHeader]
	if values == nil || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func (ctx Context) GetSecureClientCertificate() (*x509.Certificate, bool) {
	rawClientCert, ok := ctx.GetHeader(constants.SecureClientCertificateHeader)
	if !ok {
		ctx.Logger.Debug("the secure client certificate was not informed")
		return nil, false
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		ctx.Logger.Debug("could not parse the client certificate")
		return nil, false
	}

	ctx.Logger.Debug("secure client certificate was found")
	return clientCert, true
}

// Try to get the secure client certificate first, if it's not informed,
// fallback to the insecure one.
func (ctx Context) GetClientCertificate() (*x509.Certificate, bool) {
	rawClientCert, ok := ctx.GetHeader(constants.SecureClientCertificateHeader)
	if !ok {
		ctx.Logger.Debug("the secure client certificate was not informed, trying the insecure one")
		rawClientCert, ok = ctx.GetHeader(constants.InsecureClientCertificateHeader)
		if !ok {
			ctx.Logger.Debug("the insecure client certificate was not informed")
			return nil, false
		}
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		ctx.Logger.Debug("could not parse the client certificate")
		return nil, false
	}

	ctx.Logger.Debug("client certificate was found")
	return clientCert, true
}

func (ctx Context) GetHeader(header string) (string, bool) {
	value := ctx.Request.Header.Get(header)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx Context) GetClient(clientId string) (models.Client, error) {
	client, err := ctx.ClientManager.Get(clientId)
	if err != nil {
		return models.Client{}, err
	}

	// This will allow the method client.GetPublicJwks to cache the client keys if they fetched from the JWKS URI.
	if client.PublicJwks == nil {
		client.PublicJwks = &jose.JSONWebKeySet{}
	}
	return client, nil
}

func (ctx Context) ExecuteDcrPlugin(dynamicClient *models.DynamicClientRequest) {
	if ctx.DcrPlugin != nil {
		ctx.DcrPlugin(ctx, dynamicClient)
	}
}

func (ctx Context) Redirect(redirectUrl string) {
	http.Redirect(ctx.Response, ctx.Request, redirectUrl, http.StatusSeeOther)
}

func (ctx Context) RenderHtml(html string, params any) {
	tmpl, _ := template.New("name").Parse(html)
	tmpl.Execute(ctx.Response, params)
}

func (ctx Context) RenderHtmlTemplate(tmpl *template.Template, params any) {
	tmpl.Execute(ctx.Response, params)
}

func (ctx Context) GetRequestMethod() string {
	return ctx.Request.Method
}

func (ctx Context) GetRequestUrl() string {
	// TODO: Improve this.
	return "https://" + ctx.Request.Host + ctx.Request.URL.RequestURI()
}

// Get the audiences that will be accepted when validating client assertions.
func (ctx Context) GetClientAssertionAudiences() []string {
	audiences := []string{ctx.Host, ctx.Host + string(constants.TokenEndpoint), ctx.Host + ctx.Request.URL.RequestURI()}
	if ctx.MtlsIsEnabled {
		audiences = append(audiences, ctx.MtlsHost, ctx.MtlsHost+string(constants.TokenEndpoint), ctx.MtlsHost+ctx.Request.URL.RequestURI())
	}
	return audiences
}

func (ctx Context) GetFormData() map[string]any {

	if err := ctx.Request.ParseForm(); err != nil {
		return map[string]any{}
	}

	formData := make(map[string]any)
	for param, values := range ctx.Request.PostForm {
		formData[param] = values[0]
	}
	return formData
}

func (ctx Context) GetPolicyById(policyId string) AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.Id == policyId {
			return policy
		}
	}
	return AuthnPolicy{}
}

func (ctx Context) GetAvailablePolicy(client models.Client, session models.AuthnSession) (
	policy AuthnPolicy,
	ok bool,
) {
	for _, policy = range ctx.Policies {
		if ok = policy.IsAvailableFunc(ctx, client, session); ok {
			return policy, true
		}
	}

	return AuthnPolicy{}, false
}

func (ctx Context) WriteJson(obj any, status int) error {
	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(status)
	if err := json.NewEncoder(ctx.Response).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteJwt(token string, status int) error {
	ctx.Response.Header().Set("Content-Type", "application/jwt")
	ctx.Response.WriteHeader(status)

	if _, err := ctx.Response.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}
