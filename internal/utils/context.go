package utils

import (
	"crypto/x509"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GetTokenOptionsFunc func(client models.Client, scopes string) models.TokenOptions

type DcrPluginFunc func(ctx Context, dynamicClient *models.DynamicClientRequest)

type Configuration struct {
	Profile       constants.Profile
	Host          string
	MtlsIsEnabled bool
	MtlsHost      string
	Scopes        []string

	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager

	PrivateJwks                          jose.JSONWebKeySet
	DefaultTokenSignatureKeyId           string
	GrantTypes                           []constants.GrantType
	ResponseTypes                        []constants.ResponseType
	ResponseModes                        []constants.ResponseMode
	ClientAuthnMethods                   []constants.ClientAuthnType
	IntrospectionIsEnabled               bool
	IntrospectionClientAuthnMethods      []constants.ClientAuthnType
	PrivateKeyJwtSignatureAlgorithms     []jose.SignatureAlgorithm
	PrivateKeyJwtAssertionLifetimeSecs   int
	ClientSecretJwtSignatureAlgorithms   []jose.SignatureAlgorithm
	ClientSecretJwtAssertionLifetimeSecs int
	OpenIdScopeIsRequired                bool
	IdTokenExpiresInSecs                 int
	DefaultIdTokenSignatureKeyId         string
	IdTokenSignatureKeyIds               []string
	ShouldRotateRefreshTokens            bool
	RefreshTokenLifetimeSecs             int
	CustomClaims                         []constants.Claim
	ClaimTypes                           []constants.ClaimType
	IssuerResponseParameterIsEnabled     bool
	ClaimsParameterIsEnabled             bool
	JarmIsEnabled                        bool
	JarmLifetimeSecs                     int
	DefaultJarmSignatureKeyId            string
	JarmSignatureKeyIds                  []string
	JarIsEnabled                         bool
	JarIsRequired                        bool
	JarSignatureAlgorithms               []jose.SignatureAlgorithm
	ParIsEnabled                         bool
	ParIsRequired                        bool
	ParLifetimeSecs                      int
	DpopIsEnabled                        bool
	DpopIsRequired                       bool
	DpopLifetimeSecs                     int
	DpopSignatureAlgorithms              []jose.SignatureAlgorithm
	PkceIsEnabled                        bool
	PkceIsRequired                       bool
	CodeChallengeMethods                 []constants.CodeChallengeMethod
	SubjectIdentifierTypes               []constants.SubjectIdentifierType
	Policies                             []AuthnPolicy
	GetTokenOptions                      GetTokenOptionsFunc
	DcrIsEnabled                         bool
	ShouldRotateRegistrationTokens       bool
	DcrPlugin                            DcrPluginFunc
	AuthenticationSessionTimeoutSecs     int
	TlsBoundTokensIsEnabled              bool
	CorrelationIdHeader                  constants.Header
	CaCertificatePool                    *x509.CertPool
	AuthenticationContextReferences      []constants.AuthenticationContextReference
	DisplayValues                        []constants.DisplayType
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
	correlationId := req.Context().Value(constants.CorrelationId).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(string(constants.CorrelationId), correlationId),
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

func (ctx Context) getSignatureKey(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyId string,
	keyIds []string,
) jose.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyId := range keyIds {
			key, _ := ctx.GetPrivateKey(keyId)
			if key.Algorithm == string(signatureAlgorithm) {
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

func (ctx Context) GetDpopJwt() (string, bool) {
	return ctx.GetHeader(string(constants.DpopHeader))
}

func (ctx Context) GetHeader(header string) (string, bool) {
	values, ok := ctx.Request.Header[header]
	if !ok || len(values) == 0 {
		return "", false
	}

	return values[0], true
}

func (ctx Context) GetClient(clientId string) (models.Client, error) {
	return ctx.ClientManager.Get(clientId)
}

func (ctx Context) ExecureDcrPlugin(dynamicClient *models.DynamicClientRequest) {
	if ctx.DcrPlugin != nil {
		ctx.DcrPlugin(ctx, dynamicClient)
	}
}

func (ctx Context) Redirect(redirectUrl string) {
	http.Redirect(ctx.Response, ctx.Request, redirectUrl, http.StatusFound)
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
	return ctx.Host + ctx.Request.URL.RequestURI()
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
	if err := json.NewEncoder(ctx.Response).Encode(token); err != nil {
		return err
	}

	return nil
}
