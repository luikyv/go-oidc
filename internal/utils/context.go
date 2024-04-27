package utils

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type Context struct {
	ScopeManager        crud.ScopeManager
	GrantModelManager   crud.GrantModelManager
	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	PrivateJWKS         jose.JSONWebKeySet
	Policies            []AuthnPolicy
	RequestContext      *gin.Context
	Logger              *slog.Logger
}

func NewContext(
	scopeManager crud.ScopeManager,
	grantModelManager crud.GrantModelManager,
	clientManager crud.ClientManager,
	grantSessionManager crud.GrantSessionManager,
	authnSessionManager crud.AuthnSessionManager,
	privateJWKS jose.JSONWebKeySet,
	policies []AuthnPolicy,
	reqContext *gin.Context,
) Context {

	// Create logger.
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)
	// Set shared information.
	correlationId, _ := reqContext.MustGet(constants.CorrelationIdKey).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(constants.CorrelationIdKey, correlationId),
	)

	return Context{
		ScopeManager:        scopeManager,
		GrantModelManager:   grantModelManager,
		ClientManager:       clientManager,
		GrantSessionManager: grantSessionManager,
		AuthnSessionManager: authnSessionManager,
		PrivateJWKS:         privateJWKS,
		Policies:            policies,
		RequestContext:      reqContext,
		Logger:              logger,
	}
}

func (ctx Context) GetAvailablePolicy(session models.AuthnSession) (policy AuthnPolicy, policyIsAvailable bool) {
	for _, policy = range ctx.Policies {
		if policyIsAvailable = policy.IsAvailableFunc(session, ctx.RequestContext); policyIsAvailable {
			break
		}
	}
	return policy, policyIsAvailable
}

func (ctx Context) GetPrivateKey(keyId string) (jose.JSONWebKey, bool) {
	keys := ctx.PrivateJWKS.Key(keyId)
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
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		publicKey := privateKey.Public()
		// If the key is not of assymetric type, publicKey holds a null value.
		// To know if it is the case, we'll check if its key ID is not a null value which would mean privateKey is symetric and cannot be public.
		if publicKey.KeyID != "" {
			publicKeys = append(publicKeys, privateKey.Public())
		}
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func (ctx Context) GetSigningAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		if privateKey.Use == "sig" {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}
