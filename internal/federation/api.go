package federation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.OpenIDFedIsEnabled {
		return
	}
	router.Handle("GET "+config.EndpointPrefix+config.OpenIDFedEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleFetchStatement), middlewares...))

	if slices.Contains(config.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
		router.Handle("POST "+config.EndpointPrefix+config.OpenIDFedRegistrationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleExplicitRegistration), middlewares...))
	}

	if slices.Contains(config.OpenIDFedJWKSRepresentations, goidc.JWKSRepresentationSignedURI) {
		router.Handle("GET "+config.EndpointPrefix+config.OpenIDFedSignedJWKSEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleSignedJWKS), middlewares...))
	}
}

func handleFetchStatement(ctx oidc.Context) {
	statement, err := newEntityConfiguration(ctx)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.WriteJWTWithType(statement, http.StatusOK, contentTypeEntityStatementJWT); err != nil {
		ctx.WriteError(err)
	}
}

func handleExplicitRegistration(ctx oidc.Context) {
	var entityStatement string
	var regErr error
	mediaType := ctx.MediaType()
	switch mediaType {
	case contentTypeEntityStatementJWT:
		signedStatement, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.WriteError(fmt.Errorf("could not read the entity statement: %w", err))
			return
		}
		entityStatement, regErr = registerEntityConfiguration(ctx, string(signedStatement))
	case contentTypeTrustChain:
		var chainStatements []string
		if err := json.NewDecoder(ctx.Request.Body).Decode(&chainStatements); err != nil {
			regErr = goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", err)
			break
		}
		entityStatement, regErr = registerChainStatements(ctx, chainStatements)
	default:
		regErr = goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			fmt.Errorf("unsupported content type %q", mediaType))
	}

	if regErr != nil {
		ctx.WriteError(regErr)
		return
	}

	if err := ctx.WriteJWTWithType(entityStatement, http.StatusOK, contentTypeExplicitRegistrationJWT); err != nil {
		ctx.WriteError(err)
	}
}

func handleSignedJWKS(ctx oidc.Context) {
	signedJWKS, err := signedJWKS(ctx)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.WriteJWTWithType(signedJWKS, http.StatusOK, contentTypeJWKSJWT); err != nil {
		ctx.WriteError(err)
	}
}
