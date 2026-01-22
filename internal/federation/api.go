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
	router.Handle(
		"GET "+config.EndpointPrefix+config.OpenIDFedEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleFetchStatement), middlewares...),
	)

	if slices.Contains(config.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
		router.Handle(
			"POST "+config.EndpointPrefix+config.OpenIDFedRegistrationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleExplicitRegistration), middlewares...),
		)
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
	switch ctx.Request.Header.Get("Content-Type") {
	case contentTypeEntityStatementJWT:
		signedStatement, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.WriteError(fmt.Errorf("could not read the entity statement: %w", err))
			return
		}
		entityStatement, regErr = registerClientWithEntityConfiguration(ctx, string(signedStatement))
	case contentTypeTrustChain:
		var chainStatements []string
		_ = json.NewDecoder(ctx.Request.Body).Decode(&chainStatements)
		entityStatement, regErr = registerClientFromChainStatements(ctx, chainStatements)
	default:
		regErr = fmt.Errorf("unsupported content type: %s", ctx.Request.Header.Get("Content-Type"))
	}

	if regErr != nil {
		ctx.WriteError(regErr)
		return
	}

	if err := ctx.WriteJWTWithType(entityStatement, http.StatusOK, contentTypeExplicitRegistrationJWT); err != nil {
		ctx.WriteError(err)
	}
}
