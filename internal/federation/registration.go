package federation

import (
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func registerEntityConfiguration(ctx oidc.Context, signedStatement string) (string, error) {
	entityConfig, err := parseEntityConfiguration(ctx, signedStatement, &parseOptions{
		explicitRegistration: true,
	})
	if err != nil {
		return "", err
	}

	if chainHeader := entityConfig.TrustChainHeader(); chainHeader != nil {
		// [OpenID Fed §12.2.2] The config in the trust chain header is only used to establish trust.
		// The config that must be used for all other purposes is the subject's config.
		chainHeader[0] = entityConfig
		return registerClientExplicitly(ctx, chainHeader)
	}

	chain, err := buildTrustChain(ctx, entityConfig)
	if err != nil {
		return "", err
	}

	return registerClientExplicitly(ctx, chain)
}

func registerChainStatements(ctx oidc.Context, chainStatements []string) (string, error) {
	chain, err := parseTrustChain(ctx, chainStatements)
	if err != nil {
		return "", err
	}

	return registerClientExplicitly(ctx, chain)
}

func registerClientExplicitly(ctx oidc.Context, chain trustChain) (string, error) {
	c, err := resolveClient(ctx, chain)
	if err != nil {
		return "", err
	}

	if !slices.Contains(c.ClientRegistrationTypes, goidc.ClientRegistrationTypeExplicit) {
		return "", goidc.NewError(goidc.ErrorCodeInvalidRequest, "the entity is not registered for explicit registration")
	}

	if err := ctx.SaveClient(c); err != nil {
		return "", fmt.Errorf("could not save the federation client: %w", err)
	}

	now := timeutil.TimestampNow()
	statement := entityStatement{
		Issuer:         ctx.Issuer(),
		Subject:        chain.subjectConfig().Subject,
		Audience:       chain.subjectConfig().Subject,
		IssuedAt:       now,
		ExpiresAt:      now + 600,
		JWKS:           chain.subjectConfig().JWKS,
		AuthorityHints: []string{chain.firstSubordinateStatement().Issuer},
		TrustAnchor:    c.Federation.TrustAnchor,
	}
	statement.Metadata.OpenIDClient = &c.ClientMeta

	return ctx.OpenIDFedSign(statement, (&jose.SignerOptions{}).WithType(jwtTypeExplicitRegistration))
}
