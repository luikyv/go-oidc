package federation

import (
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client/validation"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func registerAutomatically(ctx oidc.Context, id string) (*goidc.Client, error) {
	clientConfig, _, err := buildAndResolveTrustChain(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("could not resolve the trust chain for client %s: %w", id, err)
	}

	return register(ctx, clientConfig, goidc.ClientRegistrationTypeAutomatic)
}

func registerExplicitlyWithEntityConfiguration(ctx oidc.Context, signedStatement string) (string, error) {
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
		return registerExplicitlyWithTrustChain(ctx, chainHeader)
	}

	chain, err := buildTrustChain(ctx, entityConfig)
	if err != nil {
		return "", err
	}

	return registerExplicitlyWithTrustChain(ctx, chain)
}

func registerExplicitlyWithChainStatements(ctx oidc.Context, chainStatements []string) (string, error) {
	chain, err := parseTrustChain(ctx, chainStatements)
	if err != nil {
		return "", err
	}

	return registerExplicitlyWithTrustChain(ctx, chain)
}

func registerExplicitlyWithTrustChain(ctx oidc.Context, chain trustChain) (string, error) {
	resolvedConfig, err := chain.resolve()
	if err != nil {
		return "", err
	}

	c, err := register(ctx, resolvedConfig, goidc.ClientRegistrationTypeExplicit)
	if err != nil {
		return "", err
	}

	now := timeutil.TimestampNow()
	statement := entityStatement{
		Issuer:         ctx.Issuer(),
		Subject:        resolvedConfig.Subject,
		Audience:       resolvedConfig.Subject,
		IssuedAt:       timeutil.TimestampNow(),
		ExpiresAt:      now + 600,
		JWKS:           resolvedConfig.JWKS,
		AuthorityHints: []string{chain.firstSubordinateStatement().Issuer},
		TrustAnchor:    resolvedConfig.TrustAnchor,
	}
	statement.Metadata.OpenIDClient = &c.ClientMeta

	return ctx.OpenIDFedSign(statement, (&jose.SignerOptions{}).WithType(jwtTypeExplicitRegistration))
}

func register(ctx oidc.Context, clientConfig entityStatement, regType goidc.ClientRegistrationType) (*goidc.Client, error) {
	if clientConfig.Metadata.OpenIDClient == nil {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the entity is not an openid client")
	}

	if !slices.Contains(clientConfig.Metadata.OpenIDClient.ClientRegistrationTypes, regType) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity %s is not registered for client registration type %s", clientConfig.Subject, regType))
	}

	c := &goidc.Client{
		ID:                         clientConfig.Subject,
		IsFederated:                true,
		FederationTrustAnchor:      clientConfig.TrustAnchor,
		FederationRegistrationType: regType,
		CreatedAtTimestamp:         timeutil.TimestampNow(),
		ExpiresAtTimestamp:         clientConfig.ExpiresAt,
		ClientMeta:                 *clientConfig.Metadata.OpenIDClient,
	}

	trustMarks, err := extractRequiredTrustMarks(ctx, clientConfig, c)
	if err != nil {
		return nil, err
	}
	c.FederationTrustMarks = trustMarks

	if err := ctx.OpenIDFedHandleClient(c); err != nil {
		return nil, err
	}

	if err := validation.Validate(ctx, clientConfig.Metadata.OpenIDClient); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid client metadata", err)
	}

	if err := ctx.SaveClient(c); err != nil {
		return nil, fmt.Errorf("could not save the federation client: %w", err)
	}
	return c, nil
}
