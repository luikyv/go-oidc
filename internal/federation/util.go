package federation

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// TODO: Improve error messages.
// TODO: Make a config for the algs used to validate the statements.
func Client(ctx oidc.Context, id string) (*goidc.Client, error) {

	clientStatement, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return nil, err
	}

	if clientStatement.Metadata.OpenIDClient == nil {
		return nil, errors.New("the entity is not an openid client")
	}

	trustChain, err := resolveTrustChain(ctx, clientStatement)
	if err != nil {
		return nil, err
	}

	clientStatement, err = applyTrustChain(ctx, clientStatement, trustChain)
	if err != nil {
		return nil, err
	}

	return &goidc.Client{
		ID:               id,
		RegistrationType: goidc.ClientRegistrationTypeAutomatic,
		ExpiresAt:        &clientStatement.ExpiresAt,
		ClientMetaInfo:   clientStatement.Metadata.OpenIDClient.ClientMetaInfo,
	}, nil
}

func resolveTrustChain(
	ctx oidc.Context,
	entityConfig entityStatement,
) (
	[]entityStatement,
	error,
) {

	var errs error
	for _, authorityID := range entityConfig.AuthorityHints {
		trustChain, err := resolveTrustChainBranch(ctx, entityConfig, authorityID)
		if err == nil {
			return trustChain, nil
		}
		errs = errors.Join(errs, err)
	}

	return nil, fmt.Errorf("could not resolve trust chain for entity %s: %w", entityConfig.Subject, errs)
}

func resolveTrustChainBranch(
	ctx oidc.Context,
	entityConfig entityStatement,
	authorityID string,
) (
	[]entityStatement,
	error,
) {
	authorityConfig, err := fetchEntityConfiguration(ctx, authorityID)
	if err != nil {
		return nil, err
	}

	subordinateStatement, err := fetchSubordinateStatement(ctx, entityConfig.Subject, authorityConfig)
	if err != nil {
		return nil, err
	}

	_, err = parseEntityConfiguration(ctx, entityConfig.Signed(), entityConfig.Subject, subordinateStatement.JWKS)
	if err != nil {
		return nil, err
	}

	if slices.Contains(ctx.OpenIDFedTrustedAuthorities, authorityConfig.Issuer) {
		return []entityStatement{authorityConfig, subordinateStatement}, nil
	}

	trustChain, err := resolveTrustChain(ctx, authorityConfig)
	if err != nil {
		return nil, err
	}

	trustChain = append([]entityStatement{subordinateStatement}, trustChain...)
	if len(trustChain) > ctx.OpenIDFedTrustChainMaxDepth {
		return nil, errors.New("trust chain maximum depth reached")
	}
	return trustChain, nil
}

// fetchSubordinateStatement fetches a subordinate statement.
// A subordinate statement is an entity statement issued by a superior authority
// about an immediate subordinate.
func fetchSubordinateStatement(
	ctx oidc.Context,
	sub string,
	authority entityStatement,
) (
	entityStatement,
	error,
) {
	// TODO: Validate the error.
	uri, _ := url.Parse(authority.Metadata.FederationAuthority.FetchEndpoint)
	params := uri.Query()
	params.Add("sub", sub)
	uri.RawQuery = params.Encode()

	signedStatement, err := fetchEntityStatement(ctx, uri.String())
	if err != nil {
		return entityStatement{}, err
	}

	subStatement, err := parseEntityStatement(ctx, signedStatement, sub, authority.Issuer, authority.JWKS)
	if err != nil {
		return entityStatement{}, err
	}

	if len(subStatement.AuthorityHints) != 0 {
		return entityStatement{}, errors.New("a subordinate statement must not have authority hints")
	}

	return parseEntityStatement(ctx, signedStatement, sub, authority.Issuer, authority.JWKS)
}

// fetchEntityConfiguration fetches an entity's configuration.
// The entity configuration is issued by an entity about itself.
func fetchEntityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {
	signedStatement, err := fetchEntityStatement(ctx, id+"/.well-known/openid-federation")
	if err != nil {
		return entityStatement{}, err
	}

	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity statement for %s: %w", id, err)
	}

	var statement entityStatement
	if err := parsedStatement.UnsafeClaimsWithoutVerification(&statement); err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity statement for %s: %w", id, err)
	}

	return parseEntityConfiguration(ctx, signedStatement, id, statement.JWKS)
}

func fetchEntityStatement(ctx oidc.Context, uri string) (string, error) {
	resp, err := ctx.HTTPClient().Get(uri)
	if err != nil {
		return "", fmt.Errorf("could not fetch the entity statement: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching the entity statement resulted in status %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/entity-statement+jwt" {
		return "", fmt.Errorf("fetching the entity statement resulted in content type %s which is invalid", resp.Header.Get("Content-Type"))
	}

	signedStatement, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read the entity statement: %w", err)
	}

	return string(signedStatement), nil
}

func parseEntityConfiguration(
	ctx oidc.Context,
	signedStatement, entityID string,
	jwks jose.JSONWebKeySet,
) (
	entityStatement,
	error,
) {
	return parseEntityStatement(ctx, signedStatement, entityID, entityID, jwks)
}

func parseEntityStatement(
	ctx oidc.Context,
	signedStatement, entityID, authorityID string,
	jwks jose.JSONWebKeySet,
) (
	entityStatement,
	error,
) {
	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity statement: %w", err)
	}

	if parsedStatement.Headers[0].ExtraHeaders["typ"] != "entity-statement+jwt" {
		return entityStatement{}, errors.New("invalid entity statement 'typ' header")
	}

	var statement entityStatement
	var claims jwt.Claims
	if err := parsedStatement.Claims(jwks, &claims, &statement); err != nil {
		return entityStatement{}, fmt.Errorf("invalid entity statement signature: %w", err)
	}

	if claims.IssuedAt == nil {
		return entityStatement{}, fmt.Errorf("invalid 'iat' claim in the entity statement: %w", err)
	}

	if claims.Expiry == nil {
		return entityStatement{}, fmt.Errorf("invalid 'exp' claim in the entity statement: %w", err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:  authorityID,
		Subject: entityID,
	}); err != nil {
		return entityStatement{}, fmt.Errorf("invalid entity statement: %w", err)
	}

	// TODO: Add validations for metadata policy, ...

	statement.signed = signedStatement
	return statement, nil
}

func applyTrustChain(
	_ oidc.Context,
	config entityStatement,
	chain []entityStatement,
) (
	entityStatement,
	error,
) {
	var policy metadataPolicy
	for _, authority := range chain {

		if authority.ExpiresAt < config.ExpiresAt {
			config.ExpiresAt = authority.ExpiresAt
		}

		if authority.MetadataPolicy == nil {
			continue
		}

		var err error
		policy, err = authority.MetadataPolicy.merge(policy)
		if err != nil {
			return entityStatement{}, err
		}
	}

	return policy.apply(config)
}

func newEntityStatement(ctx oidc.Context) (string, error) {
	publicJWKS, err := ctx.PublicOpenIDFedJWKS()
	if err != nil {
		return "", err
	}

	now := timeutil.TimestampNow()
	statement := entityStatement{
		Issuer:         ctx.Host,
		Subject:        ctx.Host,
		IssuedAt:       timeutil.TimestampNow(),
		ExpiresAt:      now + 600,
		JWKS:           jose.JSONWebKeySet(publicJWKS),
		AuthorityHints: ctx.OpenIDFedAuthorityHints,
	}
	statement.Metadata.OpenIDProvider = &openIDProvider{
		ClientRegistrationTypes: ctx.OpenIDFedClientRegTypes,
		OpenIDConfiguration:     discovery.NewOIDCConfig(ctx),
	}

	ops := (&jose.SignerOptions{}).WithType("entity-statement+jwt")
	return ctx.OpenIDFedSign(statement, ops)
}
