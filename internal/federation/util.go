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
	"github.com/luikyv/go-oidc/internal/joseutil"
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

	clientStatement, err = applyTrustChainPolicies(ctx, clientStatement, trustChain)
	if err != nil {
		return nil, err
	}

	return &goidc.Client{
		ID:             id,
		ClientMetaInfo: clientStatement.Metadata.OpenIDClient.ClientMetaInfo,
	}, nil
}

func resolveTrustChain(
	ctx oidc.Context,
	entityConfig openIDEntityStatement,
) (
	[]openIDEntityStatement,
	error,
) {

	// TODO: Remove this.
	if len(entityConfig.AuthorityHints) == 0 {
		return []openIDEntityStatement{entityConfig}, nil
	}

	var errs []error
	for _, authorityID := range entityConfig.AuthorityHints {
		trustChain, err := resolveTrustChainBranch(ctx, entityConfig, authorityID)
		if err == nil {
			return trustChain, nil
		}
		errs = append(errs, err)
	}

	return nil, fmt.Errorf("could not resolve trust chain for entity %s: %v", entityConfig.Subject, errs)
}

func resolveTrustChainBranch(
	ctx oidc.Context,
	entityConfig openIDEntityStatement,
	authorityID string,
) (
	[]openIDEntityStatement,
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
		return []openIDEntityStatement{authorityConfig, subordinateStatement}, nil
	}

	trustChain, err := resolveTrustChain(ctx, authorityConfig)
	if err != nil {
		return nil, err
	}

	trustChain = append(trustChain, subordinateStatement)
	if len(trustChain) > ctx.OpenIDFedTrustChainMaxDepth {
		return nil, errors.New("trust chain maximum depth reached")
	}
	return trustChain, nil
}

func fetchSubordinateStatement(
	ctx oidc.Context,
	subordinateID string,
	authority openIDEntityStatement,
) (
	openIDEntityStatement,
	error,
) {
	// TODO: Validate the error.
	uri, _ := url.Parse(authority.Metadata.OpenIDAuthority.FetchEndpoint)
	params := uri.Query()
	params.Add("sub", subordinateID)
	uri.RawQuery = params.Encode()

	signedStatement, err := fetchEntityStatement(ctx, uri.String())
	if err != nil {
		return openIDEntityStatement{}, err
	}

	return parseEntityStatement(ctx, signedStatement, subordinateID, authority.Issuer, authority.JWKS)
}

func fetchEntityConfiguration(
	ctx oidc.Context,
	entityID string,
) (
	openIDEntityStatement,
	error,
) {
	signedStatement, err := fetchEntityStatement(ctx, entityID+"/.well-known/openid-federation")
	if err != nil {
		return openIDEntityStatement{}, err
	}

	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return openIDEntityStatement{}, fmt.Errorf("could not parse the entity statement for %s: %w", entityID, err)
	}

	var statement openIDEntityStatement
	if err := parsedStatement.UnsafeClaimsWithoutVerification(&statement); err != nil {
		return openIDEntityStatement{}, fmt.Errorf("could not parse the entity statement for %s: %w", entityID, err)
	}

	return parseEntityConfiguration(ctx, signedStatement, entityID, statement.JWKS)
}

func fetchEntityStatement(ctx oidc.Context, uri string) (string, error) {
	// TODO: Validate the content type.
	resp, err := ctx.HTTPClient().Get(uri)
	if err != nil {
		return "", fmt.Errorf("could not fetch the entity statement: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching the entity statement resulted in status %d", resp.StatusCode)
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
	openIDEntityStatement,
	error,
) {
	return parseEntityStatement(ctx, signedStatement, entityID, entityID, jwks)
}

func parseEntityStatement(
	ctx oidc.Context,
	signedStatement, entityID, authorityID string,
	jwks jose.JSONWebKeySet,
) (
	openIDEntityStatement,
	error,
) {
	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return openIDEntityStatement{}, fmt.Errorf("could not parse the entity statement: %w", err)
	}

	if parsedStatement.Headers[0].ExtraHeaders["typ"] != "entity-statement+jwt" {
		return openIDEntityStatement{}, errors.New("invalid entity statement 'typ' header")
	}

	var statement openIDEntityStatement
	var claims jwt.Claims
	if err := parsedStatement.Claims(jwks, &claims, &statement); err != nil {
		return openIDEntityStatement{}, fmt.Errorf("invalid entity statement signature: %w", err)
	}

	if claims.IssuedAt == nil {
		return openIDEntityStatement{}, fmt.Errorf("invalid 'iat' claim in the entity statement: %w", err)
	}

	if claims.Expiry == nil {
		return openIDEntityStatement{}, fmt.Errorf("invalid 'exp' claim in the entity statement: %w", err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:  authorityID,
		Subject: entityID,
	}); err != nil {
		return openIDEntityStatement{}, fmt.Errorf("invalid entity statement: %w", err)
	}

	// TODO: Add validations for metadata policy, ...

	statement.signed = signedStatement
	return statement, nil
}

func applyTrustChainPolicies(
	_ oidc.Context,
	entityConfig openIDEntityStatement,
	chain []openIDEntityStatement,
) (
	openIDEntityStatement,
	error,
) {
	var policy metadataPolicy
	for _, authority := range chain {
		if authority.MetadataPolicy == nil {
			continue
		}

		var err error
		policy, err = policy.merge(*authority.MetadataPolicy)
		if err != nil {
			return openIDEntityStatement{}, err
		}
	}

	return policy.apply(entityConfig)
}

func newEntityStatement(ctx oidc.Context) (string, error) {
	now := timeutil.TimestampNow()
	statement := openIDEntityStatement{
		Issuer:    ctx.Host,
		Subject:   ctx.Host,
		IssuedAt:  timeutil.TimestampNow(),
		ExpiresAt: now + 600,
		JWKS: jose.JSONWebKeySet{
			Keys: ctx.OpenIDFedJWKS.Keys,
		},
		AuthorityHints: ctx.OpenIDFedAuthorityHints,
	}
	statement.Metadata.OpenIDProvider = &openIDProvider{
		OpenIDConfiguration: discovery.NewOIDCConfig(ctx),
	}

	jwk := ctx.OpenIDFedJWKS.Keys[0]
	ops := (&jose.SignerOptions{}).WithType("entity-statement+jwt")
	return joseutil.SignWithJWK(statement, jwk, ops)
}
