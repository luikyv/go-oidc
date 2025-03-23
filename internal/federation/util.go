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

func Client(ctx oidc.Context, id string) (*goidc.Client, error) {
	clientConfig, _, err := buildAndResolveTrustChain(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("could not resolve the trust chain for client %s: %w", id, err)
	}

	if clientConfig.Metadata.OpenIDClient == nil {
		return nil, errors.New("the entity is not an openid client")
	}

	trustMarks, err := extractRequiredTrustMarks(ctx, clientConfig)
	if err != nil {
		return nil, err
	}

	return &goidc.Client{
		ID:               id,
		IsFederated:      true,
		RegistrationType: goidc.ClientRegistrationTypeAutomatic,
		TrustMarkIDs:     trustMarks,
		ExpiresAt:        &clientConfig.ExpiresAt,
		ClientMeta:       clientConfig.Metadata.OpenIDClient.ClientMeta,
	}, nil
}

// buildAndResolveTrustChain builds a trust chain and then resolves it to obtain
// the final entity statement for the given entity ID.
func buildAndResolveTrustChain(ctx oidc.Context, id string) (entityStatement, trustChain, error) {
	chain, err := buildTrustChain(ctx, id)
	if err != nil {
		return entityStatement{}, nil, fmt.Errorf("could not build the trust chain for client %s: %w", id, err)
	}

	config, err := resolveTrustChain(ctx, chain)
	if err != nil {
		return entityStatement{}, nil, fmt.Errorf("could not resolve the trust chain for client %s: %w", id, err)
	}

	return config, chain, nil
}

// buildTrustChain finds a sequence of entity statements that represents a chain
// starting at an entity configuration that is the subject of the chain and ending
// in a trust anchor.
func buildTrustChain(ctx oidc.Context, id string) (trustChain, error) {

	entityConfig, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return nil, err
	}

	chain, err := buildTrustChainFromConfig(ctx, entityConfig)
	if err != nil {
		return nil, err
	}

	return append([]entityStatement{entityConfig}, chain...), nil
}

func buildTrustChainFromConfig(ctx oidc.Context, entityConfig entityStatement) (trustChain, error) {
	var errs error
	for _, authorityID := range entityConfig.AuthorityHints {

		authorityConfig, err := fetchAuthorityConfiguration(ctx, authorityID)
		if err != nil {
			return nil, err
		}

		chain, err := buildTrustChainBranch(ctx, entityConfig, authorityConfig)
		if err == nil {
			return chain, nil
		}
		errs = errors.Join(errs, err)
	}

	return nil, fmt.Errorf("could not resolve trust chain for entity %s: %w", entityConfig.Subject, errs)
}

func buildTrustChainBranch(ctx oidc.Context, entityConfig entityStatement, authorityConfig entityStatement) (trustChain, error) {
	subordinateStatement, err := fetchSubordinateStatement(ctx, entityConfig.Subject, authorityConfig)
	if err != nil {
		return nil, err
	}

	_, err = parseEntityConfiguration(ctx, entityConfig.Signed(), entityConfig.Subject, subordinateStatement.JWKS)
	if err != nil {
		return nil, err
	}

	if slices.Contains(ctx.OpenIDFedTrustedAuthorities, authorityConfig.Issuer) {
		return []entityStatement{subordinateStatement, authorityConfig}, nil
	}

	chain, err := buildTrustChainFromConfig(ctx, authorityConfig)
	if err != nil {
		return nil, err
	}

	chain = append([]entityStatement{subordinateStatement}, chain...)
	if len(chain) > ctx.OpenIDFedTrustChainMaxDepth {
		return nil, errors.New("trust chain maximum depth reached")
	}
	return chain, nil
}

// fetchSubordinateStatement fetches a subordinate statement.
// A subordinate statement is an entity statement issued by a superior authority
// about an immediate subordinate.
func fetchSubordinateStatement(ctx oidc.Context, sub string, authority entityStatement) (entityStatement, error) {
	uri, err := url.Parse(authority.Metadata.FederationAuthority.FetchEndpoint)
	if err != nil {
		return entityStatement{}, fmt.Errorf("federation_fetch_endpoint of %s is not a valid uri: %w", authority.Issuer, err)
	}
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
		return entityStatement{}, errors.New("subordinate statements cannot have the claim 'authority_hints'")
	}

	if subStatement.TrustMarkIssuers != nil {
		return entityStatement{}, errors.New("subordinate statements cannot have the claim 'trust_mark_issuers'")
	}

	if subStatement.TrustMarkOwners != nil {
		return entityStatement{}, errors.New("subordinate statements cannot have the claim 'trust_mark_owners'")
	}

	return parseEntityStatement(ctx, signedStatement, sub, authority.Issuer, authority.JWKS)
}

func fetchAuthorityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {

	config, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return entityStatement{}, err
	}

	if config.Metadata.FederationAuthority == nil {
		return entityStatement{}, fmt.Errorf("the entity %s is not a federation authority", id)
	}

	return config, nil
}

// fetchEntityConfiguration fetches an entity's configuration.
// The entity configuration is issued by an entity about itself.
func fetchEntityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {
	signedStatement, err := fetchEntityStatement(ctx, id+federationEndpointPath)
	if err != nil {
		return entityStatement{}, err
	}

	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity statement for %s: %w", id, err)
	}

	var entityConfig entityStatement
	if err := parsedStatement.UnsafeClaimsWithoutVerification(&entityConfig); err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity configuration for %s: %w", id, err)
	}

	if entityConfig.MetadataPolicy != nil {
		return entityStatement{}, fmt.Errorf("the entity configuration for %s cannot have 'metadata_policy': %w", id, err)
	}

	return parseEntityConfiguration(ctx, signedStatement, id, entityConfig.JWKS)
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

	if resp.Header.Get("Content-Type") != entityStatementJWTContentType {
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

	if parsedStatement.Headers[0].ExtraHeaders["typ"] != entityStatementJWTType {
		return entityStatement{}, errors.New("invalid entity statement 'typ' header")
	}

	// "...Entity Configurations and Subordinate Statements MUST NOT contain the
	// trust_chain header parameter, as they are integral components of a Trust Chain..."
	if parsedStatement.Headers[0].ExtraHeaders["trust_chain"] != nil {
		return entityStatement{}, errors.New("entity statements must not contain the 'trust_chain' header")
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

	if statement.MetadataPolicy != nil {
		if err := statement.MetadataPolicy.validate(); err != nil {
			return entityStatement{}, fmt.Errorf("invalid entity statement metadata policy: %w", err)
		}
	}

	statement.signed = signedStatement
	return statement, nil
}

// resolveTrustChain processes a trust chain to determine the final entity statement.
func resolveTrustChain(_ oidc.Context, chain trustChain) (entityStatement, error) {

	config := chain.subjectConfig()
	var policy metadataPolicy
	for _, authority := range chain[1:] {

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

func extractRequiredTrustMarks(ctx oidc.Context, config entityStatement) ([]string, error) {
	var trustMarks []string
	for _, requiredTrustMark := range ctx.OpenIDFedRequiredTrustMarks() {
		if err := validateTrustMark(ctx, config, requiredTrustMark); err != nil {
			return nil, err
		}
		trustMarks = append(trustMarks, requiredTrustMark)
	}
	return trustMarks, nil
}

func validateTrustMark(ctx oidc.Context, config entityStatement, requiredTrustMarkID string) error {

	var trustMarkJWS string
	for _, tm := range config.TrustMarks {
		if tm.ID == requiredTrustMarkID {
			trustMarkJWS = tm.TrustMark
			break
		}
	}

	if trustMarkJWS == "" {
		return fmt.Errorf("entity %s does not have the trust mark %s", config.Issuer, requiredTrustMarkID)
	}

	parsedTrustMark, err := jwt.ParseSigned(trustMarkJWS, ctx.OpenIDFedTrustMarkSigAlgs)
	if err != nil {
		return fmt.Errorf("could not parse the trust mark for %s: %w", requiredTrustMarkID, err)
	}

	if parsedTrustMark.Headers[0].ExtraHeaders["typ"] != trustMarkJWTType {
		return errors.New("invalid trust mark 'typ' header")
	}

	var trustMarkClaims trustMark
	if err := parsedTrustMark.UnsafeClaimsWithoutVerification(&trustMarkClaims); err != nil {
		return fmt.Errorf("could not parse the trust mark for %s: %w", requiredTrustMarkID, err)
	}

	trustMarkIssuer, chain, err := buildAndResolveTrustChain(ctx, trustMarkClaims.Issuer)
	if err != nil {
		return fmt.Errorf("could not resolve the trust chain for trust mark issuer %s: %w", trustMarkClaims.Issuer, err)
	}

	var mark trustMark
	var claims jwt.Claims
	if err := parsedTrustMark.Claims(trustMarkIssuer.JWKS, &mark, &claims); err != nil {
		return fmt.Errorf("invalid trust mark signature: %w", err)
	}

	if claims.IssuedAt == nil {
		return fmt.Errorf("invalid 'iat' claim in the trust mark: %w", err)
	}

	if claims.Expiry == nil {
		return fmt.Errorf("invalid 'exp' claim in the trust mark: %w", err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:  trustMarkIssuer.Subject,
		Subject: config.Subject,
	}); err != nil {
		return fmt.Errorf("invalid trust mark: %w", err)
	}

	trustMarkIssuers := chain.authorityConfig().TrustMarkIssuers[requiredTrustMarkID]
	if len(trustMarkIssuers) != 0 && !slices.Contains(trustMarkIssuers, trustMarkIssuer.Issuer) {
		return fmt.Errorf("the entity %s is not allowed to issue trust marks for %s", trustMarkClaims.Issuer, requiredTrustMarkID)
	}

	// If the trust mark id appears in the trust_mark_owners claim of the trust anchor's
	// entity configuration, verify that the trust mark contains a valid delegation.
	if trustMarkOwner, ok := chain.authorityConfig().TrustMarkOwners[requiredTrustMarkID]; ok {
		if trustMarkClaims.Delegation == "" {
			return fmt.Errorf("the claim 'delegation' is required in trust mark %s", requiredTrustMarkID)
		}

		parsedTrustMarkDelegation, err := jwt.ParseSigned(trustMarkClaims.Delegation, ctx.OpenIDFedTrustMarkSigAlgs)
		if err != nil {
			return fmt.Errorf("could not parse the entity statement: %w", err)
		}

		if parsedTrustMarkDelegation.Headers[0].ExtraHeaders["typ"] != trustMarkDelegationJWTType {
			return errors.New("invalid trust mark delegation 'typ' header")
		}

		var markDelegation trustMark
		var claims jwt.Claims
		if err := parsedTrustMark.Claims(trustMarkOwner.JWKS, &markDelegation, &claims); err != nil {
			return fmt.Errorf("invalid trust mark delegation signature: %w", err)
		}

		if claims.IssuedAt == nil {
			return fmt.Errorf("invalid 'iat' claim in the trust mark delegation: %w", err)
		}

		if claims.Expiry == nil {
			return fmt.Errorf("invalid 'exp' claim in the trust mark delegation: %w", err)
		}

		if err := claims.Validate(jwt.Expected{
			Issuer:  trustMarkOwner.Subject,
			Subject: trustMarkClaims.Issuer,
		}); err != nil {
			return fmt.Errorf("invalid trust mark delegation: %w", err)
		}
	}

	return nil
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

	ops := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
	return ctx.OpenIDFedSign(statement, ops)
}
