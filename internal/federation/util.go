package federation

import (
	"errors"
	"fmt"
	"io"
	"mime"
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
		ID:                         id,
		IsFederated:                true,
		FederationRegistrationType: goidc.ClientRegistrationTypeAutomatic,
		FederationTrustMarkIDs:     trustMarks,
		CreatedAtTimestamp:         timeutil.TimestampNow(),
		ExpiresAtTimestamp:         clientConfig.ExpiresAt,
		ClientMeta:                 clientConfig.Metadata.OpenIDClient.ClientMeta,
	}, nil
}

// buildAndResolveTrustChain builds a trust chain and then resolves it to obtain
// the final entity statement for the given entity ID.
func buildAndResolveTrustChain(ctx oidc.Context, id string) (entityStatement, trustChain, error) {
	chain, err := buildTrustChain(ctx, id)
	if err != nil {
		return entityStatement{}, nil, err
	}

	config, err := chain.resolve()
	if err != nil {
		return entityStatement{}, nil, err
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

	chain, err := buildTrustChainFromConfig(ctx, entityConfig, map[string]struct{}{})
	if err != nil {
		return nil, err
	}

	return append([]entityStatement{entityConfig}, chain...), nil
}

func buildTrustChainFromConfig(ctx oidc.Context, entityConfig entityStatement, entityMap map[string]struct{}) (trustChain, error) {
	if entityConfig.AuthorityHints == nil {
		return nil, fmt.Errorf("could not build trust chain for entity %s with no authority hints", entityConfig.Subject)
	}

	var errs error
	for _, authorityID := range entityConfig.AuthorityHints {

		if _, exists := entityMap[authorityID]; exists {
			return nil, ErrCircularDependency
		}
		entityMap[authorityID] = struct{}{}

		authorityConfig, err := fetchAuthorityConfiguration(ctx, authorityID)
		if err != nil {
			return nil, err
		}

		chain, err := buildTrustChainBranch(ctx, entityConfig, authorityConfig, entityMap)
		if err == nil {
			return chain, nil
		}
		errs = errors.Join(errs, err)
	}

	return nil, fmt.Errorf("could not build trust chain for entity %s: %w", entityConfig.Subject, errs)
}

func buildTrustChainBranch(ctx oidc.Context, entityConfig entityStatement, authorityConfig entityStatement, entityMap map[string]struct{}) (trustChain, error) {
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

	chain, err := buildTrustChainFromConfig(ctx, authorityConfig, entityMap)
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
		return entityStatement{}, fmt.Errorf("'federation_fetch_endpoint' of %s is not a valid uri: %w", authority.Issuer, err)
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
		return entityStatement{}, fmt.Errorf("the entity configuration for %s cannot have 'metadata_policy'", id)
	}

	return parseEntityConfiguration(ctx, signedStatement, id, entityConfig.JWKS)
}

func fetchEntityStatement(ctx oidc.Context, uri string) (string, error) {
	resp, err := ctx.HTTPClient().Get(uri)
	if err != nil {
		return "", fmt.Errorf("could not fetch the entity statement: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching the entity statement resulted in status %d", resp.StatusCode)
	}

	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != entityStatementJWTContentType {
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
	jwks goidc.JSONWebKeySet,
) (
	entityStatement,
	error,
) {
	return parseEntityStatement(ctx, signedStatement, entityID, entityID, jwks)
}

func parseEntityStatement(
	ctx oidc.Context,
	signedStatement, entityID, authorityID string,
	jwks goidc.JSONWebKeySet,
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
	if err := parsedStatement.Claims(jwks.ToJOSE(), &claims, &statement); err != nil {
		return entityStatement{}, fmt.Errorf("invalid entity statement signature: %w", err)
	}

	if claims.IssuedAt == nil {
		return entityStatement{}, fmt.Errorf("invalid 'iat' claim in the entity statement")
	}

	if claims.Expiry == nil {
		return entityStatement{}, fmt.Errorf("invalid 'exp' claim in the entity statement")
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

func extractRequiredTrustMarks(ctx oidc.Context, config entityStatement) ([]string, error) {
	requiredTrustMarks := ctx.OpenIDFedRequiredTrustMarks()
	trustMarks := make([]string, len(requiredTrustMarks))
	for i, requiredTrustMark := range requiredTrustMarks {
		if err := validateTrustMark(ctx, config, requiredTrustMark); err != nil {
			return nil, err
		}
		trustMarks[i] = requiredTrustMark
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

	var mark trustMark
	if err := parsedTrustMark.UnsafeClaimsWithoutVerification(&mark); err != nil {
		return fmt.Errorf("could not parse the trust mark for %s: %w", requiredTrustMarkID, err)
	}

	trustMarkIssuer, chain, err := buildAndResolveTrustChain(ctx, mark.Issuer)
	if err != nil {
		return fmt.Errorf("could not resolve the trust chain for trust mark issuer %s: %w", mark.Issuer, err)
	}

	var claims jwt.Claims
	if err := parsedTrustMark.Claims(trustMarkIssuer.JWKS.ToJOSE(), &claims); err != nil {
		return fmt.Errorf("invalid trust mark signature: %w", err)
	}

	if claims.IssuedAt == nil {
		return fmt.Errorf("invalid 'iat' claim in the trust mark: %s", requiredTrustMarkID)
	}

	if mark.ID != requiredTrustMarkID {
		return fmt.Errorf("invalid 'trust_mark_id' claim in the trust mark: %s", requiredTrustMarkID)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:  trustMarkIssuer.Subject,
		Subject: config.Subject,
	}); err != nil {
		return fmt.Errorf("invalid trust mark: %w", err)
	}

	trustMarkIssuers := chain.authorityConfig().TrustMarkIssuers[requiredTrustMarkID]
	if len(trustMarkIssuers) != 0 && !slices.Contains(trustMarkIssuers, trustMarkIssuer.Issuer) {
		return fmt.Errorf("the entity %s is not allowed to issue trust marks for %s", mark.Issuer, requiredTrustMarkID)
	}

	// If the trust mark id appears in the trust_mark_owners claim of the trust anchor's
	// entity configuration, verify that the trust mark contains a valid delegation.
	if trustMarkOwner, ok := chain.authorityConfig().TrustMarkOwners[requiredTrustMarkID]; ok {
		if mark.Delegation == "" {
			return fmt.Errorf("the claim 'delegation' is required in trust mark %s", requiredTrustMarkID)
		}

		parsedTrustMarkDelegation, err := jwt.ParseSigned(mark.Delegation, ctx.OpenIDFedTrustMarkSigAlgs)
		if err != nil {
			return fmt.Errorf("could not parse the entity statement: %w", err)
		}

		if parsedTrustMarkDelegation.Headers[0].ExtraHeaders["typ"] != trustMarkDelegationJWTType {
			return errors.New("invalid trust mark delegation 'typ' header")
		}

		var markDelegation trustMark
		var claims jwt.Claims
		if err := parsedTrustMark.Claims(trustMarkOwner.JWKS.ToJOSE(), &markDelegation, &claims); err != nil {
			return fmt.Errorf("invalid trust mark delegation signature: %w", err)
		}

		if claims.IssuedAt == nil {
			return errors.New("invalid 'iat' claim in the trust mark delegation")
		}

		if claims.Expiry == nil {
			return errors.New("invalid 'exp' claim in the trust mark delegation")
		}

		if err := claims.Validate(jwt.Expected{
			Issuer:  trustMarkOwner.Subject,
			Subject: mark.Issuer,
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
		JWKS:           publicJWKS,
		AuthorityHints: ctx.OpenIDFedAuthorityHints,
	}
	statement.Metadata.OpenIDProvider = &openIDProvider{
		ClientRegistrationTypes: ctx.OpenIDFedClientRegTypes,
		OpenIDConfiguration:     discovery.NewOIDCConfig(ctx),
	}

	ops := (&jose.SignerOptions{}).WithType(entityStatementJWTType)
	return ctx.OpenIDFedSign(statement, ops)
}
