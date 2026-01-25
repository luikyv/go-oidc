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
	"github.com/luikyv/go-oidc/internal/dcr"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterClient(ctx oidc.Context, id string, hints []string) (*goidc.Client, error) {
	clientConfig, _, err := buildAndResolveTrustChain(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("could not resolve the trust chain for client %s: %w", id, err)
	}

	return registerClient(ctx, clientConfig, goidc.ClientRegistrationTypeAutomatic)
}

func registerClient(ctx oidc.Context, clientConfig entityStatement, regType goidc.ClientRegistrationType) (*goidc.Client, error) {
	if clientConfig.Metadata.OpenIDClient == nil {
		return nil, errors.New("the entity is not an openid client")
	}

	if err := dcr.Validate(ctx, &clientConfig.Metadata.OpenIDClient.ClientMeta); err != nil {
		return nil, err
	}

	client := &goidc.Client{
		ID:                         clientConfig.Subject,
		IsFederated:                true,
		TrustAnchor:                clientConfig.TrustAnchor,
		FederationRegistrationType: regType,
		CreatedAtTimestamp:         timeutil.TimestampNow(),
		ExpiresAtTimestamp:         clientConfig.ExpiresAt,
		ClientMeta:                 clientConfig.Metadata.OpenIDClient.ClientMeta,
	}

	trustMarks, err := extractRequiredTrustMarks(ctx, clientConfig, client)
	if err != nil {
		return nil, err
	}
	client.FederationTrustMarkIDs = trustMarks

	if err := ctx.SaveClient(client); err != nil {
		return nil, fmt.Errorf("could not save the federation client: %w", err)
	}
	return client, nil
}

// buildAndResolveTrustChain builds a trust chain and then resolves it to obtain
// the final entity statement for the given entity ID.
func buildAndResolveTrustChain(ctx oidc.Context, id string) (entityStatement, trustChain, error) {
	entityConfig, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return entityStatement{}, nil, err
	}

	chain, err := buildTrustChain(ctx, entityConfig)
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
func buildTrustChain(ctx oidc.Context, entityConfig entityStatement) (trustChain, error) {

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

	// Validate the the entity configuration was signed by the jwks provided in the subordinate statement.
	_, err = parseEntityStatement(ctx, entityConfig.Signed(), entityConfig.Subject, entityConfig.Subject, subordinateStatement.JWKS)
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

func newEntityConfiguration(ctx oidc.Context) (string, error) {
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

	openIDProviderMeta := &openIDProvider{
		ClientRegistrationTypes: ctx.OpenIDFedClientRegTypes,
		OpenIDConfiguration:     discovery.NewOIDCConfig(ctx),
	}
	if slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
		openIDProviderMeta.FederationRegistrationEndpoint = ctx.BaseURL() + ctx.OpenIDFedRegistrationEndpoint
	}
	statement.Metadata.OpenIDProvider = openIDProviderMeta

	ops := (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement)
	return ctx.OpenIDFedSign(statement, ops)
}

func registerClientWithEntityConfiguration(ctx oidc.Context, signedStatement string) (string, error) {
	entityConfig, err := parseEntityConfiguration(ctx, signedStatement)
	if err != nil {
		return "", err
	}

	if entityConfig.Audience != ctx.Issuer() {
		return "", fmt.Errorf("the entity configuration has an invalid audience")
	}

	chain, err := buildTrustChain(ctx, entityConfig)
	if err != nil {
		return "", err
	}

	return registerClienFromTrustChain(ctx, chain)
}

func registerClientFromChainStatements(ctx oidc.Context, chainStatements []string) (string, error) {
	chain, err := parseTrustChain(ctx, chainStatements)
	if err != nil {
		return "", err
	}

	return registerClienFromTrustChain(ctx, chain)
}

func registerClienFromTrustChain(ctx oidc.Context, chain trustChain) (string, error) {
	resolvedConfig, err := chain.resolve()
	if err != nil {
		return "", err
	}

	client, err := registerClient(ctx, resolvedConfig, goidc.ClientRegistrationTypeExplicit)
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
	statement.Metadata.OpenIDClient = &openIDClient{
		ClientMeta: client.ClientMeta,
	}

	return ctx.OpenIDFedSign(statement, (&jose.SignerOptions{}).WithType(jwtTypeExplicitRegistration))
}

func fetchAuthorityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {
	signedStatement, err := fetchEntityStatement(ctx, id+federationEndpointPath)
	if err != nil {
		return entityStatement{}, err
	}

	return parseAuthorityConfiguration(ctx, signedStatement)
}

// fetchEntityConfiguration fetches an entity's configuration.
// The entity configuration is issued by an entity about itself.
func fetchEntityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {
	signedStatement, err := fetchEntityStatement(ctx, id+federationEndpointPath)
	if err != nil {
		return entityStatement{}, err
	}

	return parseEntityConfiguration(ctx, signedStatement)
}

// fetchSubordinateStatement fetches a subordinate statement.
// A subordinate statement is an entity statement issued by a superior authority about an immediate subordinate.
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

	return parseSubordinateStatement(ctx, signedStatement, sub, authority.Issuer, authority.JWKS)
}

func fetchEntityStatement(ctx oidc.Context, uri string) (string, error) {
	resp, err := ctx.HTTPClient().Get(uri)
	if err != nil {
		return "", fmt.Errorf("could not fetch the entity statement: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching the entity statement resulted in status %d", resp.StatusCode)
	}

	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != contentTypeEntityStatementJWT {
		return "", fmt.Errorf("fetching the entity statement resulted in content type %s which is invalid", resp.Header.Get("Content-Type"))
	}

	signedStatement, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read the entity statement: %w", err)
	}

	return string(signedStatement), nil
}

func parseTrustChain(ctx oidc.Context, chainStatements []string) (trustChain, error) {
	// The trust chain must have at least 3 statements:
	// 1. The subject's entity configuration.
	// 2. The first subordinate statement.
	// 3. The trust anchor's entity configuration.
	if len(chainStatements) < 3 {
		return nil, errors.New("trust chain must have at least 3 statements")
	}

	entityConfig, err := parseEntityConfiguration(ctx, chainStatements[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse entity configuration: %w", err)
	}

	chain := trustChain{entityConfig}

	// Parse all intermediate subordinate statements.
	// The last statement is the trust anchor's entity configuration which is parsed differently.
	for i := 1; i < len(chainStatements)-1; i++ {
		statement := chainStatements[i]
		// Get the previous statement to determine the expected subject.
		prevStatement := chain[i-1]
		// Get the next statement to determine the issuer's JWKS for signature verification.
		nextStatementParsed, err := jwt.ParseSigned(chainStatements[i+1], ctx.OpenIDFedEntityStatementSigAlgs)
		if err != nil {
			return nil, fmt.Errorf("could not parse statement at index %d: %w", i+1, err)
		}
		var nextStatementClaims entityStatement
		if err := nextStatementParsed.UnsafeClaimsWithoutVerification(&nextStatementClaims); err != nil {
			return nil, fmt.Errorf("could not parse claims at index %d: %w", i+1, err)
		}

		subordinateStatement, err := parseSubordinateStatement(ctx, statement, prevStatement.Issuer, nextStatementClaims.Subject, nextStatementClaims.JWKS)
		if err != nil {
			return nil, fmt.Errorf("could not parse subordinate statement at index %d: %w", i, err)
		}

		chain = append(chain, subordinateStatement)
	}

	// Verify that the entity configuration was signed by JWKS provided by the first subordinate statement.
	if _, err := parseEntityStatement(ctx, entityConfig.Signed(), entityConfig.Subject, entityConfig.Issuer, chain.firstSubordinateStatement().JWKS); err != nil {
		return nil, fmt.Errorf("entity configuration signed with key not authorized by immediate superior: %w", err)
	}

	trustAnchorConfig, err := parseAuthorityConfiguration(ctx, chainStatements[len(chainStatements)-1])
	if err != nil {
		return nil, fmt.Errorf("could not parse trust anchor configuration: %w", err)
	}

	// Verify that the trust anchor is trusted.
	if !slices.Contains(ctx.OpenIDFedTrustedAuthorities, trustAnchorConfig.Issuer) {
		return nil, fmt.Errorf("trust anchor %s is not trusted", trustAnchorConfig.Issuer)
	}

	originalTrustAnchorConfig, err := fetchAuthorityConfiguration(ctx, trustAnchorConfig.Issuer)
	if err != nil {
		return nil, fmt.Errorf("could not fetch original trust anchor configuration: %w", err)
	}

	// Verify that the trust anchor's entity configuration was signed by the original trust anchor's JWKS.
	_, err = parseEntityStatement(ctx, trustAnchorConfig.Signed(), trustAnchorConfig.Issuer, trustAnchorConfig.Issuer, originalTrustAnchorConfig.JWKS)
	if err != nil {
		return nil, fmt.Errorf("invalid trust anchor signature: %w", err)
	}

	chain = append(chain, trustAnchorConfig)
	return chain, nil
}

func parseAuthorityConfiguration(ctx oidc.Context, signedStatement string) (entityStatement, error) {
	config, err := parseEntityConfiguration(ctx, signedStatement)
	if err != nil {
		return entityStatement{}, err
	}

	if config.Metadata.FederationAuthority == nil {
		return entityStatement{}, fmt.Errorf("the entity %s is not a federation authority", config.Issuer)
	}

	return config, nil
}

func parseEntityConfiguration(ctx oidc.Context, signedStatement string) (entityStatement, error) {
	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity statement: %w", err)
	}

	var entityConfig entityStatement
	if err := parsedStatement.UnsafeClaimsWithoutVerification(&entityConfig); err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity configuration: %w", err)
	}

	if entityConfig.MetadataPolicy != nil {
		return entityStatement{}, fmt.Errorf("the entity configuration for %s cannot have 'metadata_policy'", entityConfig.Issuer)
	}

	return parseEntityStatement(ctx, signedStatement, entityConfig.Issuer, entityConfig.Issuer, entityConfig.JWKS)
}

func parseSubordinateStatement(ctx oidc.Context, signedStatement, sub, iss string, jwks goidc.JSONWebKeySet) (entityStatement, error) {
	subStatement, err := parseEntityStatement(ctx, signedStatement, sub, iss, jwks)
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

	return subStatement, nil
}

func parseEntityStatement(ctx oidc.Context, signedStatement, sub, iss string, jwks goidc.JSONWebKeySet) (entityStatement, error) {
	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, fmt.Errorf("could not parse the entity statement: %w", err)
	}

	if parsedStatement.Headers[0].ExtraHeaders["typ"] != jwtTypeEntityStatement {
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
		Issuer:  iss,
		Subject: sub,
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

func extractRequiredTrustMarks(ctx oidc.Context, config entityStatement, client *goidc.Client) ([]string, error) {
	requiredTrustMarks := ctx.OpenIDFedRequiredTrustMarks(client)
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

	if parsedTrustMark.Headers[0].ExtraHeaders["typ"] != jwtTypeTrustMark {
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

		if parsedTrustMarkDelegation.Headers[0].ExtraHeaders["typ"] != jwtTypeTrustMarkDelegation {
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
