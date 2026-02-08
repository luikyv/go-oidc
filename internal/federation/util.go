package federation

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Client(ctx oidc.Context, id string) (*goidc.Client, error) {

	if !slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeAutomatic) || !strutil.IsURL(id) {
		return ctx.ClientManager.Client(ctx, id)
	}

	c, err := ctx.ClientManager.Client(ctx, id)
	if err != nil {
		if errors.Is(err, goidc.ErrClientNotFound) {
			return registerAutomatically(ctx, id)
		}
		return nil, err
	}

	if c.ExpiresAtTimestamp != 0 && timeutil.TimestampNow() > c.ExpiresAtTimestamp {
		// Refresh the federation client using the same trust anchor.
		return registerAutomatically(ctx, id)
	}

	return c, nil
}

func FetchEntityConfigurationJWKS(ctx oidc.Context, id string) (goidc.JSONWebKeySet, error) {
	config, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return config.JWKS, nil
}

func newEntityConfiguration(ctx oidc.Context) (string, error) {
	config := discovery.NewOpenIDConfiguration(ctx)
	if !slices.Contains(ctx.OpenIDFedJWKSRepresentations, goidc.OpenIDFedJWKSRepresentationURI) {
		config.JWKSEndpoint = ""
	}

	config.ClientRegistrationTypes = ctx.OpenIDFedClientRegTypes
	if slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
		config.FederationRegistrationEndpoint = ctx.BaseURL() + ctx.OpenIDFedRegistrationEndpoint
	}
	if slices.Contains(ctx.OpenIDFedJWKSRepresentations, goidc.OpenIDFedJWKSRepresentationSignedURI) {
		config.SignedJWKSEndpoint = ctx.BaseURL() + ctx.OpenIDFedSignedJWKSEndpoint
	}
	if slices.Contains(ctx.OpenIDFedJWKSRepresentations, goidc.OpenIDFedJWKSRepresentationInline) {
		jwks, err := ctx.JWKS()
		if err != nil {
			return "", err
		}
		config.JWKS = &jwks
	}

	publicJWKS, err := ctx.OpenIDFedPublicJWKS()
	if err != nil {
		return "", err
	}
	now := timeutil.TimestampNow()
	statement := entityStatement{
		Issuer:           ctx.Issuer(),
		Subject:          ctx.Issuer(),
		IssuedAt:         now,
		ExpiresAt:        now + 600,
		JWKS:             publicJWKS,
		AuthorityHints:   ctx.OpenIDFedAuthorityHints,
		TrustAnchorHints: ctx.OpenIDFedTrustedAnchors,
	}
	statement.Metadata.OpenIDProvider = &config

	return ctx.OpenIDFedSign(statement, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
}

func registerAutomatically(ctx oidc.Context, id string) (*goidc.Client, error) {
	clientConfig, _, err := buildAndResolveTrustChain(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("could not resolve the trust chain for client %s: %w", id, err)
	}

	return register(ctx, clientConfig, goidc.ClientRegistrationTypeAutomatic)
}

func register(ctx oidc.Context, clientConfig entityStatement, regType goidc.ClientRegistrationType) (*goidc.Client, error) {
	if clientConfig.Metadata.OpenIDClient == nil {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the entity is not an openid client")
	}

	if !slices.Contains(clientConfig.Metadata.OpenIDClient.ClientRegistrationTypes, regType) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity %s is not registered for client registration type %s", clientConfig.Subject, regType))
	}

	if err := client.Validate(ctx, clientConfig.Metadata.OpenIDClient); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid client metadata", err)
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

	if err := ctx.SaveClient(c); err != nil {
		return nil, fmt.Errorf("could not save the federation client: %w", err)
	}
	return c, nil
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
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not build trust chain for entity %s with no authority hints", entityConfig.Subject))
	}

	var errs error
	for _, authorityID := range entityConfig.AuthorityHints {

		if _, exists := entityMap[authorityID]; exists {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "circular dependency detected in trust chain for entity "+entityConfig.Subject, ErrCircularDependency)
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

	return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not build trust chain for entity %s", entityConfig.Subject), errs)
}

func buildTrustChainBranch(ctx oidc.Context, entityConfig entityStatement, authorityConfig entityStatement, entityMap map[string]struct{}) (trustChain, error) {
	subordinateStatement, err := fetchSubordinateStatement(ctx, entityConfig.Subject, authorityConfig)
	if err != nil {
		return nil, err
	}

	// Validate the the entity configuration was signed by the jwks provided in the subordinate statement.
	_, err = parseEntityStatement(ctx, entityConfig.Signed(), parseOptions{
		jwks:    subordinateStatement.JWKS,
		issuer:  entityConfig.Subject,
		subject: entityConfig.Subject,
	})
	if err != nil {
		return nil, err
	}

	if slices.Contains(ctx.OpenIDFedTrustedAnchors, authorityConfig.Issuer) {
		return []entityStatement{subordinateStatement, authorityConfig}, nil
	}

	chain, err := buildTrustChainFromConfig(ctx, authorityConfig, entityMap)
	if err != nil {
		return nil, err
	}

	chain = append([]entityStatement{subordinateStatement}, chain...)
	if len(chain) > ctx.OpenIDFedTrustChainMaxDepth {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "trust chain maximum depth reached")
	}
	return chain, nil
}

func registerExplicitlyWithEntityConfiguration(ctx oidc.Context, signedStatement string) (string, error) {
	entityConfig, err := parseEntityConfiguration(ctx, signedStatement, &parseOptions{
		audience: ctx.Issuer(),
	})
	if err != nil {
		return "", err
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

	return parseEntityConfiguration(ctx, signedStatement, nil)
}

// fetchSubordinateStatement fetches a subordinate statement.
// A subordinate statement is an entity statement issued by a superior authority about an immediate subordinate.
func fetchSubordinateStatement(ctx oidc.Context, sub string, authority entityStatement) (entityStatement, error) {
	uri, err := url.Parse(authority.Metadata.FederationAuthority.FetchEndpoint)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("'federation_fetch_endpoint' of %s is not a valid uri", authority.Issuer), err)
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
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not fetch the entity statement", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("fetching the entity statement resulted in status %d", resp.StatusCode))
	}

	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != contentTypeEntityStatementJWT {
		return "", goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("fetching the entity statement resulted in content type %s which is invalid", resp.Header.Get("Content-Type")))
	}

	signedStatement, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not read the entity statement", err)
	}

	return string(signedStatement), nil
}

func parseTrustChain(ctx oidc.Context, chainStatements []string) (trustChain, error) {
	// The trust chain must have at least 3 statements:
	// 1. The subject's entity configuration.
	// 2. The first subordinate statement.
	// 3. The trust anchor's entity configuration.
	if len(chainStatements) < 3 {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "trust chain must have at least 3 statements")
	}

	entityConfig, err := parseEntityConfiguration(ctx, chainStatements[0], nil)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse entity configuration", err)
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
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse statement at index %d", i+1), err)
		}
		var nextStatementClaims entityStatement
		if err := nextStatementParsed.UnsafeClaimsWithoutVerification(&nextStatementClaims); err != nil {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse claims at index %d", i+1), err)
		}

		subordinateStatement, err := parseSubordinateStatement(ctx, statement, prevStatement.Issuer, nextStatementClaims.Subject, nextStatementClaims.JWKS)
		if err != nil {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse subordinate statement at index %d", i), err)
		}

		chain = append(chain, subordinateStatement)
	}

	// Verify that the entity configuration was signed by JWKS provided by the first subordinate statement.
	if _, err := parseEntityStatement(ctx, entityConfig.Signed(), parseOptions{
		jwks:    chain.firstSubordinateStatement().JWKS,
		issuer:  entityConfig.Issuer,
		subject: entityConfig.Subject,
	}); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "entity configuration signed with key not authorized by immediate superior", err)
	}

	trustAnchorConfig, err := parseAuthorityConfiguration(ctx, chainStatements[len(chainStatements)-1])
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse trust anchor configuration", err)
	}

	// Verify that the trust anchor is trusted.
	if !slices.Contains(ctx.OpenIDFedTrustedAnchors, trustAnchorConfig.Issuer) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("trust anchor %s is not trusted", trustAnchorConfig.Issuer))
	}

	originalTrustAnchorConfig, err := fetchAuthorityConfiguration(ctx, trustAnchorConfig.Issuer)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not fetch original trust anchor configuration", err)
	}

	// Verify that the trust anchor's entity configuration was signed by the original trust anchor's JWKS.
	_, err = parseEntityStatement(ctx, trustAnchorConfig.Signed(), parseOptions{
		jwks:    originalTrustAnchorConfig.JWKS,
		issuer:  trustAnchorConfig.Issuer,
		subject: trustAnchorConfig.Issuer,
	})
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust anchor signature", err)
	}

	chain = append(chain, trustAnchorConfig)
	return chain, nil
}

func parseAuthorityConfiguration(ctx oidc.Context, signedStatement string) (entityStatement, error) {
	config, err := parseEntityConfiguration(ctx, signedStatement, nil)
	if err != nil {
		return entityStatement{}, err
	}

	if config.Metadata.FederationAuthority == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity %s is not a federation authority", config.Issuer))
	}

	return config, nil
}

func parseEntityConfiguration(ctx oidc.Context, signedStatement string, opts *parseOptions) (entityStatement, error) {
	if opts == nil {
		opts = &parseOptions{}
	}

	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
	}

	var entityConfig entityStatement
	if err := parsedStatement.UnsafeClaimsWithoutVerification(&entityConfig); err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity configuration", err)
	}

	entityConfig, err = parseEntityStatement(ctx, signedStatement, parseOptions{
		jwks:     entityConfig.JWKS,
		issuer:   entityConfig.Issuer,
		subject:  entityConfig.Issuer,
		audience: opts.audience,
	})
	if err != nil {
		return entityStatement{}, err
	}

	if entityConfig.AuthorityHints != nil && len(entityConfig.AuthorityHints) == 0 {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "claims 'authority_hints' cannot be an empty array")
	}

	if entityConfig.TrustAnchorHints != nil && len(entityConfig.TrustAnchorHints) == 0 {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "claims 'trust_anchor_hints' cannot be an empty array")
	}

	if entityConfig.MetadataPolicy != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity configuration for %s cannot have 'metadata_policy'", entityConfig.Issuer))
	}

	if entityConfig.MetadataPolicyCritical != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity configuration cannot have 'metadata_policy_crit'")
	}

	if entityConfig.Constraints != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity configuration cannot have 'constraints'")
	}

	if entityConfig.SourceEndpoint != "" {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity configuration cannot have 'source_endpoint'")
	}

	return entityConfig, nil
}

func parseSubordinateStatement(ctx oidc.Context, signedStatement, sub, iss string, jwks goidc.JSONWebKeySet) (entityStatement, error) {
	subStatement, err := parseEntityStatement(ctx, signedStatement, parseOptions{
		jwks:    jwks,
		issuer:  iss,
		subject: sub,
	})
	if err != nil {
		return entityStatement{}, err
	}

	if subStatement.AuthorityHints != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "subordinate statements cannot have the claim 'authority_hints'")
	}

	if subStatement.TrustAnchorHints != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "subordinate statements cannot have the claim 'trust_anchor_hints'")
	}

	if subStatement.TrustMarks != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "subordinate statements cannot have the claim 'trust_marks'")
	}

	if subStatement.TrustMarkIssuers != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "subordinate statements cannot have the claim 'trust_mark_issuers'")
	}

	if subStatement.TrustMarkOwners != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "subordinate statements cannot have the claim 'trust_mark_owners'")
	}

	if subStatement.MetadataPolicy != nil {
		if err := subStatement.MetadataPolicy.validate(); err != nil {
			return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid entity statement metadata policy", err)
		}
	}

	if subStatement.SourceEndpoint != "" {
		if _, err := url.Parse(subStatement.SourceEndpoint); err != nil {
			return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid 'source_endpoint' claim", err)
		}
	}

	return subStatement, nil
}

func parseEntityStatement(ctx oidc.Context, signedStatement string, opts parseOptions) (entityStatement, error) {
	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
	}

	if parsedStatement.Headers[0].KeyID == "" {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statements must contain a 'kid' header")
	}

	if parsedStatement.Headers[0].Algorithm == "" || parsedStatement.Headers[0].Algorithm == string(goidc.None) {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statements must contain a valid 'alg' header")
	}

	if parsedStatement.Headers[0].ExtraHeaders["typ"] != jwtTypeEntityStatement {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid entity statement 'typ' header")
	}

	// [OpenID Fed §4.3] Entity Statements must not contain the 'trust_chain' header.
	if parsedStatement.Headers[0].ExtraHeaders["trust_chain"] != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statements must not contain the 'trust_chain' header")
	}

	// [OpenID Fed §4.3] Entity Statements must not contain the 'peer_trust_chain' header.
	if parsedStatement.Headers[0].ExtraHeaders["peer_trust_chain"] != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statements must not contain the 'peer_trust_chain' header")
	}

	var statement entityStatement
	var claims jwt.Claims
	if err := parsedStatement.Claims(opts.jwks.ToJOSE(), &claims, &statement); err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid entity statement signature", err)
	}

	if claims.IssuedAt == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'iat' claim in the entity statement")
	}

	if claims.Expiry == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'exp' claim in the entity statement")
	}

	if opts.audience == "" && claims.Audience != nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "'aud' claim is present in the entity statement")
	}

	var audiences []string
	if opts.audience != "" {
		audiences = []string{opts.audience}
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      opts.issuer,
		Subject:     opts.subject,
		AnyAudience: audiences,
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid entity statement", err)
	}

	if statement.JWKS.Keys == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statements must contain a 'jwks' claim")
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

func validateTrustMark(ctx oidc.Context, config entityStatement, markType string) error {

	var trustMarkJWS string
	for _, tm := range config.TrustMarks {
		if tm.Type == markType {
			trustMarkJWS = tm.TrustMark
			break
		}
	}

	if trustMarkJWS == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("entity %s does not have the trust mark %s", config.Issuer, markType))
	}

	parsedTrustMark, err := jwt.ParseSigned(trustMarkJWS, ctx.OpenIDFedTrustMarkSigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse the trust mark for %s", markType), err)
	}

	if parsedTrustMark.Headers[0].ExtraHeaders["typ"] != jwtTypeTrustMark {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid trust mark 'typ' header")
	}

	var mark trustMark
	if err := parsedTrustMark.UnsafeClaimsWithoutVerification(&mark); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse the trust mark for %s", markType), err)
	}

	trustMarkIssuer, chain, err := buildAndResolveTrustChain(ctx, mark.Issuer)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not resolve the trust chain for trust mark issuer %s", mark.Issuer), err)
	}

	var claims jwt.Claims
	if err := parsedTrustMark.Claims(trustMarkIssuer.JWKS.ToJOSE(), &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark signature", err)
	}

	if claims.IssuedAt == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("invalid 'iat' claim in the trust mark: %s", markType))
	}

	if mark.ID != markType {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("invalid 'trust_mark_id' claim in the trust mark: %s", markType))
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:  trustMarkIssuer.Subject,
		Subject: config.Subject,
	}); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark", err)
	}

	trustMarkIssuers := chain.trustAnchorConfig().TrustMarkIssuers[markType]
	if len(trustMarkIssuers) != 0 && !slices.Contains(trustMarkIssuers, trustMarkIssuer.Issuer) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity %s is not allowed to issue trust marks for %s", mark.Issuer, markType))
	}

	// If the trust mark id appears in the trust_mark_owners claim of the trust anchor's
	// entity configuration, verify that the trust mark contains a valid delegation.
	if trustMarkOwner, ok := chain.trustAnchorConfig().TrustMarkOwners[markType]; ok {
		if mark.Delegation == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the claim 'delegation' is required in trust mark %s", markType))
		}

		parsedTrustMarkDelegation, err := jwt.ParseSigned(mark.Delegation, ctx.OpenIDFedTrustMarkSigAlgs)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
		}

		if parsedTrustMarkDelegation.Headers[0].ExtraHeaders["typ"] != jwtTypeTrustMarkDelegation {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation 'typ' header")
		}

		var markDelegation trustMark
		var claims jwt.Claims
		if err := parsedTrustMark.Claims(trustMarkOwner.JWKS.ToJOSE(), &markDelegation, &claims); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation signature", err)
		}

		if claims.IssuedAt == nil {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'iat' claim in the trust mark delegation")
		}

		if claims.Expiry == nil {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'exp' claim in the trust mark delegation")
		}

		if err := claims.Validate(jwt.Expected{
			Issuer:  trustMarkOwner.Subject,
			Subject: mark.Issuer,
		}); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation", err)
		}
	}

	return nil
}

func signedJWKS(ctx oidc.Context) (string, error) {
	jwks, err := ctx.PublicJWKS()
	if err != nil {
		return "", err
	}

	var exp int
	if ctx.OpenIDFedSignedJWKSLifetimeSecs != 0 {
		exp = timeutil.TimestampNow() + ctx.OpenIDFedSignedJWKSLifetimeSecs
	}
	return ctx.OpenIDFedSign(struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		IssuedAt  int    `json:"iat"`
		ExpiresAt int    `json:"exp,omitempty"`
		goidc.JSONWebKeySet
	}{
		Issuer:        ctx.Issuer(),
		Subject:       ctx.Issuer(),
		IssuedAt:      timeutil.TimestampNow(),
		ExpiresAt:     exp,
		JSONWebKeySet: jwks,
	}, (&jose.SignerOptions{}).WithType(jwtTypeJWKS))
}
