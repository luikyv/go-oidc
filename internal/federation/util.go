package federation

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func FetchEntityConfigurationJWKS(ctx oidc.Context, id string) (goidc.JSONWebKeySet, error) {
	config, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return config.JWKS, nil
}

type Options struct {
	TrustChain []string
}

func Client(ctx oidc.Context, id string, opts *Options) (*goidc.Client, error) {
	if opts == nil {
		opts = &Options{}
	}

	if opts.TrustChain != nil {
		chain, err := parseTrustChain(ctx, opts.TrustChain)
		if err != nil {
			return nil, err
		}

		if chain.subjectConfig().Subject != id {
			return nil, goidc.NewError(goidc.ErrorCodeInvalidTrustChain, "the trust chain subject does not match the client id")
		}

		return resolveClient(ctx, chain)
	}

	entityConfig, err := fetchEntityConfiguration(ctx, id)
	if err != nil {
		return nil, err
	}

	chain, err := buildTrustChain(ctx, entityConfig)
	if err != nil {
		return nil, err
	}

	return resolveClient(ctx, chain)
}

func resolveClient(ctx oidc.Context, chain trustChain) (*goidc.Client, error) {
	config, err := chain.resolve()
	if err != nil {
		return nil, err
	}

	if config.Metadata.OpenIDClient == nil {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the entity is not an openid client")
	}

	c := &goidc.Client{
		ID:                 config.Subject,
		CreatedAtTimestamp: timeutil.TimestampNow(),
		ExpiresAtTimestamp: config.ExpiresAt,
		ClientMeta:         *config.Metadata.OpenIDClient,
		Federation: &struct {
			TrustAnchor string   `json:"trust_anchor"`
			TrustMarks  []string `json:"trust_marks,omitempty"`
		}{
			TrustAnchor: config.TrustAnchor,
		},
	}

	c.Federation.TrustMarks, err = extractRequiredTrustMarks(ctx, config, c)
	if err != nil {
		return nil, err
	}

	if err := ctx.OpenIDFedHandleClient(c); err != nil {
		return nil, err
	}

	if err := client.Validate(ctx, config.Metadata.OpenIDClient); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid client metadata", err)
	}

	return c, nil
}

func newEntityConfiguration(ctx oidc.Context) (string, error) {
	config := discovery.NewOpenIDConfiguration(ctx)
	if !slices.Contains(ctx.OpenIDFedJWKSRepresentations, goidc.JWKSRepresentationURI) {
		config.JWKSEndpoint = ""
	}

	config.OrganizationName = ctx.OpenIDFedOrganizationName
	config.ClientRegistrationTypes = ctx.OpenIDFedClientRegTypes
	if slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeExplicit) {
		config.FederationRegistrationEndpoint = ctx.BaseURL() + ctx.OpenIDFedRegistrationEndpoint
	}
	if slices.Contains(ctx.OpenIDFedJWKSRepresentations, goidc.JWKSRepresentationSignedURI) {
		config.SignedJWKSEndpoint = ctx.BaseURL() + ctx.OpenIDFedSignedJWKSEndpoint
	}
	if slices.Contains(ctx.OpenIDFedJWKSRepresentations, goidc.JWKSRepresentationInline) {
		jwks, err := ctx.JWKS()
		if err != nil {
			return "", err
		}
		config.JWKS = &jwks
	}

	trustMarks, err := fetchTrustMarks(ctx)
	if err != nil {
		return "", err
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
		TrustMarks:       trustMarks,
	}
	statement.Metadata.OpenIDProvider = &config

	return ctx.OpenIDFedSign(statement, (&jose.SignerOptions{}).WithType(jwtTypeEntityStatement))
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
	chain, err := buildTrustChainFromConfig(ctx, entityConfig, map[string]struct{}{entityConfig.Subject: {}})
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
		branchMap := maps.Clone(entityMap)

		if _, exists := branchMap[authorityID]; exists {
			errs = errors.Join(errs, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "circular dependency detected in trust chain for entity "+entityConfig.Subject, ErrCircularDependency))
			continue
		}
		branchMap[authorityID] = struct{}{}

		authorityConfig, err := fetchAuthorityConfiguration(ctx, authorityID)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		chain, err := buildTrustChainBranch(ctx, entityConfig, authorityConfig, branchMap)
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

	// Verify that the entity configuration was signed by a key in the subordinate statement's JWKS.
	parsedConfig, err := jwt.ParseSigned(entityConfig.Signed(), ctx.OpenIDFedSigAlgs)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
	}
	if err := parsedConfig.Claims(subordinateStatement.JWKS.ToJOSE()); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid entity statement signature", err)
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

func fetchAuthorityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, id+federationEndpointPath, nil)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not create the request", err)
	}
	signedStatement, err := fetchEntityStatement(ctx, r)
	if err != nil {
		return entityStatement{}, err
	}

	return parseAuthorityConfiguration(ctx, signedStatement)
}

// fetchEntityConfiguration fetches an entity's configuration.
// The entity configuration is issued by an entity about itself.
func fetchEntityConfiguration(ctx oidc.Context, id string) (entityStatement, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, id+federationEndpointPath, nil)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not create the request", err)
	}
	signedStatement, err := fetchEntityStatement(ctx, r)
	if err != nil {
		return entityStatement{}, err
	}

	return parseEntityConfiguration(ctx, signedStatement, nil)
}

// fetchSubordinateStatement fetches a subordinate statement.
// A subordinate statement is an entity statement issued by a superior authority about an immediate subordinate.
func fetchSubordinateStatement(ctx oidc.Context, sub string, authority entityStatement) (entityStatement, error) {
	if authority.Metadata.FederationAuthority == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("entity %s is not a federation authority", authority.Issuer))
	}

	fetchEndpoint := authority.Metadata.FederationAuthority.FetchEndpoint
	if _, err := url.Parse(fetchEndpoint); fetchEndpoint == "" || err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("'federation_fetch_endpoint' of %s is not a valid uri", authority.Issuer), err)
	}

	var r *http.Request
	if slices.Contains(authority.Metadata.FederationAuthority.FetchEndpointAuthMethods, goidc.AuthnMethodPrivateKeyJWT) {
		req, err := privateKeyJWTRequest(ctx, authority, fetchEndpoint, url.Values{"sub": {sub}})
		if err != nil {
			return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not create the request", err)
		}
		r = req
	} else {
		req, err := unauthenticatedRequest(ctx, fetchEndpoint, url.Values{"sub": {sub}})
		if err != nil {
			return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not create the request", err)
		}
		r = req
	}

	signedStatement, err := fetchEntityStatement(ctx, r)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not fetch subordinate statement from %s", authority.Issuer), err)
	}

	return parseSubordinateStatement(ctx, signedStatement, parseOptions{
		jwks:    authority.JWKS,
		issuer:  authority.Issuer,
		subject: sub,
	})
}

func fetchEntityStatement(ctx oidc.Context, r *http.Request) (string, error) {
	resp, err := ctx.OpenIDFedHTTPClient().Do(r)
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
	// The trust chain must have at least 2 statements:
	// 1. The subject's entity configuration.
	// 2. The first subordinate statement issued by an immediate superior.
	if len(chainStatements) < 2 {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidTrustChain, "trust chain must have at least 2 statements")
	}

	parsedLastStatement, err := jwt.ParseSigned(chainStatements[len(chainStatements)-1], ctx.OpenIDFedSigAlgs)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidTrustChain, "could not parse the entity statement", err)
	}

	var lastStatement entityStatement
	if err := parsedLastStatement.UnsafeClaimsWithoutVerification(&lastStatement); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidTrustChain, "could not parse the entity configuration", err)
	}

	// Verify that the trust anchor is trusted.
	if !slices.Contains(ctx.OpenIDFedTrustedAnchors, lastStatement.Issuer) {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidTrustAnchor, fmt.Sprintf("trust anchor %s is not trusted", lastStatement.Issuer))
	}

	originalTrustAnchorConfig, err := fetchAuthorityConfiguration(ctx, lastStatement.Issuer)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not fetch trust anchor configuration", err)
	}
	// [OpenID Fed §4] The trust anchor's entity configuration may be omitted.
	if lastStatement.Subject != lastStatement.Issuer {
		// The trust anchor's config is not in the chain.
		chainStatements = append(chainStatements, originalTrustAnchorConfig.Signed())
	} else {
		// The trust anchor's config is in the chain. Verify that it was signed by the original trust anchor's JWKS.
		trustAnchorConfig, err := parseAuthorityConfiguration(ctx, chainStatements[len(chainStatements)-1])
		if err != nil {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidTrustChain, "could not parse trust anchor configuration", err)
		}

		// Verify that the trust anchor's entity configuration was signed by the original trust anchor's JWKS.
		_, err = parseEntityStatement(ctx, trustAnchorConfig.Signed(), parseOptions{
			jwks:    originalTrustAnchorConfig.JWKS,
			issuer:  trustAnchorConfig.Issuer,
			subject: trustAnchorConfig.Issuer,
		})
		if err != nil {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidTrustChain, "invalid trust anchor signature", err)
		}
	}

	entityConfig, err := parseEntityConfiguration(ctx, chainStatements[0], nil)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidTrustChain, "could not parse entity configuration", err)
	}

	chain := trustChain{entityConfig}

	// Parse all intermediate subordinate statements.
	// The last statement is the trust anchor's entity configuration which is parsed differently.
	for i := 1; i < len(chainStatements)-1; i++ {
		statement := chainStatements[i]
		// Get the previous statement to determine the expected subject.
		prevStatement := chain[i-1]
		// Get the next statement to determine the issuer's JWKS for signature verification.
		nextStatementParsed, err := jwt.ParseSigned(chainStatements[i+1], ctx.OpenIDFedSigAlgs)
		if err != nil {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse statement at index %d", i+1), err)
		}
		var nextStatementClaims entityStatement
		if err := nextStatementParsed.UnsafeClaimsWithoutVerification(&nextStatementClaims); err != nil {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("could not parse claims at index %d", i+1), err)
		}

		subordinateStatement, err := parseSubordinateStatement(ctx, statement, parseOptions{
			jwks:    nextStatementClaims.JWKS,
			issuer:  nextStatementClaims.Subject,
			subject: prevStatement.Issuer,
		})
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

	chain = append(chain, originalTrustAnchorConfig)
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

	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedSigAlgs)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
	}

	var entityConfig entityStatement
	if err := parsedStatement.UnsafeClaimsWithoutVerification(&entityConfig); err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity configuration", err)
	}

	entityConfig, err = parseEntityStatement(ctx, signedStatement, parseOptions{
		jwks:                 entityConfig.JWKS,
		issuer:               entityConfig.Issuer,
		subject:              entityConfig.Issuer,
		explicitRegistration: opts.explicitRegistration,
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

func parseSubordinateStatement(ctx oidc.Context, signedStatement string, opts parseOptions) (entityStatement, error) {
	subStatement, err := parseEntityStatement(ctx, signedStatement, opts)
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
		if err := subStatement.MetadataPolicy.Validate(); err != nil {
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
	parsedStatement, err := jwt.ParseSigned(signedStatement, ctx.OpenIDFedSigAlgs)
	if err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
	}

	var statement entityStatement
	var claims jwt.Claims
	if err := parsedStatement.Claims(opts.jwks.ToJOSE(), &claims, &statement); err != nil {
		return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid entity statement signature", err)
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

	if chain := parsedStatement.Headers[0].ExtraHeaders["peer_trust_chain"]; chain != nil {
		if !opts.explicitRegistration {
			return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statement must not contain the 'peer_trust_chain' header")
		}
	}

	if chain := parsedStatement.Headers[0].ExtraHeaders["trust_chain"]; chain != nil {
		if !opts.explicitRegistration {
			return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statement must not contain the 'trust_chain' header")
		}

		chain, ok := chain.([]any)
		if !ok {
			return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "'trust_chain' header is not an array")
		}
		chainStrings := make([]string, len(chain))
		for i, v := range chain {
			chainStrings[i], _ = v.(string)
		}

		chainHeader, err := parseTrustChain(ctx, chainStrings)
		if err != nil {
			return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid 'trust_chain' header", err)
		}

		if chainHeader.subjectConfig().Subject != statement.Subject {
			return entityStatement{}, goidc.WrapError(goidc.ErrorCodeInvalidTrustChain, "invalid 'trust_chain' header", errors.New("the subject of the trust chain header does not match the entity statement"))
		}

		statement.trustChainHeader = chainHeader
	}

	if claims.IssuedAt == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'iat' claim in the entity statement")
	}

	if claims.Expiry == nil {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'exp' claim in the entity statement")
	}

	// [OpenID Fed §4.2] Entity Statements must not contain the 'aud' claim.
	if claims.Audience != nil && !opts.explicitRegistration {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "'aud' claim is present in the entity statement")
	}

	var audiences []string
	// [OpenID Fed §12.2.1] Entity statements for explicit registration must contain the 'aud' claim.
	if opts.explicitRegistration {
		audiences = []string{ctx.Issuer()}
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

	if statement.TrustAnchor != "" {
		return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "entity statement must not contain the 'trust_anchor' claim")
	}

	statement.signed = signedStatement
	return statement, nil
}

func extractRequiredTrustMarks(ctx oidc.Context, config entityStatement, c *goidc.Client) ([]string, error) {
	trustMarkTypes := ctx.OpenIDFedRequiredTrustMarks(c)
	trustMarks := make([]string, 0, len(trustMarkTypes))
	for _, trustMarkType := range trustMarkTypes {

		var trustMark string
		for _, mark := range config.TrustMarks {
			if mark.Type == trustMarkType {
				trustMark = mark.TrustMark
				break
			}
		}

		if trustMark == "" {
			return nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity %s does not have the trust mark %s", config.Issuer, trustMarkType))
		}

		if _, err := parseTrustMark(ctx, trustMark, parseTrustMarkOptions{
			subject:  config.Subject,
			markType: trustMarkType,
		}); err != nil {
			return nil, err
		}
		trustMarks = append(trustMarks, trustMark)
	}
	return trustMarks, nil
}

func parseTrustMark(ctx oidc.Context, signedMark string, opts parseTrustMarkOptions) (trustMark, error) {
	parsedMark, err := jwt.ParseSigned(signedMark, ctx.OpenIDFedSigAlgs)
	if err != nil {
		return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the trust mark", err)
	}

	if parsedMark.Headers[0].KeyID == "" {
		return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "trust mark must contain a 'kid' header")
	}

	if parsedMark.Headers[0].ExtraHeaders["typ"] != jwtTypeTrustMark {
		return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid trust mark 'typ' header")
	}

	if parsedMark.Headers[0].Algorithm == "" || parsedMark.Headers[0].Algorithm == string(goidc.None) {
		return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid trust mark 'alg' header")
	}

	var mark trustMark
	if err := parsedMark.UnsafeClaimsWithoutVerification(&mark); err != nil {
		return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the trust mark", err)
	}

	trustMarkIssuer, chain, err := buildAndResolveTrustChain(ctx, mark.Issuer)
	if err != nil {
		return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not resolve the trust chain for trust mark issuer", err)
	}

	var claims jwt.Claims
	if err := parsedMark.Claims(trustMarkIssuer.JWKS.ToJOSE(), &claims); err != nil {
		return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark signature", err)
	}

	if claims.IssuedAt == nil {
		return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'iat' claim in the trust mark")
	}

	if mark.Type != string(opts.markType) {
		return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'trust_mark_type' claim in the trust mark")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:  trustMarkIssuer.Subject,
		Subject: opts.subject,
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark", err)
	}

	if trustMarkIssuers := chain.trustAnchorConfig().TrustMarkIssuers[string(opts.markType)]; len(trustMarkIssuers) != 0 && !slices.Contains(trustMarkIssuers, trustMarkIssuer.Issuer) {
		return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("the entity %s is not allowed to issue trust marks for %s", mark.Issuer, opts.markType))
	}

	// If the trust mark type appears in the trust_mark_owners claim of the trust anchor's
	// entity configuration, verify that the trust mark contains a valid delegation.
	if trustMarkOwner, ok := chain.trustAnchorConfig().TrustMarkOwners[string(opts.markType)]; ok {
		if mark.Delegation == "" {
			return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the claim 'delegation' is required in trust mark")
		}

		parsedTrustMarkDelegation, err := jwt.ParseSigned(mark.Delegation, ctx.OpenIDFedSigAlgs)
		if err != nil {
			return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the entity statement", err)
		}

		if parsedTrustMarkDelegation.Headers[0].KeyID == "" {
			return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "trust mark delegation must contain a 'kid' header")
		}

		if parsedTrustMarkDelegation.Headers[0].ExtraHeaders["typ"] != jwtTypeTrustMarkDelegation {
			return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation 'typ' header")
		}

		if parsedTrustMarkDelegation.Headers[0].Algorithm == "" || parsedTrustMarkDelegation.Headers[0].Algorithm == string(goidc.None) {
			return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation 'alg' header")
		}

		var markDelegation trustMark
		var markDelegationclaims jwt.Claims
		if err := parsedTrustMarkDelegation.Claims(trustMarkOwner.JWKS.ToJOSE(), &markDelegation, &markDelegationclaims); err != nil {
			return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation signature", err)
		}

		if markDelegationclaims.IssuedAt == nil {
			return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'iat' claim in the trust mark delegation")
		}

		if err := markDelegationclaims.ValidateWithLeeway(jwt.Expected{
			Issuer:  trustMarkOwner.Subject,
			Subject: mark.Issuer,
		}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
			return trustMark{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid trust mark delegation", err)
		}

		if markDelegation.Type != string(opts.markType) {
			return trustMark{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid 'trust_mark_type' claim in the trust mark delegation")
		}
	}

	return mark, nil
}

// TODO: Cache the trust marks until expiration.
func fetchTrustMarks(ctx oidc.Context) ([]trustMarkInfo, error) {
	if len(ctx.OpenIDFedTrustMarks) == 0 {
		return nil, nil
	}

	type result struct {
		mark trustMarkInfo
		err  error
	}

	resultCh := make(chan result, len(ctx.OpenIDFedTrustMarks))
	for markType, issuerID := range ctx.OpenIDFedTrustMarks {
		go func(markType goidc.TrustMark, issuerID string) {
			mark, err := fetchTrustMark(ctx, markType, issuerID)
			resultCh <- result{mark: mark, err: err}
		}(markType, issuerID)
	}

	marks := make([]trustMarkInfo, 0, len(ctx.OpenIDFedTrustMarks))
	for range ctx.OpenIDFedTrustMarks {
		res := <-resultCh
		if res.err != nil {
			return nil, res.err
		}
		marks = append(marks, res.mark)
	}

	return marks, nil
}

func fetchTrustMark(ctx oidc.Context, markType goidc.TrustMark, issuerID string) (trustMarkInfo, error) {
	issuer, err := fetchEntityConfiguration(ctx, issuerID)
	if err != nil {
		return trustMarkInfo{}, err
	}

	if issuer.Metadata.FederationAuthority == nil {
		return trustMarkInfo{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("entity %s is not a federation authority", issuerID))
	}

	trustMarkEndpoint := issuer.Metadata.FederationAuthority.TrustMarkEndpoint
	if _, err := url.Parse(trustMarkEndpoint); err != nil {
		return trustMarkInfo{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("'federation_trust_mark_endpoint' of %s is not a valid uri", issuerID), err)
	}

	var r *http.Request
	params := url.Values{"sub": {ctx.Issuer()}, "trust_mark_type": {string(markType)}}
	if slices.Contains(issuer.Metadata.FederationAuthority.TrustMarkEndpointAuthMethods, goidc.AuthnMethodPrivateKeyJWT) {
		req, err := privateKeyJWTRequest(ctx, issuer, trustMarkEndpoint, params)
		if err != nil {
			return trustMarkInfo{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not create the request", err)
		}
		r = req
	} else {
		req, err := unauthenticatedRequest(ctx, trustMarkEndpoint, params)
		if err != nil {
			return trustMarkInfo{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not create the request", err)
		}
		r = req
	}

	resp, err := ctx.OpenIDFedHTTPClient().Do(r)
	if err != nil {
		return trustMarkInfo{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not fetch the trust mark", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return trustMarkInfo{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("fetching the trust mark resulted in status %d", resp.StatusCode))
	}

	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != contentTypeTrustMarkJWT {
		return trustMarkInfo{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, fmt.Sprintf("fetching the trust mark resulted in content type %s which is invalid", resp.Header.Get("Content-Type")))
	}

	mark, err := io.ReadAll(resp.Body)
	if err != nil {
		return trustMarkInfo{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not read the trust mark", err)
	}

	return trustMarkInfo{
		Type:      markType,
		TrustMark: string(mark),
	}, nil
}

func privateKeyJWTRequest(ctx oidc.Context, authority entityStatement, uri string, params url.Values) (*http.Request, error) {
	if params == nil {
		params = url.Values{}
	}

	assertionClaims := map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimSubject:  ctx.Issuer(),
		goidc.ClaimAudience: authority.Issuer,
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimExpiry:   timeutil.TimestampNow() + 600,
		goidc.ClaimTokenID:  ctx.JWTID(),
	}
	assertion, err := ctx.OpenIDFedSign(assertionClaims, nil, authority.Metadata.FederationAuthority.EndpointAuthSigAlgValuesSupported...)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInternalError, "could not sign the assertion", err)
	}

	params.Set("client_id", ctx.Issuer())
	params.Set("client_assertion", assertion)
	params.Set("client_assertion_type", string(goidc.AssertionTypeJWTBearer))
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r, nil
}

func unauthenticatedRequest(ctx oidc.Context, uri string, params url.Values) (*http.Request, error) {
	if params == nil {
		params = url.Values{}
	}

	url, err := url.Parse(uri)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid uri", err)
	}
	url.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInternalError, "could not create the request", err)
	}
	return req, nil
}
