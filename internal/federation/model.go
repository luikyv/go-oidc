package federation

import (
	"net/url"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	contentTypeEntityStatementJWT      = "application/entity-statement+jwt"
	contentTypeTrustChain              = "application/trust-chain+json"
	contentTypeExplicitRegistrationJWT = "application/explicit-registration-response+jwt"
	contentTypeJWKSJWT                 = "application/jwk-set+jwt"
	jwtTypeEntityStatement             = "entity-statement+jwt"
	jwtTypeTrustMark                   = "trust-mark+jwt"
	jwtTypeTrustMarkDelegation         = "trust-mark-delegation+jwt"
	jwtTypeExplicitRegistration        = "explicit-registration-response+jwt"
	jwtTypeJWKS                        = "jwk-set+jwt"
	federationEndpointPath             = "/.well-known/openid-federation"
)

type entityStatement struct {
	Issuer                 string              `json:"iss"`
	Audience               string              `json:"aud,omitempty"`
	Subject                string              `json:"sub"`
	IssuedAt               int                 `json:"iat"`
	ExpiresAt              int                 `json:"exp"`
	JWKS                   goidc.JSONWebKeySet `json:"jwks"`
	AuthorityHints         []string            `json:"authority_hints,omitempty"`
	TrustAnchorHints       []string            `json:"trust_anchor_hints,omitempty"`
	Metadata               metadata            `json:"metadata"`
	MetadataPolicy         *metadataPolicy     `json:"metadata_policy,omitempty"`
	MetadataPolicyCritical []string            `json:"metadata_policy_crit,omitempty"`
	Constraints            *constraints        `json:"constraints,omitempty"`
	Critical               []string            `json:"crit,omitempty"`
	// SourceEndpoint is the endpoint from which the subordinate statement was fetched.
	SourceEndpoint string `json:"source_endpoint,omitempty"`
	TrustMarks     []struct {
		Type      string `json:"trust_mark_type"`
		TrustMark string `json:"trust_mark"`
	} `json:"trust_marks,omitempty"`
	// TrustMarkIssuers may be used by a trust anchor to tell which combination
	// of trust mark identifiers and issuers are trusted by the federation.
	// It is a JSON object with member names that are trust mark identifiers and
	// each corresponding value being an array of entity identifiers that are
	// trusted to represent the accreditation authority for trust marks with that identifier.
	// If the array following a Trust Mark identifier is empty, anyone may issue
	// trust marks with that identifier.
	TrustMarkIssuers map[string][]string `json:"trust_mark_issuers,omitempty"`
	// TrustMarkOwners is used when a trust mark identifier is owned by an entity
	// different from the trust mark issuer, then that knowledge must be expressed in this claim.
	TrustMarkOwners map[string]struct {
		// Subject is the identifier of the trust mark owner.
		Subject string `json:"sub"`
		// JWKS is the owner's federation entity keys used for signing.
		JWKS goidc.JSONWebKeySet `json:"jwks"`
	} `json:"trust_mark_owners,omitempty"`
	// TrustAnchor is the identifier of the trust anchor in the trust chain.
	// This claim is specific to explicit registration responses, it is not a general entity statement claim.
	TrustAnchor string `json:"trust_anchor,omitempty"`
	signed      string `json:"-"`
}

func (s entityStatement) Signed() string {
	return s.signed
}

type constraints struct {
	MaxPathLength     *int `json:"max_path_length,omitempty"`
	NamingConstraints *struct {
		Permitted []string `json:"permitted,omitempty"`
		Excluded  []string `json:"excluded,omitempty"`
	} `json:"naming_constraints"`
	AllowedEntityTypes []string `json:"allowed_entity_types,omitempty"`
}

// trustChain represents a sequence of entity statements forming a trust chain.
// A trust chain begins (index 0) with an entity configuration that is the subject of the trust chain.
// The trust chain has zero or more subordinate statements issued by intermediates
// about their immediate subordinates, and includes the subordinate statement issued
// by the trust anchor about the top-most Intermediate (if there are intermediates)
// or the trust chain subject (if there are no intermediates).
// The trust chain always ends with the entity configuration of the trust anchor (index len(tc)-1).
type trustChain []entityStatement

func (tc trustChain) subjectConfig() entityStatement {
	return tc[0]
}

func (tc trustChain) firstSubordinateStatement() entityStatement {
	return tc[1]
}

func (tc trustChain) subordinateStatements() []entityStatement {
	return tc[1 : len(tc)-1]
}

func (tc trustChain) trustAnchorConfig() entityStatement {
	return tc[len(tc)-1]
}

// resolve processes a trust chain to determine the final entity statement.
func (chain trustChain) resolve() (entityStatement, error) {
	var err error

	config := chain.subjectConfig()
	// [OpenID Fed 1.0 §6.1.4.2] The resolution must start by applying the metadata in the first sub statement to the subject config.
	config.Metadata, err = chain.firstSubordinateStatement().Metadata.merge(config.Metadata)
	if err != nil {
		return entityStatement{}, err
	}

	var policy metadataPolicy
	subStatements := chain.subordinateStatements()
	// [OpenID Fed 1.0 §6.1.4.1] The policy resolution must begin with the sub statement issued by the most superior entity
	// and end with the sub statement issued by the immediate superior of the trust chain subject.
	for i, subStatement := range slices.Backward(subStatements) {
		if subStatement.ExpiresAt < config.ExpiresAt {
			config.ExpiresAt = subStatement.ExpiresAt
		}

		if constraints := subStatement.Constraints; constraints != nil {
			// [OpenID Fed 1.0 §6.2.1] Check if the number of entities between the current entity the subject is greater than the max path length.
			// A max path length of 0 means that there should be no intermediate entities between the current entity and the subject.
			if maxPathLength, dist := constraints.MaxPathLength, i; maxPathLength != nil && dist > *maxPathLength {
				return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "max path length exceeded")
			}

			// [OpenID Fed 1.0 §6.2.2] Naming constraints apply to all entity identifiers from this point down to the subject.
			if namingConstraints := constraints.NamingConstraints; namingConstraints != nil {
				for j := range i + 1 {
					entityID := subStatements[j].Subject
					if namingConstraints.Permitted != nil && !slices.ContainsFunc(namingConstraints.Permitted, func(namespace string) bool {
						return matchesNamespace(entityID, namespace)
					}) {
						return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "naming constraint not met")
					}
					if slices.ContainsFunc(namingConstraints.Excluded, func(namespace string) bool {
						return matchesNamespace(entityID, namespace)
					}) {
						return entityStatement{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "naming constraint not met")
					}
				}
			}

			// TODO: [OpenID Fed 1.0 §6.2.3] Handle allowed entity types.
		}

		if subStatement.MetadataPolicy == nil {
			continue
		}

		policy, err = policy.merge(*subStatement.MetadataPolicy)
		if err != nil {
			return entityStatement{}, err
		}

		if err := policy.validate(); err != nil {
			return entityStatement{}, err
		}
	}

	config.TrustAnchor = chain.trustAnchorConfig().Issuer
	return policy.apply(config)
}

// matchesNamespace checks if an entity ID matches a namespace constraint.
func matchesNamespace(entityID, namespace string) bool {
	entityURL, err := url.Parse(entityID)
	if err != nil {
		return false
	}

	namespaceURL, err := url.Parse(namespace)
	if err != nil {
		return false
	}

	// If namespace host starts with '.', it's a wildcard for subdomains.
	if strings.HasPrefix(namespaceURL.Host, ".") {
		return strings.HasSuffix(entityURL.Host, namespaceURL.Host)
	}
	return entityURL.Host == namespaceURL.Host
}

type federationAuthority struct {
	FetchEndpoint           string `json:"federation_fetch_endpoint,omitempty"`
	ListEndpoint            string `json:"federation_list_endpoint,omitempty"`
	ResolveEndpoint         string `json:"federation_resolve_endpoint,omitempty"`
	TrustMarkStatusEndpoint string `json:"federation_trust_mark_status_endpoint,omitempty"`
	TrustMarkListEndpoint   string `json:"federation_trust_mark_list_endpoint,omitempty"`
	TrustMarkEndpoint       string `json:"federation_trust_mark_endpoint,omitempty"`
	HistoricalKeysEndpoint  string `json:"federation_historical_keys_endpoint,omitempty"`
	// EndpointAuthSigAlgValuesSupported are the algorithmsfor signing the JWT used for private_key_jwt when
	// authenticating to federation endpoints.
	EndpointAuthSigAlgValuesSupported []goidc.SignatureAlgorithm `json:"endpoint_auth_signing_alg_values_supported,omitempty"`
	OrganizationName                  string                     `json:"organization_name,omitempty"`
}

type trustMark struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	ID         string `json:"trust_mark_id"`
	IssuedAt   int    `json:"iat"`
	ExpiresAt  int    `json:"exp"`
	Delegation string `json:"delegation"`
}

type parseOptions struct {
	jwks     goidc.JSONWebKeySet
	issuer   string
	subject  string
	audience string
}
