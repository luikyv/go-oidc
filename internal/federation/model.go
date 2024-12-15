package federation

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type openIDEntityStatement struct {
	Issuer         string             `json:"iss"`
	Subject        string             `json:"sub"`
	IssuedAt       int                `json:"iat"`
	ExpiresAt      int                `json:"exp"`
	JWKS           jose.JSONWebKeySet `json:"jwks"`
	AuthorityHints []string           `json:"authority_hints,omitempty"`
	Metadata       struct {
		OpenIDAuthority *openIDAuthority `json:"federation_entity,omitempty"`
		OpenIDProvider  *openIDProvider  `json:"openid_provider,omitempty"`
		OpenIDClient    *openIDClient    `json:"openid_relying_party,omitempty"`
	} `json:"metadata"`
	MetadataPolicy *metadataPolicy `json:"metadata_policy,omitempty"`
	signed         string          `json:"-"`
}

func (s openIDEntityStatement) Signed() string {
	return s.signed
}

type openIDProvider struct {
	discovery.OpenIDConfiguration
}

type openIDClient struct {
	goidc.ClientMetaInfo
}

type openIDAuthority struct {
	FetchEndpoint    string `json:"federation_fetch_endpoint"`
	ListEndpoint     string `json:"federation_list_endpoint"`
	ResolveEndpoint  string `json:"federation_resolve_endpoint"`
	OrganizationName string `json:"organization_name"`
}
