package federation

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMetadataPolicy_Validate(t *testing.T) {
	// Given.
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}

	// When.
	err := policy.validate()

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPolicy_Merge(t *testing.T) {
	// Given.
	highPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	lowPolicy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}

	// When.
	_, err := highPolicy.merge(lowPolicy)

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPolicy_Apply(t *testing.T) {
	// Given.
	policy := metadataPolicy{
		OpenIDClient: &openIDClientMetadataPolicy{},
	}
	statement := entityStatement{
		Metadata: struct {
			FederationAuthority *federationAuthority           "json:\"federation_entity,omitempty\""
			OpenIDProvider      *discovery.OpenIDConfiguration "json:\"openid_provider,omitempty\""
			OpenIDClient        *goidc.ClientMeta              "json:\"openid_relying_party,omitempty\""
		}{
			OpenIDClient: &goidc.ClientMeta{},
		},
	}

	// When.
	_, err := policy.apply(statement)

	// Then.
	if err != nil {
		t.Fatal(err)
	}
}
