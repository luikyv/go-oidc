package federation

import (
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMatchesNamespace(t *testing.T) {
	testCases := []struct {
		name      string
		entityID  string
		namespace string
		want      bool
	}{
		{
			name:      "exact host match",
			entityID:  "https://example.com/entity",
			namespace: "https://example.com",
			want:      true,
		},
		{
			name:      "exact host match with path",
			entityID:  "https://example.com/path/entity",
			namespace: "https://example.com",
			want:      true,
		},
		{
			name:      "different hosts",
			entityID:  "https://other.com/entity",
			namespace: "https://example.com",
			want:      false,
		},
		{
			name:      "subdomain wildcard match",
			entityID:  "https://sub.example.com/entity",
			namespace: "https://.example.com",
			want:      true,
		},
		{
			name:      "subdomain wildcard no match",
			entityID:  "https://other.com/entity",
			namespace: "https://.example.com",
			want:      false,
		},
		{
			name:      "deep subdomain wildcard match",
			entityID:  "https://deep.sub.example.com/entity",
			namespace: "https://.example.com",
			want:      true,
		},
		{
			name:      "invalid entity URL",
			entityID:  "://invalid",
			namespace: "https://example.com",
			want:      false,
		},
		{
			name:      "invalid namespace URL",
			entityID:  "https://example.com",
			namespace: "://invalid",
			want:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesNamespace(tc.entityID, tc.namespace)
			if got != tc.want {
				t.Errorf("matchesNamespace(%q, %q) = %v, want %v",
					tc.entityID, tc.namespace, got, tc.want)
			}
		})
	}
}

func TestTrustChain_SubjectConfig(t *testing.T) {
	chain := trustChain{
		{Issuer: "https://client.example.com", Subject: "https://client.example.com"},
		{Issuer: "https://intermediate.example.com", Subject: "https://client.example.com"},
		{Issuer: "https://anchor.example.com", Subject: "https://anchor.example.com"},
	}

	got := chain.subjectConfig()
	if got.Issuer != "https://client.example.com" {
		t.Errorf("subjectConfig().Issuer = %q, want %q", got.Issuer, "https://client.example.com")
	}
}

func TestTrustChain_TrustAnchorConfig(t *testing.T) {
	chain := trustChain{
		{Issuer: "https://client.example.com"},
		{Issuer: "https://intermediate.example.com"},
		{Issuer: "https://anchor.example.com"},
	}

	got := chain.trustAnchorConfig()
	if got.Issuer != "https://anchor.example.com" {
		t.Errorf("trustAnchorConfig().Issuer = %q, want %q", got.Issuer, "https://anchor.example.com")
	}
}

func TestTrustChain_SubordinateStatements(t *testing.T) {
	chain := trustChain{
		{Issuer: "https://client.example.com"},
		{Issuer: "https://int1.example.com", Subject: "https://client.example.com"},
		{Issuer: "https://int2.example.com", Subject: "https://int1.example.com"},
		{Issuer: "https://anchor.example.com"},
	}

	subs := chain.subordinateStatements()
	if len(subs) != 2 {
		t.Fatalf("len(subordinateStatements()) = %d, want 2", len(subs))
	}
	if subs[0].Issuer != "https://int1.example.com" {
		t.Errorf("subs[0].Issuer = %q, want %q", subs[0].Issuer, "https://int1.example.com")
	}
	if subs[1].Issuer != "https://int2.example.com" {
		t.Errorf("subs[1].Issuer = %q, want %q", subs[1].Issuer, "https://int2.example.com")
	}
}

func TestTrustChain_Resolve_MaxPathLength(t *testing.T) {
	maxPath := 0
	chain := trustChain{
		{
			Issuer:  "https://client.example.com",
			Subject: "https://client.example.com",
			Metadata: metadata{
				OpenIDClient: &goidc.ClientMeta{},
			},
			ExpiresAt: 9999999999,
		},
		{
			Issuer:    "https://intermediate.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 9999999999,
			Constraints: &constraints{
				MaxPathLength: &maxPath,
			},
		},
		{
			Issuer:    "https://anchor.example.com",
			Subject:   "https://anchor.example.com",
			ExpiresAt: 9999999999,
		},
	}

	// With max_path_length=0 and 1 subordinate statement, it should pass
	_, err := chain.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrustChain_Resolve_MaxPathLengthExceeded(t *testing.T) {
	maxPath := 0
	chain := trustChain{
		{
			Issuer:  "https://client.example.com",
			Subject: "https://client.example.com",
			Metadata: metadata{
				OpenIDClient: &goidc.ClientMeta{},
			},
			ExpiresAt: 9999999999,
		},
		{
			Issuer:    "https://int1.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 9999999999,
		},
		{
			Issuer:    "https://int2.example.com",
			Subject:   "https://int1.example.com",
			ExpiresAt: 9999999999,
			Constraints: &constraints{
				MaxPathLength: &maxPath, // max_path_length=0 but distance=1
			},
		},
		{
			Issuer:    "https://anchor.example.com",
			Subject:   "https://anchor.example.com",
			ExpiresAt: 9999999999,
		},
	}

	_, err := chain.resolve()
	if err == nil {
		t.Fatal("expected error for max path length exceeded")
	}
}

func TestTrustChain_Resolve_NamingConstraintsPermitted(t *testing.T) {
	chain := trustChain{
		{
			Issuer:  "https://client.example.com",
			Subject: "https://client.example.com",
			Metadata: metadata{
				OpenIDClient: &goidc.ClientMeta{},
			},
			ExpiresAt: 9999999999,
		},
		{
			Issuer:    "https://intermediate.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 9999999999,
			Constraints: &constraints{
				NamingConstraints: &struct {
					Permitted []string `json:"permitted,omitempty"`
					Excluded  []string `json:"excluded,omitempty"`
				}{
					Permitted: []string{"https://example.com"},
				},
			},
		},
		{
			Issuer:    "https://anchor.example.com",
			Subject:   "https://anchor.example.com",
			ExpiresAt: 9999999999,
		},
	}

	// client.example.com matches .example.com would need wildcard
	// Let's use exact match
	chain[1].Constraints.NamingConstraints.Permitted = []string{"https://client.example.com"}

	_, err := chain.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrustChain_Resolve_NamingConstraintsNotPermitted(t *testing.T) {
	chain := trustChain{
		{
			Issuer:  "https://client.example.com",
			Subject: "https://client.example.com",
			Metadata: metadata{
				OpenIDClient: &goidc.ClientMeta{},
			},
			ExpiresAt: 9999999999,
		},
		{
			Issuer:    "https://intermediate.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 9999999999,
			Constraints: &constraints{
				NamingConstraints: &struct {
					Permitted []string `json:"permitted,omitempty"`
					Excluded  []string `json:"excluded,omitempty"`
				}{
					Permitted: []string{"https://other.com"}, // client.example.com not in permitted
				},
			},
		},
		{
			Issuer:    "https://anchor.example.com",
			Subject:   "https://anchor.example.com",
			ExpiresAt: 9999999999,
		},
	}

	_, err := chain.resolve()
	if err == nil {
		t.Fatal("expected error for naming constraint not met")
	}
}

func TestTrustChain_Resolve_NamingConstraintsExcluded(t *testing.T) {
	chain := trustChain{
		{
			Issuer:  "https://client.example.com",
			Subject: "https://client.example.com",
			Metadata: metadata{
				OpenIDClient: &goidc.ClientMeta{},
			},
			ExpiresAt: 9999999999,
		},
		{
			Issuer:    "https://intermediate.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 9999999999,
			Constraints: &constraints{
				NamingConstraints: &struct {
					Permitted []string `json:"permitted,omitempty"`
					Excluded  []string `json:"excluded,omitempty"`
				}{
					Excluded: []string{"https://client.example.com"}, // explicitly excluded
				},
			},
		},
		{
			Issuer:    "https://anchor.example.com",
			Subject:   "https://anchor.example.com",
			ExpiresAt: 9999999999,
		},
	}

	_, err := chain.resolve()
	if err == nil {
		t.Fatal("expected error for naming constraint excluded")
	}
}

func TestTrustChain_Resolve_ExpiresAtPropagation(t *testing.T) {
	chain := trustChain{
		{
			Issuer:    "https://client.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 1000,
			Metadata: metadata{
				OpenIDClient: &goidc.ClientMeta{},
			},
		},
		{
			Issuer:    "https://intermediate.example.com",
			Subject:   "https://client.example.com",
			ExpiresAt: 500, // Earlier expiration
		},
		{
			Issuer:    "https://anchor.example.com",
			Subject:   "https://anchor.example.com",
			ExpiresAt: 2000,
		},
	}

	resolved, err := chain.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use the earliest expiration from subordinate statements
	if resolved.ExpiresAt != 500 {
		t.Errorf("resolved.ExpiresAt = %d, want 500", resolved.ExpiresAt)
	}
}

func TestEntityStatement_TrustChainHeader(t *testing.T) {
	t.Run("nil header returns nil", func(t *testing.T) {
		s := entityStatement{}
		if s.TrustChainHeader() != nil {
			t.Error("expected nil trust chain header")
		}
	})

	t.Run("returns stored header", func(t *testing.T) {
		chain := trustChain{
			{Issuer: "https://client.example.com"},
			{Issuer: "https://anchor.example.com"},
		}
		s := entityStatement{
			trustChainHeader: chain,
		}

		got := s.TrustChainHeader()
		if len(got) != 2 {
			t.Errorf("len(TrustChainHeader()) = %d, want 2", len(got))
		}
	})
}
