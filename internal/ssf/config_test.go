package ssf

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNewConfiguration(t *testing.T) {
	tests := []struct {
		name string
		ctx  func(testing.TB) oidc.Context
		want configuration
	}{
		{
			name: "minimal",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com",
				JWKSURI:               "https://example.com/jwks",
				ConfigurationEndpoint: "https://example.com/configuration",
			},
		},
		{
			name: "endpoint prefix",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com/issuer"
				ctx.SSFEndpointPrefix = "/ssf"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com/issuer",
				JWKSURI:               "https://example.com/issuer/ssf/jwks",
				ConfigurationEndpoint: "https://example.com/issuer/ssf/configuration",
			},
		},
		{
			name: "delivery methods",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{
					goidc.SSFDeliveryMethodPush,
					goidc.SSFDeliveryMethodPoll,
				}
				return ctx
			},
			want: configuration{
				SpecVersion: specVersion,
				Issuer:      "https://example.com",
				JWKSURI:     "https://example.com/jwks",
				DeliveryMethods: []goidc.SSFDeliveryMethod{
					goidc.SSFDeliveryMethodPush,
					goidc.SSFDeliveryMethodPoll,
				},
				ConfigurationEndpoint: "https://example.com/configuration",
			},
		},
		{
			name: "status management",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFStatusEnabled = true
				ctx.SSFStatusEndpoint = "/status"
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com",
				JWKSURI:               "https://example.com/jwks",
				ConfigurationEndpoint: "https://example.com/configuration",
				StatusEndpoint:        "https://example.com/status",
			},
		},
		{
			name: "subject management",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFSubjectEnabled = true
				ctx.SSFSubjectAddEndpoint = "/subjects/add"
				ctx.SSFSubjectRemoveEndpoint = "/subjects/remove"
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com",
				JWKSURI:               "https://example.com/jwks",
				ConfigurationEndpoint: "https://example.com/configuration",
				AddSubjectEndpoint:    "https://example.com/subjects/add",
				RemoveSubjectEndpoint: "https://example.com/subjects/remove",
			},
		},
		{
			name: "verification",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFVerificationEnabled = true
				ctx.SSFVerificationEndpoint = "/verification"
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com",
				JWKSURI:               "https://example.com/jwks",
				ConfigurationEndpoint: "https://example.com/configuration",
				VerificationEndpoint:  "https://example.com/verification",
			},
		},
		{
			name: "critical subject members",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFCriticalSubjectMembers = []string{"user", "tenant"}
				return ctx
			},
			want: configuration{
				SpecVersion:            specVersion,
				Issuer:                 "https://example.com",
				JWKSURI:                "https://example.com/jwks",
				ConfigurationEndpoint:  "https://example.com/configuration",
				CriticalSubjectMembers: []string{"user", "tenant"},
			},
		},
		{
			name: "authorization schemes",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFAuthorizationSchemes = []goidc.SSFAuthScheme{{SpecURN: goidc.SSFAuthchemeURNRFC6749}}
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com",
				JWKSURI:               "https://example.com/jwks",
				ConfigurationEndpoint: "https://example.com/configuration",
				AuthorizationSchemes:  []goidc.SSFAuthScheme{{SpecURN: goidc.SSFAuthchemeURNRFC6749}},
			},
		},
		{
			name: "default subjects",
			ctx: func(tb testing.TB) oidc.Context {
				ctx := oidctest.NewContext(tb)
				ctx.SSFIssuer = "https://example.com"
				ctx.SSFJWKSEndpoint = "/jwks"
				ctx.SSFConfigurationEndpoint = "/configuration"
				ctx.SSFDefaultSubjects = goidc.SSFDefaultSubjectAll
				return ctx
			},
			want: configuration{
				SpecVersion:           specVersion,
				Issuer:                "https://example.com",
				JWKSURI:               "https://example.com/jwks",
				ConfigurationEndpoint: "https://example.com/configuration",
				DefaultSubjects:       goidc.SSFDefaultSubjectAll,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given.
			ctx := tt.ctx(t)

			// When.
			got := newConfiguration(ctx)

			// Then.
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("newConfiguration() diff (-want +got):\n%s", diff)
			}
		})
	}
}
