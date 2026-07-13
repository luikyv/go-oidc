package ssf

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	specVersion = "1_0"
)

type configuration struct {
	SpecVersion            string                    `json:"spec_version,omitempty"`
	Issuer                 string                    `json:"issuer"`
	JWKSURI                string                    `json:"jwks_uri,omitempty"`
	DeliveryMethods        []goidc.SSFDeliveryMethod `json:"delivery_methods_supported,omitempty"`
	ConfigurationEndpoint  string                    `json:"configuration_endpoint,omitempty"`
	StatusEndpoint         string                    `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint     string                    `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint  string                    `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint   string                    `json:"verification_endpoint,omitempty"`
	CriticalSubjectMembers []string                  `json:"critical_subject_members,omitempty"`
	AuthorizationSchemes   []goidc.SSFAuthScheme     `json:"authorization_schemes,omitempty"`
	DefaultSubjects        goidc.SSFDefaultSubject   `json:"default_subjects,omitempty"`
}

func newConfiguration(ctx oidc.Context) configuration {
	return configuration{
		SpecVersion:            specVersion,
		Issuer:                 ctx.SSFIssuer,
		JWKSURI:                ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFJWKSEndpoint,
		DeliveryMethods:        ctx.SSFDeliveryMethods,
		CriticalSubjectMembers: ctx.SSFCriticalSubjectMembers,
		AuthorizationSchemes:   ctx.SSFAuthorizationSchemes,
		DefaultSubjects:        ctx.SSFDefaultSubjects,
		ConfigurationEndpoint:  ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFConfigurationEndpoint,
		StatusEndpoint: func() string {
			if !ctx.SSFStatusEnabled {
				return ""
			}
			return ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFStatusEndpoint
		}(),
		AddSubjectEndpoint: func() string {
			if !ctx.SSFSubjectEnabled {
				return ""
			}
			return ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFSubjectAddEndpoint
		}(),
		RemoveSubjectEndpoint: func() string {
			if !ctx.SSFSubjectEnabled {
				return ""
			}
			return ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFSubjectRemoveEndpoint
		}(),
		VerificationEndpoint: func() string {
			if !ctx.SSFVerificationEnabled {
				return ""
			}
			return ctx.SSFIssuer + ctx.SSFEndpointPrefix + ctx.SSFVerificationEndpoint
		}(),
	}
}
