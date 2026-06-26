package federation

import (
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type metadata struct {
	FederationAuthority *goidc.FederationAuthority `json:"federation_entity,omitempty"`
	OpenIDProvider      *goidc.Configuration       `json:"openid_provider,omitempty"`
	OpenIDClient        *client.Meta               `json:"openid_relying_party,omitempty"`
}

// Merge merges metadata from a subordinate statement (high) with metadata from
// an entity configuration (low). Values from the subordinate statement take
// precedence over values from the entity configuration.
//
// Per the federation spec, subordinate statements can only modify/restrict
// existing metadata, not create it.
func (subordinate metadata) Merge(config metadata) (metadata, error) {
	if config.OpenIDProvider != nil {
		merged := *config.OpenIDProvider
		if sub := subordinate.OpenIDProvider; sub != nil {
			if sub.Issuer != "" {
				merged.Issuer = sub.Issuer
			}
			if sub.ClientRegistrationEndpoint != "" {
				merged.ClientRegistrationEndpoint = sub.ClientRegistrationEndpoint
			}
			if sub.AuthorizationEndpoint != "" {
				merged.AuthorizationEndpoint = sub.AuthorizationEndpoint
			}
			if sub.TokenEndpoint != "" {
				merged.TokenEndpoint = sub.TokenEndpoint
			}
			if sub.UserInfoEndpoint != "" {
				merged.UserInfoEndpoint = sub.UserInfoEndpoint
			}
			if sub.JWKSEndpoint != "" {
				merged.JWKSEndpoint = sub.JWKSEndpoint
			}
			if sub.PAREndpoint != "" {
				merged.PAREndpoint = sub.PAREndpoint
			}
			if sub.PARRequired {
				merged.PARRequired = sub.PARRequired
			}
			if sub.ResponseTypes != nil {
				merged.ResponseTypes = sub.ResponseTypes
			}
			if sub.ResponseModes != nil {
				merged.ResponseModes = sub.ResponseModes
			}
			if sub.GrantTypes != nil {
				merged.GrantTypes = sub.GrantTypes
			}
			if sub.Scopes != nil {
				merged.Scopes = sub.Scopes
			}
			if sub.UserClaimsSupported != nil {
				merged.UserClaimsSupported = sub.UserClaimsSupported
			}
			if sub.ClaimTypesSupported != nil {
				merged.ClaimTypesSupported = sub.ClaimTypesSupported
			}
			if sub.SubIdentifierTypes != nil {
				merged.SubIdentifierTypes = sub.SubIdentifierTypes
			}
			if sub.IDTokenSigAlgs != nil {
				merged.IDTokenSigAlgs = sub.IDTokenSigAlgs
			}
			if sub.IDTokenKeyEncAlgs != nil {
				merged.IDTokenKeyEncAlgs = sub.IDTokenKeyEncAlgs
			}
			if sub.IDTokenContentEncAlgs != nil {
				merged.IDTokenContentEncAlgs = sub.IDTokenContentEncAlgs
			}
			if sub.UserInfoKeyEncAlgs != nil {
				merged.UserInfoKeyEncAlgs = sub.UserInfoKeyEncAlgs
			}
			if sub.UserInfoContentEncAlgs != nil {
				merged.UserInfoContentEncAlgs = sub.UserInfoContentEncAlgs
			}
			if sub.UserInfoSigAlgs != nil {
				merged.UserInfoSigAlgs = sub.UserInfoSigAlgs
			}
			if sub.TokenAuthnMethods != nil {
				merged.TokenAuthnMethods = sub.TokenAuthnMethods
			}
			if sub.TokenAuthnSigAlgs != nil {
				merged.TokenAuthnSigAlgs = sub.TokenAuthnSigAlgs
			}
			if sub.JAREnabled {
				merged.JAREnabled = sub.JAREnabled
			}
			if sub.JARRequired {
				merged.JARRequired = sub.JARRequired
			}
			if sub.JARAlgs != nil {
				merged.JARAlgs = sub.JARAlgs
			}
			if sub.JARKeyEncAlgs != nil {
				merged.JARKeyEncAlgs = sub.JARKeyEncAlgs
			}
			if sub.JARContentEncAlgs != nil {
				merged.JARContentEncAlgs = sub.JARContentEncAlgs
			}
			if sub.JARByReferenceEnabled {
				merged.JARByReferenceEnabled = sub.JARByReferenceEnabled
			}
			if sub.JARRequestURIRegistrationRequired {
				merged.JARRequestURIRegistrationRequired = sub.JARRequestURIRegistrationRequired
			}
			if sub.JARMAlgs != nil {
				merged.JARMAlgs = sub.JARMAlgs
			}
			if sub.JARMKeyEncAlgs != nil {
				merged.JARMKeyEncAlgs = sub.JARMKeyEncAlgs
			}
			if sub.JARMContentEncAlgs != nil {
				merged.JARMContentEncAlgs = sub.JARMContentEncAlgs
			}
			if sub.IssuerResponseParamEnabled {
				merged.IssuerResponseParamEnabled = sub.IssuerResponseParamEnabled
			}
			if sub.ClaimsParamEnabled {
				merged.ClaimsParamEnabled = sub.ClaimsParamEnabled
			}
			if sub.AuthDetailsEnabled {
				merged.AuthDetailsEnabled = sub.AuthDetailsEnabled
			}
			if sub.AuthDetailTypesSupported != nil {
				merged.AuthDetailTypesSupported = sub.AuthDetailTypesSupported
			}
			if sub.DPoPSigAlgs != nil {
				merged.DPoPSigAlgs = sub.DPoPSigAlgs
			}
			if sub.TokenIntrospectionEndpoint != "" {
				merged.TokenIntrospectionEndpoint = sub.TokenIntrospectionEndpoint
			}
			if sub.TokenIntrospectionAuthnMethods != nil {
				merged.TokenIntrospectionAuthnMethods = sub.TokenIntrospectionAuthnMethods
			}
			if sub.TokenIntrospectionAuthnSigAlgs != nil {
				merged.TokenIntrospectionAuthnSigAlgs = sub.TokenIntrospectionAuthnSigAlgs
			}
			if sub.TokenRevocationEndpoint != "" {
				merged.TokenRevocationEndpoint = sub.TokenRevocationEndpoint
			}
			if sub.TokenRevocationAuthnMethods != nil {
				merged.TokenRevocationAuthnMethods = sub.TokenRevocationAuthnMethods
			}
			if sub.TokenRevocationAuthnSigAlgs != nil {
				merged.TokenRevocationAuthnSigAlgs = sub.TokenRevocationAuthnSigAlgs
			}
			if sub.DeviceAuthorizationEndpoint != "" {
				merged.DeviceAuthorizationEndpoint = sub.DeviceAuthorizationEndpoint
			}
			if sub.CIBATokenDeliveryModes != nil {
				merged.CIBATokenDeliveryModes = sub.CIBATokenDeliveryModes
			}
			if sub.CIBAEndpoint != "" {
				merged.CIBAEndpoint = sub.CIBAEndpoint
			}
			if sub.CIBAJARSigAlgs != nil {
				merged.CIBAJARSigAlgs = sub.CIBAJARSigAlgs
			}
			if sub.CIBAUserCodeEnabled {
				merged.CIBAUserCodeEnabled = sub.CIBAUserCodeEnabled
			}
			if sub.MTLSAliases != nil {
				merged.MTLSAliases = sub.MTLSAliases
			}
			if sub.TLSBoundTokensEnabled {
				merged.TLSBoundTokensEnabled = sub.TLSBoundTokensEnabled
			}
			if sub.ACRs != nil {
				merged.ACRs = sub.ACRs
			}
			if sub.DisplayValues != nil {
				merged.DisplayValues = sub.DisplayValues
			}
			if sub.CodeChallengeMethods != nil {
				merged.CodeChallengeMethods = sub.CodeChallengeMethods
			}
			if sub.EndSessionEndpoint != "" {
				merged.EndSessionEndpoint = sub.EndSessionEndpoint
			}
			if sub.ClientRegistrationTypes != nil {
				merged.ClientRegistrationTypes = sub.ClientRegistrationTypes
			}
			if sub.OrganizationName != "" {
				merged.OrganizationName = sub.OrganizationName
			}
			if sub.FederationRegistrationEndpoint != "" {
				merged.FederationRegistrationEndpoint = sub.FederationRegistrationEndpoint
			}
			if sub.SignedJWKSEndpoint != "" {
				merged.SignedJWKSEndpoint = sub.SignedJWKSEndpoint
			}
			if sub.JWKS != nil {
				merged.JWKS = sub.JWKS
			}
			if sub.PreAuthCodeAnonymousAccess {
				merged.PreAuthCodeAnonymousAccess = sub.PreAuthCodeAnonymousAccess
			}
		}
		subordinate.OpenIDProvider = &merged
	} else {
		subordinate.OpenIDProvider = nil
	}

	if config.OpenIDClient != nil {
		merged := *config.OpenIDClient
		if sub := subordinate.OpenIDClient; sub != nil {
			if sub.SubIdentifierTypes != nil {
				merged.SubIdentifierTypes = sub.SubIdentifierTypes
			}
			if sub.IDTokenSigAlgs != nil {
				merged.IDTokenSigAlgs = sub.IDTokenSigAlgs
			}
			if sub.IDTokenKeyEncAlgs != nil {
				merged.IDTokenKeyEncAlgs = sub.IDTokenKeyEncAlgs
			}
			if sub.IDTokenContentEncAlgs != nil {
				merged.IDTokenContentEncAlgs = sub.IDTokenContentEncAlgs
			}
			if sub.UserInfoSigAlgs != nil {
				merged.UserInfoSigAlgs = sub.UserInfoSigAlgs
			}
			if sub.UserInfoKeyEncAlgs != nil {
				merged.UserInfoKeyEncAlgs = sub.UserInfoKeyEncAlgs
			}
			if sub.UserInfoContentEncAlgs != nil {
				merged.UserInfoContentEncAlgs = sub.UserInfoContentEncAlgs
			}
			if sub.JARSigAlgs != nil {
				merged.JARSigAlgs = sub.JARSigAlgs
			}
			if sub.JARKeyEncAlgs != nil {
				merged.JARKeyEncAlgs = sub.JARKeyEncAlgs
			}
			if sub.JARContentEncAlgs != nil {
				merged.JARContentEncAlgs = sub.JARContentEncAlgs
			}
			if sub.TokenAuthnMethods != nil {
				merged.TokenAuthnMethods = sub.TokenAuthnMethods
			}
			if sub.TokenAuthnSigAlgs != nil {
				merged.TokenAuthnSigAlgs = sub.TokenAuthnSigAlgs
			}
			if sub.CIBAJARSigAlgs != nil {
				merged.CIBAJARSigAlgs = sub.CIBAJARSigAlgs
			}
			if sub.JARMSigAlgs != nil {
				merged.JARMSigAlgs = sub.JARMSigAlgs
			}
			if sub.JARMKeyEncAlgs != nil {
				merged.JARMKeyEncAlgs = sub.JARMKeyEncAlgs
			}
			if sub.JARMContentEncAlgs != nil {
				merged.JARMContentEncAlgs = sub.JARMContentEncAlgs
			}
			if sub.Name != "" {
				merged.Name = sub.Name
			}
			if sub.ApplicationType != "" {
				merged.ApplicationType = sub.ApplicationType
			}
			if sub.LogoURI != "" {
				merged.LogoURI = sub.LogoURI
			}
			if sub.Contacts != nil {
				merged.Contacts = sub.Contacts
			}
			if sub.PolicyURI != "" {
				merged.PolicyURI = sub.PolicyURI
			}
			if sub.TermsOfServiceURI != "" {
				merged.TermsOfServiceURI = sub.TermsOfServiceURI
			}
			if sub.RedirectURIs != nil {
				merged.RedirectURIs = sub.RedirectURIs
			}
			if sub.RequestURIs != nil {
				merged.RequestURIs = sub.RequestURIs
			}
			if sub.GrantTypes != nil {
				merged.GrantTypes = sub.GrantTypes
			}
			if sub.ResponseTypes != nil {
				merged.ResponseTypes = sub.ResponseTypes
			}
			if sub.JWKSURI != "" {
				merged.JWKSURI = sub.JWKSURI
			}
			if sub.JWKS != nil {
				merged.JWKS = sub.JWKS
			}
			if sub.SignedJWKSURI != "" {
				merged.SignedJWKSURI = sub.SignedJWKSURI
			}
			if sub.ScopeIDs != "" {
				merged.ScopeIDs = sub.ScopeIDs
			}
			if sub.SubIdentifierType != "" {
				merged.SubIdentifierType = sub.SubIdentifierType
			}
			if sub.SectorIdentifierURI != "" {
				merged.SectorIdentifierURI = sub.SectorIdentifierURI
			}
			if sub.IDTokenSigAlg != "" {
				merged.IDTokenSigAlg = sub.IDTokenSigAlg
			}
			if sub.IDTokenKeyEncAlg != "" {
				merged.IDTokenKeyEncAlg = sub.IDTokenKeyEncAlg
			}
			if sub.IDTokenContentEncAlg != "" {
				merged.IDTokenContentEncAlg = sub.IDTokenContentEncAlg
			}
			if sub.UserInfoSigAlg != "" {
				merged.UserInfoSigAlg = sub.UserInfoSigAlg
			}
			if sub.UserInfoKeyEncAlg != "" {
				merged.UserInfoKeyEncAlg = sub.UserInfoKeyEncAlg
			}
			if sub.UserInfoContentEncAlg != "" {
				merged.UserInfoContentEncAlg = sub.UserInfoContentEncAlg
			}
			if sub.JARRequired {
				merged.JARRequired = sub.JARRequired
			}
			if sub.JARSigAlg != "" {
				merged.JARSigAlg = sub.JARSigAlg
			}
			if sub.JARKeyEncAlg != "" {
				merged.JARKeyEncAlg = sub.JARKeyEncAlg
			}
			if sub.JARContentEncAlg != "" {
				merged.JARContentEncAlg = sub.JARContentEncAlg
			}
			if sub.JARMSigAlg != "" {
				merged.JARMSigAlg = sub.JARMSigAlg
			}
			if sub.JARMKeyEncAlg != "" {
				merged.JARMKeyEncAlg = sub.JARMKeyEncAlg
			}
			if sub.JARMContentEncAlg != "" {
				merged.JARMContentEncAlg = sub.JARMContentEncAlg
			}
			if sub.TokenAuthnMethod != "" {
				merged.TokenAuthnMethod = sub.TokenAuthnMethod
			}
			if sub.TokenAuthnSigAlg != "" {
				merged.TokenAuthnSigAlg = sub.TokenAuthnSigAlg
			}
			if sub.TokenIntrospectionAuthnMethod != "" {
				merged.TokenIntrospectionAuthnMethod = sub.TokenIntrospectionAuthnMethod
			}
			if sub.TokenIntrospectionAuthnSigAlg != "" {
				merged.TokenIntrospectionAuthnSigAlg = sub.TokenIntrospectionAuthnSigAlg
			}
			if sub.TokenRevocationAuthnMethod != "" {
				merged.TokenRevocationAuthnMethod = sub.TokenRevocationAuthnMethod
			}
			if sub.TokenRevocationAuthnSigAlg != "" {
				merged.TokenRevocationAuthnSigAlg = sub.TokenRevocationAuthnSigAlg
			}
			if sub.DPoPTokenBindingRequired {
				merged.DPoPTokenBindingRequired = sub.DPoPTokenBindingRequired
			}
			if sub.TLSSubjectDistinguishedName != "" {
				merged.TLSSubjectDistinguishedName = sub.TLSSubjectDistinguishedName
			}
			if sub.TLSSubjectAlternativeName != "" {
				merged.TLSSubjectAlternativeName = sub.TLSSubjectAlternativeName
			}
			if sub.TLSSubjectAlternativeNameIP != "" {
				merged.TLSSubjectAlternativeNameIP = sub.TLSSubjectAlternativeNameIP
			}
			if sub.TLSTokenBindingRequired {
				merged.TLSTokenBindingRequired = sub.TLSTokenBindingRequired
			}
			if sub.AuthDetailTypes != nil {
				merged.AuthDetailTypes = sub.AuthDetailTypes
			}
			if sub.DefaultMaxAgeSecs != nil {
				merged.DefaultMaxAgeSecs = sub.DefaultMaxAgeSecs
			}
			if sub.DefaultACRValues != "" {
				merged.DefaultACRValues = sub.DefaultACRValues
			}
			if sub.PARRequired {
				merged.PARRequired = sub.PARRequired
			}
			if sub.CIBATokenDeliveryMode != "" {
				merged.CIBATokenDeliveryMode = sub.CIBATokenDeliveryMode
			}
			if sub.CIBANotificationEndpoint != "" {
				merged.CIBANotificationEndpoint = sub.CIBANotificationEndpoint
			}
			if sub.CIBAJARSigAlg != "" {
				merged.CIBAJARSigAlg = sub.CIBAJARSigAlg
			}
			if sub.CIBAUserCodeEnabled {
				merged.CIBAUserCodeEnabled = sub.CIBAUserCodeEnabled
			}
			if sub.OrganizationName != "" {
				merged.OrganizationName = sub.OrganizationName
			}
			if sub.PostLogoutRedirectURIs != nil {
				merged.PostLogoutRedirectURIs = sub.PostLogoutRedirectURIs
			}
			if sub.ClientRegistrationTypes != nil {
				merged.ClientRegistrationTypes = sub.ClientRegistrationTypes
			}
			if sub.DisplayName != "" {
				merged.DisplayName = sub.DisplayName
			}
			if sub.Description != "" {
				merged.Description = sub.Description
			}
			if sub.Keywords != nil {
				merged.Keywords = sub.Keywords
			}
			if sub.InformationURI != "" {
				merged.InformationURI = sub.InformationURI
			}
			if sub.OrganizationURI != "" {
				merged.OrganizationURI = sub.OrganizationURI
			}
			if sub.CredentialOfferEndpoint != "" {
				merged.CredentialOfferEndpoint = sub.CredentialOfferEndpoint
			}
			if sub.CustomAttributes != nil {
				merged.CustomAttributes = sub.CustomAttributes
			}
		}
		subordinate.OpenIDClient = &merged
	} else {
		subordinate.OpenIDClient = nil
	}

	return subordinate, nil
}
