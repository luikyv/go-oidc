package federation

import (
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/discovery"
)

type metadata struct {
	FederationAuthority *federationAuthority           `json:"federation_entity,omitempty"`
	OpenIDProvider      *discovery.OpenIDConfiguration `json:"openid_provider,omitempty"`
	OpenIDClient        *client.Client                 `json:"openid_relying_party,omitempty"`
}

// Merge merges metadata from a subordinate statement (high) with metadata from
// an entity configuration (low). Values from the subordinate statement take
// precedence over values from the entity configuration.
func (subordinate metadata) Merge(config metadata) (metadata, error) {
	// Per the federation spec, subordinate statements can only modify/restrict existing metadata, not create it.
	if config.OpenIDClient == nil {
		subordinate.OpenIDClient = nil
		return subordinate, nil
	}
	if subordinate.OpenIDClient == nil {
		subordinate.OpenIDClient = config.OpenIDClient
		return subordinate, nil
	}

	sub := subordinate.OpenIDClient
	merged := *config.OpenIDClient

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
	if sub.SecretExpiresAt != nil {
		merged.SecretExpiresAt = sub.SecretExpiresAt
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
	if sub.JARIsRequired {
		merged.JARIsRequired = sub.JARIsRequired
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
	if sub.DPoPTokenBindingIsRequired {
		merged.DPoPTokenBindingIsRequired = sub.DPoPTokenBindingIsRequired
	}
	if sub.TLSSubDistinguishedName != "" {
		merged.TLSSubDistinguishedName = sub.TLSSubDistinguishedName
	}
	if sub.TLSSubAlternativeName != "" {
		merged.TLSSubAlternativeName = sub.TLSSubAlternativeName
	}
	if sub.TLSSubAlternativeNameIp != "" {
		merged.TLSSubAlternativeNameIp = sub.TLSSubAlternativeNameIp
	}
	if sub.TLSTokenBindingIsRequired {
		merged.TLSTokenBindingIsRequired = sub.TLSTokenBindingIsRequired
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
	if sub.PARIsRequired {
		merged.PARIsRequired = sub.PARIsRequired
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
	if sub.CIBAUserCodeIsEnabled {
		merged.CIBAUserCodeIsEnabled = sub.CIBAUserCodeIsEnabled
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

	subordinate.OpenIDClient = &merged
	return subordinate, nil
}
