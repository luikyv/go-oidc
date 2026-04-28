package federation

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type metadataPolicy struct {
	OpenIDClient *openIDClientMetadataPolicy `json:"openid_relying_party,omitempty"`
}

func (policy metadataPolicy) Validate() error {
	if policy.OpenIDClient != nil {
		if err := policy.OpenIDClient.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (highPolicy metadataPolicy) Merge(lowPolicy metadataPolicy) (metadataPolicy, error) {
	if lowPolicy.OpenIDClient != nil {
		var highOpenIDClient openIDClientMetadataPolicy
		if highPolicy.OpenIDClient != nil {
			highOpenIDClient = *highPolicy.OpenIDClient
		}

		result, err := highOpenIDClient.Merge(*lowPolicy.OpenIDClient)
		if err != nil {
			return metadataPolicy{}, err
		}

		highPolicy.OpenIDClient = &result
	}

	return highPolicy, nil
}

func (policy metadataPolicy) Apply(statement entityStatement) (entityStatement, error) {
	if original, policy := statement.Metadata.OpenIDClient, policy.OpenIDClient; original != nil && policy != nil {
		modified, err := policy.Apply(*original)
		if err != nil {
			return entityStatement{}, err
		}
		statement.Metadata.OpenIDClient = &modified
	}

	return statement, nil
}

type openIDClientMetadataPolicy struct {
	Name                          metadataOperators[string]                           `json:"client_name"`
	ApplicationType               metadataOperators[goidc.ApplicationType]            `json:"application_type"`
	LogoURI                       metadataOperators[string]                           `json:"logo_uri"`
	Contacts                      metadataOperators[[]string]                         `json:"contacts"`
	PolicyURI                     metadataOperators[string]                           `json:"policy_uri"`
	TermsOfServiceURI             metadataOperators[string]                           `json:"tos_uri"`
	RedirectURIs                  metadataOperators[[]string]                         `json:"redirect_uris"`
	RequestURIs                   metadataOperators[[]string]                         `json:"request_uris"`
	GrantTypes                    metadataOperators[[]goidc.GrantType]                `json:"grant_types"`
	ResponseTypes                 metadataOperators[[]goidc.ResponseType]             `json:"response_types"`
	JWKSURI                       metadataOperators[string]                           `json:"jwks_uri"`
	JWKS                          metadataOperators[*goidc.JSONWebKeySet]             `json:"jwks"`
	ScopeIDs                      metadataOperators[[]string]                         `json:"scope"`
	SubIdentifierType             metadataOperators[goidc.SubIdentifierType]          `json:"subject_type"`
	SectorIdentifierURI           metadataOperators[string]                           `json:"sector_identifier_uri"`
	IDTokenSigAlg                 metadataOperators[goidc.SignatureAlgorithm]         `json:"id_token_signed_response_alg"`
	IDTokenKeyEncAlg              metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"id_token_encrypted_response_alg"`
	IDTokenContentEncAlg          metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"id_token_encrypted_response_enc"`
	UserInfoSigAlg                metadataOperators[goidc.SignatureAlgorithm]         `json:"userinfo_signed_response_alg"`
	UserInfoKeyEncAlg             metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"userinfo_encrypted_response_alg"`
	UserInfoContentEncAlg         metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"userinfo_encrypted_response_enc"`
	JARIsRequired                 metadataOperators[bool]                             `json:"require_signed_request_object"`
	JARSigAlg                     metadataOperators[goidc.SignatureAlgorithm]         `json:"request_object_signing_alg"`
	JARKeyEncAlg                  metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"request_object_encryption_alg"`
	JARContentEncAlg              metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"request_object_encryption_enc"`
	JARMSigAlg                    metadataOperators[goidc.SignatureAlgorithm]         `json:"authorization_signed_response_alg"`
	JARMKeyEncAlg                 metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"authorization_encrypted_response_alg"`
	JARMContentEncAlg             metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"authorization_encrypted_response_enc"`
	TokenAuthnMethod              metadataOperators[goidc.AuthnMethod]                `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              metadataOperators[goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg"`
	TokenIntrospectionAuthnMethod metadataOperators[goidc.AuthnMethod]                `json:"introspection_endpoint_auth_method"`
	TokenIntrospectionAuthnSigAlg metadataOperators[goidc.SignatureAlgorithm]         `json:"introspection_endpoint_auth_signing_alg"`
	TokenRevocationAuthnMethod    metadataOperators[goidc.AuthnMethod]                `json:"revocation_endpoint_auth_method"`
	TokenRevocationAuthnSigAlg    metadataOperators[goidc.SignatureAlgorithm]         `json:"revocation_endpoint_auth_signing_alg"`
	DPoPTokenBindingIsRequired    metadataOperators[bool]                             `json:"dpop_bound_access_tokens"`
	TLSSubDistinguishedName       metadataOperators[string]                           `json:"tls_client_auth_subject_dn"`
	TLSSubAlternativeName         metadataOperators[string]                           `json:"tls_client_auth_san_dns"`
	TLSSubAlternativeNameIp       metadataOperators[string]                           `json:"tls_client_auth_san_ip"`
	TLSTokenBindingIsRequired     metadataOperators[bool]                             `json:"tls_client_certificate_bound_access_tokens"`
	AuthDetailTypes               metadataOperators[[]goidc.AuthDetailType]           `json:"authorization_details_types"`
	DefaultMaxAgeSecs             metadataOperators[*int]                             `json:"default_max_age"`
	DefaultACRValues              metadataOperators[string]                           `json:"default_acr_values"`
	PARIsRequired                 metadataOperators[bool]                             `json:"require_pushed_authorization_requests"`
	CIBATokenDeliveryMode         metadataOperators[goidc.CIBATokenDeliveryMode]      `json:"backchannel_token_delivery_mode"`
	CIBANotificationEndpoint      metadataOperators[string]                           `json:"backchannel_client_notification_endpoint"`
	CIBAJARSigAlg                 metadataOperators[goidc.SignatureAlgorithm]         `json:"backchannel_authentication_request_signing_alg"`
	CIBAUserCodeIsEnabled         metadataOperators[bool]                             `json:"backchannel_user_code_parameter"`
	SignedJWKSURI                 metadataOperators[string]                           `json:"signed_jwks_uri"`
	OrganizationName              metadataOperators[string]                           `json:"organization_name"`
	ClientRegistrationTypes       metadataOperators[[]goidc.ClientRegistrationType]   `json:"client_registration_types"`
	PostLogoutRedirectURIs        metadataOperators[[]string]                         `json:"post_logout_redirect_uris"`
	DisplayName                   metadataOperators[string]                           `json:"display_name"`
	Description                   metadataOperators[string]                           `json:"description"`
	Keywords                      metadataOperators[[]string]                         `json:"keywords"`
	InformationURI                metadataOperators[string]                           `json:"information_uri"`
	OrganizationURI               metadataOperators[string]                           `json:"organization_uri"`
	CredentialOfferEndpoint       metadataOperators[string]                           `json:"credential_offer_endpoint"`
	CustomAttributes              map[string]metadataOperators[any]                   `json:"custom_attributes"`
}

func (policy *openIDClientMetadataPolicy) setCustomAttribute(att string, value metadataOperators[any]) {
	if policy.CustomAttributes == nil {
		policy.CustomAttributes = map[string]metadataOperators[any]{}
	}
	policy.CustomAttributes[att] = value
}

func (policy *openIDClientMetadataPolicy) customAttribute(att string) metadataOperators[any] {
	return policy.CustomAttributes[att]
}

func (policy *openIDClientMetadataPolicy) UnmarshalJSON(data []byte) error {
	// Unmarshal into a map to capture all keys.
	var allFields map[string]metadataOperators[any]
	if err := json.Unmarshal(data, &allFields); err != nil { //nolint:musttag
		return err
	}

	type alias openIDClientMetadataPolicy
	var info alias
	if err := json.Unmarshal(data, &info); err != nil { //nolint:musttag
		return err
	}

	info.CustomAttributes = make(map[string]metadataOperators[any])
	for key, value := range allFields {
		if !slices.Contains(client.JSONFields, key) {
			info.CustomAttributes[key] = value
		}
	}

	*policy = openIDClientMetadataPolicy(info)
	return nil
}

func (p openIDClientMetadataPolicy) Validate() error {
	if err := p.Name.Validate(); err != nil {
		return err
	}

	if err := p.ApplicationType.Validate(); err != nil {
		return err
	}

	if err := p.LogoURI.Validate(); err != nil {
		return err
	}

	if err := p.Contacts.Validate(); err != nil {
		return err
	}

	if err := p.PolicyURI.Validate(); err != nil {
		return err
	}

	if err := p.TermsOfServiceURI.Validate(); err != nil {
		return err
	}

	if err := p.RedirectURIs.Validate(); err != nil {
		return err
	}

	if err := p.RequestURIs.Validate(); err != nil {
		return err
	}

	if err := p.GrantTypes.Validate(); err != nil {
		return err
	}

	if err := p.ResponseTypes.Validate(); err != nil {
		return err
	}

	if err := p.JWKSURI.Validate(); err != nil {
		return err
	}

	if err := p.JWKS.Validate(); err != nil {
		return err
	}

	if err := p.ScopeIDs.Validate(); err != nil {
		return err
	}

	if err := p.SubIdentifierType.Validate(); err != nil {
		return err
	}

	if err := p.SectorIdentifierURI.Validate(); err != nil {
		return err
	}

	if err := p.IDTokenSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.IDTokenKeyEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.IDTokenContentEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.UserInfoSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.UserInfoKeyEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.UserInfoContentEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.JARIsRequired.Validate(); err != nil {
		return err
	}

	if err := p.JARSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.JARKeyEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.JARContentEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.JARMSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.JARMKeyEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.JARMContentEncAlg.Validate(); err != nil {
		return err
	}

	if err := p.TokenAuthnMethod.Validate(); err != nil {
		return err
	}

	if err := p.TokenAuthnSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.TokenIntrospectionAuthnMethod.Validate(); err != nil {
		return err
	}

	if err := p.TokenIntrospectionAuthnSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.TokenRevocationAuthnMethod.Validate(); err != nil {
		return err
	}

	if err := p.TokenRevocationAuthnSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.DPoPTokenBindingIsRequired.Validate(); err != nil {
		return err
	}

	if err := p.TLSSubDistinguishedName.Validate(); err != nil {
		return err
	}

	if err := p.TLSSubAlternativeName.Validate(); err != nil {
		return err
	}

	if err := p.TLSSubAlternativeNameIp.Validate(); err != nil {
		return err
	}

	if err := p.TLSTokenBindingIsRequired.Validate(); err != nil {
		return err
	}

	if err := p.AuthDetailTypes.Validate(); err != nil {
		return err
	}

	if err := p.DefaultMaxAgeSecs.Validate(); err != nil {
		return err
	}

	if err := p.DefaultACRValues.Validate(); err != nil {
		return err
	}

	if err := p.PARIsRequired.Validate(); err != nil {
		return err
	}

	if err := p.CIBATokenDeliveryMode.Validate(); err != nil {
		return err
	}

	if err := p.CIBANotificationEndpoint.Validate(); err != nil {
		return err
	}

	if err := p.CIBAJARSigAlg.Validate(); err != nil {
		return err
	}

	if err := p.CIBAUserCodeIsEnabled.Validate(); err != nil {
		return err
	}

	if err := p.SignedJWKSURI.Validate(); err != nil {
		return err
	}

	if err := p.OrganizationName.Validate(); err != nil {
		return err
	}

	if err := p.ClientRegistrationTypes.Validate(); err != nil {
		return err
	}

	if err := p.PostLogoutRedirectURIs.Validate(); err != nil {
		return err
	}

	if err := p.DisplayName.Validate(); err != nil {
		return err
	}

	if err := p.Description.Validate(); err != nil {
		return err
	}

	if err := p.Keywords.Validate(); err != nil {
		return err
	}

	if err := p.InformationURI.Validate(); err != nil {
		return err
	}

	if err := p.OrganizationURI.Validate(); err != nil {
		return err
	}

	if err := p.CredentialOfferEndpoint.Validate(); err != nil {
		return err
	}

	for _, ops := range p.CustomAttributes {
		if err := ops.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (high openIDClientMetadataPolicy) Merge(low openIDClientMetadataPolicy) (openIDClientMetadataPolicy, error) {
	opName, err := high.Name.Merge(low.Name)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.Name = opName

	opApplicationType, err := high.ApplicationType.Merge(low.ApplicationType)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ApplicationType = opApplicationType

	opLogoURI, err := high.LogoURI.Merge(low.LogoURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.LogoURI = opLogoURI

	opContacts, err := high.Contacts.Merge(low.Contacts)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.Contacts = opContacts

	opPolicyURI, err := high.PolicyURI.Merge(low.PolicyURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PolicyURI = opPolicyURI

	opTermsOfServiceURI, err := high.TermsOfServiceURI.Merge(low.TermsOfServiceURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TermsOfServiceURI = opTermsOfServiceURI

	opRedirectURIs, err := high.RedirectURIs.Merge(low.RedirectURIs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.RedirectURIs = opRedirectURIs

	opRequestURIs, err := high.RequestURIs.Merge(low.RequestURIs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.RequestURIs = opRequestURIs

	opGrantTypes, err := high.GrantTypes.Merge(low.GrantTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.GrantTypes = opGrantTypes

	opResponseTypes, err := high.ResponseTypes.Merge(low.ResponseTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ResponseTypes = opResponseTypes

	opJWKSURI, err := high.JWKSURI.Merge(low.JWKSURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JWKSURI = opJWKSURI

	opJWKS, err := high.JWKS.Merge(low.JWKS)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JWKS = opJWKS

	opScopeIDs, err := high.ScopeIDs.Merge(low.ScopeIDs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ScopeIDs = opScopeIDs

	opSubIdentifierType, err := high.SubIdentifierType.Merge(low.SubIdentifierType)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.SubIdentifierType = opSubIdentifierType

	opSectorIdentifierURI, err := high.SectorIdentifierURI.Merge(low.SectorIdentifierURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.SectorIdentifierURI = opSectorIdentifierURI

	opIDTokenSigAlg, err := high.IDTokenSigAlg.Merge(low.IDTokenSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenSigAlg = opIDTokenSigAlg

	opIDTokenKeyEncAlg, err := high.IDTokenKeyEncAlg.Merge(low.IDTokenKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenKeyEncAlg = opIDTokenKeyEncAlg

	opIDTokenContentEncAlg, err := high.IDTokenContentEncAlg.Merge(low.IDTokenContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenContentEncAlg = opIDTokenContentEncAlg

	opUserInfoSigAlg, err := high.UserInfoSigAlg.Merge(low.UserInfoSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoSigAlg = opUserInfoSigAlg

	opUserInfoKeyEncAlg, err := high.UserInfoKeyEncAlg.Merge(low.UserInfoKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoKeyEncAlg = opUserInfoKeyEncAlg

	opUserInfoContentEncAlg, err := high.UserInfoContentEncAlg.Merge(low.UserInfoContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoContentEncAlg = opUserInfoContentEncAlg

	opJARIsRequired, err := high.JARIsRequired.Merge(low.JARIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARIsRequired = opJARIsRequired

	opJARSigAlg, err := high.JARSigAlg.Merge(low.JARSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARSigAlg = opJARSigAlg

	opJARKeyEncAlg, err := high.JARKeyEncAlg.Merge(low.JARKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARKeyEncAlg = opJARKeyEncAlg

	opJARContentEncAlg, err := high.JARContentEncAlg.Merge(low.JARContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARContentEncAlg = opJARContentEncAlg

	opJARMSigAlg, err := high.JARMSigAlg.Merge(low.JARMSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMSigAlg = opJARMSigAlg

	opJARMKeyEncAlg, err := high.JARMKeyEncAlg.Merge(low.JARMKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMKeyEncAlg = opJARMKeyEncAlg

	opJARMContentEncAlg, err := high.JARMContentEncAlg.Merge(low.JARMContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMContentEncAlg = opJARMContentEncAlg

	opTokenAuthnMethod, err := high.TokenAuthnMethod.Merge(low.TokenAuthnMethod)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenAuthnMethod = opTokenAuthnMethod

	opTokenAuthnSigAlg, err := high.TokenAuthnSigAlg.Merge(low.TokenAuthnSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenAuthnSigAlg = opTokenAuthnSigAlg

	opTokenIntrospectionAuthnMethod, err := high.TokenIntrospectionAuthnMethod.Merge(low.TokenIntrospectionAuthnMethod)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenIntrospectionAuthnMethod = opTokenIntrospectionAuthnMethod

	opTokenIntrospectionAuthnSigAlg, err := high.TokenIntrospectionAuthnSigAlg.Merge(low.TokenIntrospectionAuthnSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenIntrospectionAuthnSigAlg = opTokenIntrospectionAuthnSigAlg

	opTokenRevocationAuthnMethod, err := high.TokenRevocationAuthnMethod.Merge(low.TokenRevocationAuthnMethod)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenRevocationAuthnMethod = opTokenRevocationAuthnMethod

	opTokenRevocationAuthnSigAlg, err := high.TokenRevocationAuthnSigAlg.Merge(low.TokenRevocationAuthnSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenRevocationAuthnSigAlg = opTokenRevocationAuthnSigAlg

	opDPoPTokenBindingIsRequired, err := high.DPoPTokenBindingIsRequired.Merge(low.DPoPTokenBindingIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DPoPTokenBindingIsRequired = opDPoPTokenBindingIsRequired

	opTLSSubDistinguishedName, err := high.TLSSubDistinguishedName.Merge(low.TLSSubDistinguishedName)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSSubDistinguishedName = opTLSSubDistinguishedName

	opTLSSubAlternativeName, err := high.TLSSubAlternativeName.Merge(low.TLSSubAlternativeName)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSSubAlternativeName = opTLSSubAlternativeName

	opTLSSubAlternativeNameIp, err := high.TLSSubAlternativeNameIp.Merge(low.TLSSubAlternativeNameIp)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSSubAlternativeNameIp = opTLSSubAlternativeNameIp

	opTLSTokenBindingIsRequired, err := high.TLSTokenBindingIsRequired.Merge(low.TLSTokenBindingIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSTokenBindingIsRequired = opTLSTokenBindingIsRequired

	opAuthDetailTypes, err := high.AuthDetailTypes.Merge(low.AuthDetailTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.AuthDetailTypes = opAuthDetailTypes

	opDefaultMaxAgeSecs, err := high.DefaultMaxAgeSecs.Merge(low.DefaultMaxAgeSecs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DefaultMaxAgeSecs = opDefaultMaxAgeSecs

	opDefaultACRValues, err := high.DefaultACRValues.Merge(low.DefaultACRValues)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DefaultACRValues = opDefaultACRValues

	opPARIsRequired, err := high.PARIsRequired.Merge(low.PARIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PARIsRequired = opPARIsRequired

	opCIBATokenDeliveryMode, err := high.CIBATokenDeliveryMode.Merge(low.CIBATokenDeliveryMode)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBATokenDeliveryMode = opCIBATokenDeliveryMode

	opCIBANotificationEndpoint, err := high.CIBANotificationEndpoint.Merge(low.CIBANotificationEndpoint)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBANotificationEndpoint = opCIBANotificationEndpoint

	opCIBAJARSigAlg, err := high.CIBAJARSigAlg.Merge(low.CIBAJARSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBAJARSigAlg = opCIBAJARSigAlg

	opCIBAUserCodeIsEnabled, err := high.CIBAUserCodeIsEnabled.Merge(low.CIBAUserCodeIsEnabled)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBAUserCodeIsEnabled = opCIBAUserCodeIsEnabled

	opSignedJWKSURI, err := high.SignedJWKSURI.Merge(low.SignedJWKSURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.SignedJWKSURI = opSignedJWKSURI

	opOrganizationName, err := high.OrganizationName.Merge(low.OrganizationName)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.OrganizationName = opOrganizationName

	opClientRegistrationTypes, err := high.ClientRegistrationTypes.Merge(low.ClientRegistrationTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ClientRegistrationTypes = opClientRegistrationTypes

	opPostLogoutRedirectURIs, err := high.PostLogoutRedirectURIs.Merge(low.PostLogoutRedirectURIs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PostLogoutRedirectURIs = opPostLogoutRedirectURIs

	opDisplayName, err := high.DisplayName.Merge(low.DisplayName)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DisplayName = opDisplayName

	opDescription, err := high.Description.Merge(low.Description)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.Description = opDescription

	opKeywords, err := high.Keywords.Merge(low.Keywords)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.Keywords = opKeywords

	opInformationURI, err := high.InformationURI.Merge(low.InformationURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.InformationURI = opInformationURI

	opOrganizationURI, err := high.OrganizationURI.Merge(low.OrganizationURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.OrganizationURI = opOrganizationURI

	opCredentialOfferEndpoint, err := high.CredentialOfferEndpoint.Merge(low.CredentialOfferEndpoint)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CredentialOfferEndpoint = opCredentialOfferEndpoint

	for att, lowOps := range low.CustomAttributes {
		ops, err := high.customAttribute(att).Merge(lowOps)
		if err != nil {
			return openIDClientMetadataPolicy{}, err
		}
		high.setCustomAttribute(att, ops)
	}

	return high, nil
}

func (policy openIDClientMetadataPolicy) Apply(c goidc.ClientMeta) (goidc.ClientMeta, error) {
	name, err := policy.Name.Apply(c.Name)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.Name = name

	applicationType, err := policy.ApplicationType.Apply(c.ApplicationType)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.ApplicationType = applicationType

	logoURI, err := policy.LogoURI.Apply(c.LogoURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.LogoURI = logoURI

	contacts, err := policy.Contacts.Apply(c.Contacts)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.Contacts = contacts

	policyURI, err := policy.PolicyURI.Apply(c.PolicyURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.PolicyURI = policyURI

	termsOfServiceURI, err := policy.TermsOfServiceURI.Apply(c.TermsOfServiceURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TermsOfServiceURI = termsOfServiceURI

	redirectURIs, err := policy.RedirectURIs.Apply(c.RedirectURIs)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.RedirectURIs = redirectURIs

	requestURIs, err := policy.RequestURIs.Apply(c.RequestURIs)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.RequestURIs = requestURIs

	grantTypes, err := policy.GrantTypes.Apply(c.GrantTypes)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.GrantTypes = grantTypes

	responseTypes, err := policy.ResponseTypes.Apply(c.ResponseTypes)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.ResponseTypes = responseTypes

	jwksURI, err := policy.JWKSURI.Apply(c.JWKSURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JWKSURI = jwksURI

	jwks, err := policy.JWKS.Apply(c.JWKS)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JWKS = jwks

	scopeIDs := strutil.SplitWithSpaces(c.ScopeIDs)
	scopeIDs, err = policy.ScopeIDs.Apply(scopeIDs)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.ScopeIDs = strings.Join(scopeIDs, " ")

	subIdentifierType, err := policy.SubIdentifierType.Apply(c.SubIdentifierType)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.SubIdentifierType = subIdentifierType

	sectorIdentifierURI, err := policy.SectorIdentifierURI.Apply(c.SectorIdentifierURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.SectorIdentifierURI = sectorIdentifierURI

	idTokenSigAlg, err := policy.IDTokenSigAlg.Apply(c.IDTokenSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.IDTokenSigAlg = idTokenSigAlg

	idTokenKeyEncAlg, err := policy.IDTokenKeyEncAlg.Apply(c.IDTokenKeyEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.IDTokenKeyEncAlg = idTokenKeyEncAlg

	idTokenContentEncAlg, err := policy.IDTokenContentEncAlg.Apply(c.IDTokenContentEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.IDTokenContentEncAlg = idTokenContentEncAlg

	userInfoSigAlg, err := policy.UserInfoSigAlg.Apply(c.UserInfoSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.UserInfoSigAlg = userInfoSigAlg

	userInfoKeyEncAlg, err := policy.UserInfoKeyEncAlg.Apply(c.UserInfoKeyEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.UserInfoKeyEncAlg = userInfoKeyEncAlg

	userInfoContentEncAlg, err := policy.UserInfoContentEncAlg.Apply(c.UserInfoContentEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.UserInfoContentEncAlg = userInfoContentEncAlg

	jarIsRequired, err := policy.JARIsRequired.Apply(c.JARIsRequired)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARIsRequired = jarIsRequired

	jarSigAlg, err := policy.JARSigAlg.Apply(c.JARSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARSigAlg = jarSigAlg

	jarKeyEncAlg, err := policy.JARKeyEncAlg.Apply(c.JARKeyEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARKeyEncAlg = jarKeyEncAlg

	jarContentEncAlg, err := policy.JARContentEncAlg.Apply(c.JARContentEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARContentEncAlg = jarContentEncAlg

	jarmSigAlg, err := policy.JARMSigAlg.Apply(c.JARMSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARMSigAlg = jarmSigAlg

	jarmKeyEncAlg, err := policy.JARMKeyEncAlg.Apply(c.JARMKeyEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARMKeyEncAlg = jarmKeyEncAlg

	jarmContentEncAlg, err := policy.JARMContentEncAlg.Apply(c.JARMContentEncAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.JARMContentEncAlg = jarmContentEncAlg

	tokenAuthnMethod, err := policy.TokenAuthnMethod.Apply(c.TokenAuthnMethod)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TokenAuthnMethod = tokenAuthnMethod

	tokenAuthnSigAlg, err := policy.TokenAuthnSigAlg.Apply(c.TokenAuthnSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TokenAuthnSigAlg = tokenAuthnSigAlg

	tokenIntrospectionAuthnMethod, err := policy.TokenIntrospectionAuthnMethod.Apply(c.TokenIntrospectionAuthnMethod)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TokenIntrospectionAuthnMethod = tokenIntrospectionAuthnMethod

	tokenIntrospectionAuthnSigAlg, err := policy.TokenIntrospectionAuthnSigAlg.Apply(c.TokenIntrospectionAuthnSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TokenIntrospectionAuthnSigAlg = tokenIntrospectionAuthnSigAlg

	tokenRevocationAuthnMethod, err := policy.TokenRevocationAuthnMethod.Apply(c.TokenRevocationAuthnMethod)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TokenRevocationAuthnMethod = tokenRevocationAuthnMethod

	tokenRevocationAuthnSigAlg, err := policy.TokenRevocationAuthnSigAlg.Apply(c.TokenRevocationAuthnSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TokenRevocationAuthnSigAlg = tokenRevocationAuthnSigAlg

	dPoPTokenBindingIsRequired, err := policy.DPoPTokenBindingIsRequired.Apply(c.DPoPTokenBindingIsRequired)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.DPoPTokenBindingIsRequired = dPoPTokenBindingIsRequired

	tlsSubDistinguishedName, err := policy.TLSSubDistinguishedName.Apply(c.TLSSubDistinguishedName)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TLSSubDistinguishedName = tlsSubDistinguishedName

	tlsSubAlternativeName, err := policy.TLSSubAlternativeName.Apply(c.TLSSubAlternativeName)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TLSSubAlternativeName = tlsSubAlternativeName

	tlsSubAlternativeNameIp, err := policy.TLSSubAlternativeNameIp.Apply(c.TLSSubAlternativeNameIp)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TLSSubAlternativeNameIp = tlsSubAlternativeNameIp

	tlsTokenBindingIsRequired, err := policy.TLSTokenBindingIsRequired.Apply(c.TLSTokenBindingIsRequired)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.TLSTokenBindingIsRequired = tlsTokenBindingIsRequired

	authDetailTypes, err := policy.AuthDetailTypes.Apply(c.AuthDetailTypes)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.AuthDetailTypes = authDetailTypes

	defaultMaxAgeSecs, err := policy.DefaultMaxAgeSecs.Apply(c.DefaultMaxAgeSecs)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.DefaultMaxAgeSecs = defaultMaxAgeSecs

	defaultACRValues, err := policy.DefaultACRValues.Apply(c.DefaultACRValues)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.DefaultACRValues = defaultACRValues

	parIsRequired, err := policy.PARIsRequired.Apply(c.PARIsRequired)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.PARIsRequired = parIsRequired

	cibaTokenDeliveryMode, err := policy.CIBATokenDeliveryMode.Apply(c.CIBATokenDeliveryMode)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.CIBATokenDeliveryMode = cibaTokenDeliveryMode

	cibaNotificationEndpoint, err := policy.CIBANotificationEndpoint.Apply(c.CIBANotificationEndpoint)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.CIBANotificationEndpoint = cibaNotificationEndpoint

	cibaJARSigAlg, err := policy.CIBAJARSigAlg.Apply(c.CIBAJARSigAlg)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.CIBAJARSigAlg = cibaJARSigAlg

	cibaUserCodeIsEnabled, err := policy.CIBAUserCodeIsEnabled.Apply(c.CIBAUserCodeIsEnabled)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.CIBAUserCodeIsEnabled = cibaUserCodeIsEnabled

	signedJWKSURI, err := policy.SignedJWKSURI.Apply(c.SignedJWKSURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.SignedJWKSURI = signedJWKSURI

	organizationName, err := policy.OrganizationName.Apply(c.OrganizationName)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.OrganizationName = organizationName

	clientRegistrationTypes, err := policy.ClientRegistrationTypes.Apply(c.ClientRegistrationTypes)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.ClientRegistrationTypes = clientRegistrationTypes

	postLogoutRedirectURIs, err := policy.PostLogoutRedirectURIs.Apply(c.PostLogoutRedirectURIs)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.PostLogoutRedirectURIs = postLogoutRedirectURIs

	displayName, err := policy.DisplayName.Apply(c.DisplayName)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.DisplayName = displayName

	description, err := policy.Description.Apply(c.Description)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.Description = description

	keywords, err := policy.Keywords.Apply(c.Keywords)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.Keywords = keywords

	informationURI, err := policy.InformationURI.Apply(c.InformationURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.InformationURI = informationURI

	organizationURI, err := policy.OrganizationURI.Apply(c.OrganizationURI)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.OrganizationURI = organizationURI

	credentialOfferEndpoint, err := policy.CredentialOfferEndpoint.Apply(c.CredentialOfferEndpoint)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.CredentialOfferEndpoint = credentialOfferEndpoint

	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	for att, ops := range policy.CustomAttributes {
		attValue, err := ops.Apply(c.CustomAttributes[att])
		if err != nil {
			return goidc.ClientMeta{}, err
		}
		c.CustomAttributes[att] = attValue
	}

	return c, nil
}
