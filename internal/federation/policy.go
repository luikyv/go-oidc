package federation

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type metadataPolicy struct {
	OpenIDProvider *openIDProviderMetadataPolicy `json:"openid_provider,omitempty"`
	OpenIDClient   *openIDClientMetadataPolicy   `json:"openid_relying_party,omitempty"`
}

func (policy metadataPolicy) Validate() error {
	if policy.OpenIDProvider != nil {
		if err := policy.OpenIDProvider.Validate(); err != nil {
			return err
		}
	}

	if policy.OpenIDClient != nil {
		if err := policy.OpenIDClient.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (highPolicy metadataPolicy) Merge(lowPolicy metadataPolicy) (metadataPolicy, error) {
	if lowPolicy.OpenIDProvider != nil {
		var highOpenIDProvider openIDProviderMetadataPolicy
		if highPolicy.OpenIDProvider != nil {
			highOpenIDProvider = *highPolicy.OpenIDProvider
		}

		result, err := highOpenIDProvider.Merge(*lowPolicy.OpenIDProvider)
		if err != nil {
			return metadataPolicy{}, err
		}

		highPolicy.OpenIDProvider = &result
	}

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

func (policy metadataPolicy) Apply(ctx oidc.Context, statement entityStatement) (entityStatement, error) {
	if original, policy := statement.Metadata.OpenIDProvider, policy.OpenIDProvider; original != nil && policy != nil {
		modified, err := policy.Apply(*original)
		if err != nil {
			return entityStatement{}, err
		}
		statement.Metadata.OpenIDProvider = &modified
	}

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
	Name                          metadataOperators[string]                             `json:"client_name"`
	ApplicationType               metadataOperators[goidc.ApplicationType]              `json:"application_type"`
	LogoURI                       metadataOperators[string]                             `json:"logo_uri"`
	Contacts                      metadataOperators[[]string]                           `json:"contacts"`
	PolicyURI                     metadataOperators[string]                             `json:"policy_uri"`
	TermsOfServiceURI             metadataOperators[string]                             `json:"tos_uri"`
	RedirectURIs                  metadataOperators[[]string]                           `json:"redirect_uris"`
	RequestURIs                   metadataOperators[[]string]                           `json:"request_uris"`
	GrantTypes                    metadataOperators[[]goidc.GrantType]                  `json:"grant_types"`
	ResponseTypes                 metadataOperators[[]goidc.ResponseType]               `json:"response_types"`
	JWKSURI                       metadataOperators[string]                             `json:"jwks_uri"`
	JWKS                          metadataOperators[*goidc.JSONWebKeySet]               `json:"jwks"`
	ScopeIDs                      metadataOperators[[]string]                           `json:"scope"`
	SubIdentifierType             metadataOperators[goidc.SubIdentifierType]            `json:"subject_type"`
	SectorIdentifierURI           metadataOperators[string]                             `json:"sector_identifier_uri"`
	IDTokenSigAlg                 metadataOperators[goidc.SignatureAlgorithm]           `json:"id_token_signed_response_alg"`
	IDTokenKeyEncAlg              metadataOperators[goidc.KeyEncryptionAlgorithm]       `json:"id_token_encrypted_response_alg"`
	IDTokenContentEncAlg          metadataOperators[goidc.ContentEncryptionAlgorithm]   `json:"id_token_encrypted_response_enc"`
	UserInfoSigAlg                metadataOperators[goidc.SignatureAlgorithm]           `json:"userinfo_signed_response_alg"`
	UserInfoKeyEncAlg             metadataOperators[goidc.KeyEncryptionAlgorithm]       `json:"userinfo_encrypted_response_alg"`
	UserInfoContentEncAlg         metadataOperators[goidc.ContentEncryptionAlgorithm]   `json:"userinfo_encrypted_response_enc"`
	JARIsRequired                 metadataOperators[bool]                               `json:"require_signed_request_object"`
	JARSigAlg                     metadataOperators[goidc.SignatureAlgorithm]           `json:"request_object_signing_alg"`
	JARKeyEncAlg                  metadataOperators[goidc.KeyEncryptionAlgorithm]       `json:"request_object_encryption_alg"`
	JARContentEncAlg              metadataOperators[goidc.ContentEncryptionAlgorithm]   `json:"request_object_encryption_enc"`
	JARMSigAlg                    metadataOperators[goidc.SignatureAlgorithm]           `json:"authorization_signed_response_alg"`
	JARMKeyEncAlg                 metadataOperators[goidc.KeyEncryptionAlgorithm]       `json:"authorization_encrypted_response_alg"`
	JARMContentEncAlg             metadataOperators[goidc.ContentEncryptionAlgorithm]   `json:"authorization_encrypted_response_enc"`
	TokenAuthnMethod              metadataOperators[goidc.AuthnMethod]                  `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              metadataOperators[goidc.SignatureAlgorithm]           `json:"token_endpoint_auth_signing_alg"`
	TokenIntrospectionAuthnMethod metadataOperators[goidc.AuthnMethod]                  `json:"introspection_endpoint_auth_method"`
	TokenIntrospectionAuthnSigAlg metadataOperators[goidc.SignatureAlgorithm]           `json:"introspection_endpoint_auth_signing_alg"`
	TokenRevocationAuthnMethod    metadataOperators[goidc.AuthnMethod]                  `json:"revocation_endpoint_auth_method"`
	TokenRevocationAuthnSigAlg    metadataOperators[goidc.SignatureAlgorithm]           `json:"revocation_endpoint_auth_signing_alg"`
	DPoPTokenBindingIsRequired    metadataOperators[bool]                               `json:"dpop_bound_access_tokens"`
	TLSSubDistinguishedName       metadataOperators[string]                             `json:"tls_client_auth_subject_dn"`
	TLSSubAlternativeName         metadataOperators[string]                             `json:"tls_client_auth_san_dns"`
	TLSSubAlternativeNameIp       metadataOperators[string]                             `json:"tls_client_auth_san_ip"`
	TLSTokenBindingIsRequired     metadataOperators[bool]                               `json:"tls_client_certificate_bound_access_tokens"`
	AuthDetailTypes               metadataOperators[[]goidc.AuthDetailType]             `json:"authorization_details_types"`
	DefaultMaxAgeSecs             metadataOperators[*int]                               `json:"default_max_age"`
	DefaultACRValues              metadataOperators[string]                             `json:"default_acr_values"`
	PARIsRequired                 metadataOperators[bool]                               `json:"require_pushed_authorization_requests"`
	CIBATokenDeliveryMode         metadataOperators[goidc.CIBATokenDeliveryMode]        `json:"backchannel_token_delivery_mode"`
	CIBANotificationEndpoint      metadataOperators[string]                             `json:"backchannel_client_notification_endpoint"`
	CIBAJARSigAlg                 metadataOperators[goidc.SignatureAlgorithm]           `json:"backchannel_authentication_request_signing_alg"`
	CIBAUserCodeIsEnabled         metadataOperators[bool]                               `json:"backchannel_user_code_parameter"`
	SignedJWKSURI                 metadataOperators[string]                             `json:"signed_jwks_uri"`
	OrganizationName              metadataOperators[string]                             `json:"organization_name"`
	ClientRegistrationTypes       metadataOperators[[]goidc.ClientRegistrationType]     `json:"client_registration_types"`
	PostLogoutRedirectURIs        metadataOperators[[]string]                           `json:"post_logout_redirect_uris"`
	DisplayName                   metadataOperators[string]                             `json:"display_name"`
	Description                   metadataOperators[string]                             `json:"description"`
	Keywords                      metadataOperators[[]string]                           `json:"keywords"`
	InformationURI                metadataOperators[string]                             `json:"information_uri"`
	OrganizationURI               metadataOperators[string]                             `json:"organization_uri"`
	CredentialOfferEndpoint       metadataOperators[string]                             `json:"credential_offer_endpoint"`
	SubIdentifierTypes            metadataOperators[[]goidc.SubIdentifierType]          `json:"subject_types_supported"`
	IDTokenSigAlgs                metadataOperators[[]goidc.SignatureAlgorithm]         `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncAlgs             metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"id_token_encryption_alg_values_supported"`
	IDTokenContentEncAlgs         metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"id_token_encryption_enc_values_supported"`
	UserInfoSigAlgs               metadataOperators[[]goidc.SignatureAlgorithm]         `json:"userinfo_signing_alg_values_supported"`
	UserInfoKeyEncAlgs            metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"userinfo_encryption_alg_values_supported"`
	UserInfoContentEncAlgs        metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"userinfo_encryption_enc_values_supported"`
	JARSigAlgs                    metadataOperators[[]goidc.SignatureAlgorithm]         `json:"request_object_signing_alg_values_supported"`
	JARKeyEncAlgs                 metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"request_object_encryption_alg_values_supported"`
	JARContentEncAlgs             metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"request_object_encryption_enc_values_supported"`
	TokenAuthnMethods             metadataOperators[[]goidc.AuthnMethod]                `json:"token_endpoint_auth_methods_supported"`
	TokenAuthnSigAlgs             metadataOperators[[]goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg_values_supported"`
	CIBAJARSigAlgs                metadataOperators[[]goidc.SignatureAlgorithm]         `json:"backchannel_authentication_request_signing_alg_values_supported"`
	JARMSigAlgs                   metadataOperators[[]goidc.SignatureAlgorithm]         `json:"authorization_signing_alg_values_supported"`
	JARMKeyEncAlgs                metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"authorization_encryption_alg_values_supported"`
	JARMContentEncAlgs            metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"authorization_encryption_enc_values_supported"`
	CustomAttributes              map[string]metadataOperators[any]                     `json:"custom_attributes"`
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

	if err := p.SubIdentifierTypes.Validate(); err != nil {
		return err
	}

	if err := p.IDTokenSigAlgs.Validate(); err != nil {
		return err
	}

	if err := p.IDTokenKeyEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.IDTokenContentEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.UserInfoSigAlgs.Validate(); err != nil {
		return err
	}

	if err := p.UserInfoKeyEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.UserInfoContentEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.JARSigAlgs.Validate(); err != nil {
		return err
	}

	if err := p.JARKeyEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.JARContentEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.TokenAuthnMethods.Validate(); err != nil {
		return err
	}

	if err := p.TokenAuthnSigAlgs.Validate(); err != nil {
		return err
	}

	if err := p.CIBAJARSigAlgs.Validate(); err != nil {
		return err
	}

	if err := p.JARMSigAlgs.Validate(); err != nil {
		return err
	}

	if err := p.JARMKeyEncAlgs.Validate(); err != nil {
		return err
	}

	if err := p.JARMContentEncAlgs.Validate(); err != nil {
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

	opSubIdentifierTypes, err := high.SubIdentifierTypes.Merge(low.SubIdentifierTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.SubIdentifierTypes = opSubIdentifierTypes

	opIDTokenSigAlgs, err := high.IDTokenSigAlgs.Merge(low.IDTokenSigAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenSigAlgs = opIDTokenSigAlgs

	opIDTokenKeyEncAlgs, err := high.IDTokenKeyEncAlgs.Merge(low.IDTokenKeyEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenKeyEncAlgs = opIDTokenKeyEncAlgs

	opIDTokenContentEncAlgs, err := high.IDTokenContentEncAlgs.Merge(low.IDTokenContentEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenContentEncAlgs = opIDTokenContentEncAlgs

	opUserInfoSigAlgs, err := high.UserInfoSigAlgs.Merge(low.UserInfoSigAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoSigAlgs = opUserInfoSigAlgs

	opUserInfoKeyEncAlgs, err := high.UserInfoKeyEncAlgs.Merge(low.UserInfoKeyEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoKeyEncAlgs = opUserInfoKeyEncAlgs

	opUserInfoContentEncAlgs, err := high.UserInfoContentEncAlgs.Merge(low.UserInfoContentEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoContentEncAlgs = opUserInfoContentEncAlgs

	opJARSigAlgs, err := high.JARSigAlgs.Merge(low.JARSigAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARSigAlgs = opJARSigAlgs

	opJARKeyEncAlgs, err := high.JARKeyEncAlgs.Merge(low.JARKeyEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARKeyEncAlgs = opJARKeyEncAlgs

	opJARContentEncAlgs, err := high.JARContentEncAlgs.Merge(low.JARContentEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARContentEncAlgs = opJARContentEncAlgs

	opTokenAuthnMethods, err := high.TokenAuthnMethods.Merge(low.TokenAuthnMethods)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenAuthnMethods = opTokenAuthnMethods

	opTokenAuthnSigAlgs, err := high.TokenAuthnSigAlgs.Merge(low.TokenAuthnSigAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenAuthnSigAlgs = opTokenAuthnSigAlgs

	opCIBAJARSigAlgs, err := high.CIBAJARSigAlgs.Merge(low.CIBAJARSigAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBAJARSigAlgs = opCIBAJARSigAlgs

	opJARMSigAlgs, err := high.JARMSigAlgs.Merge(low.JARMSigAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMSigAlgs = opJARMSigAlgs

	opJARMKeyEncAlgs, err := high.JARMKeyEncAlgs.Merge(low.JARMKeyEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMKeyEncAlgs = opJARMKeyEncAlgs

	opJARMContentEncAlgs, err := high.JARMContentEncAlgs.Merge(low.JARMContentEncAlgs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMContentEncAlgs = opJARMContentEncAlgs

	for att, lowOps := range low.CustomAttributes {
		ops, err := high.customAttribute(att).Merge(lowOps)
		if err != nil {
			return openIDClientMetadataPolicy{}, err
		}
		high.setCustomAttribute(att, ops)
	}

	return high, nil
}

func (policy openIDClientMetadataPolicy) Apply(c client.Meta) (client.Meta, error) {
	var err error

	if c.Name, err = policy.Name.Apply(c.Name); err != nil {
		return client.Meta{}, err
	}

	if c.ApplicationType, err = policy.ApplicationType.Apply(c.ApplicationType); err != nil {
		return client.Meta{}, err
	}

	if c.LogoURI, err = policy.LogoURI.Apply(c.LogoURI); err != nil {
		return client.Meta{}, err
	}

	if c.Contacts, err = policy.Contacts.Apply(c.Contacts); err != nil {
		return client.Meta{}, err
	}

	if c.PolicyURI, err = policy.PolicyURI.Apply(c.PolicyURI); err != nil {
		return client.Meta{}, err
	}

	if c.TermsOfServiceURI, err = policy.TermsOfServiceURI.Apply(c.TermsOfServiceURI); err != nil {
		return client.Meta{}, err
	}

	if c.RedirectURIs, err = policy.RedirectURIs.Apply(c.RedirectURIs); err != nil {
		return client.Meta{}, err
	}

	if c.RequestURIs, err = policy.RequestURIs.Apply(c.RequestURIs); err != nil {
		return client.Meta{}, err
	}

	if c.GrantTypes, err = policy.GrantTypes.Apply(c.GrantTypes); err != nil {
		return client.Meta{}, err
	}

	if c.ResponseTypes, err = policy.ResponseTypes.Apply(c.ResponseTypes); err != nil {
		return client.Meta{}, err
	}

	if c.JWKSURI, err = policy.JWKSURI.Apply(c.JWKSURI); err != nil {
		return client.Meta{}, err
	}

	if c.JWKS, err = policy.JWKS.Apply(c.JWKS); err != nil {
		return client.Meta{}, err
	}

	scopeIDs := strings.Fields(c.ScopeIDs)
	if scopeIDs, err = policy.ScopeIDs.Apply(scopeIDs); err != nil {
		return client.Meta{}, err
	}
	c.ScopeIDs = strings.Join(scopeIDs, " ")

	if c.SubIdentifierType, err = policy.SubIdentifierType.Apply(c.SubIdentifierType); err != nil {
		return client.Meta{}, err
	}

	if c.SectorIdentifierURI, err = policy.SectorIdentifierURI.Apply(c.SectorIdentifierURI); err != nil {
		return client.Meta{}, err
	}

	if c.IDTokenSigAlg, err = policy.IDTokenSigAlg.Apply(c.IDTokenSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.IDTokenKeyEncAlg, err = policy.IDTokenKeyEncAlg.Apply(c.IDTokenKeyEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.IDTokenContentEncAlg, err = policy.IDTokenContentEncAlg.Apply(c.IDTokenContentEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.UserInfoSigAlg, err = policy.UserInfoSigAlg.Apply(c.UserInfoSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.UserInfoKeyEncAlg, err = policy.UserInfoKeyEncAlg.Apply(c.UserInfoKeyEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.UserInfoContentEncAlg, err = policy.UserInfoContentEncAlg.Apply(c.UserInfoContentEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.JARIsRequired, err = policy.JARIsRequired.Apply(c.JARIsRequired); err != nil {
		return client.Meta{}, err
	}

	if c.JARSigAlg, err = policy.JARSigAlg.Apply(c.JARSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.JARKeyEncAlg, err = policy.JARKeyEncAlg.Apply(c.JARKeyEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.JARContentEncAlg, err = policy.JARContentEncAlg.Apply(c.JARContentEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.JARMSigAlg, err = policy.JARMSigAlg.Apply(c.JARMSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.JARMKeyEncAlg, err = policy.JARMKeyEncAlg.Apply(c.JARMKeyEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.JARMContentEncAlg, err = policy.JARMContentEncAlg.Apply(c.JARMContentEncAlg); err != nil {
		return client.Meta{}, err
	}

	if c.TokenAuthnMethod, err = policy.TokenAuthnMethod.Apply(c.TokenAuthnMethod); err != nil {
		return client.Meta{}, err
	}

	if c.TokenAuthnSigAlg, err = policy.TokenAuthnSigAlg.Apply(c.TokenAuthnSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.TokenIntrospectionAuthnMethod, err = policy.TokenIntrospectionAuthnMethod.Apply(c.TokenIntrospectionAuthnMethod); err != nil {
		return client.Meta{}, err
	}

	if c.TokenIntrospectionAuthnSigAlg, err = policy.TokenIntrospectionAuthnSigAlg.Apply(c.TokenIntrospectionAuthnSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.TokenRevocationAuthnMethod, err = policy.TokenRevocationAuthnMethod.Apply(c.TokenRevocationAuthnMethod); err != nil {
		return client.Meta{}, err
	}

	if c.TokenRevocationAuthnSigAlg, err = policy.TokenRevocationAuthnSigAlg.Apply(c.TokenRevocationAuthnSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.DPoPTokenBindingIsRequired, err = policy.DPoPTokenBindingIsRequired.Apply(c.DPoPTokenBindingIsRequired); err != nil {
		return client.Meta{}, err
	}

	if c.TLSSubjectDistinguishedName, err = policy.TLSSubDistinguishedName.Apply(c.TLSSubjectDistinguishedName); err != nil {
		return client.Meta{}, err
	}

	if c.TLSSubjectAlternativeName, err = policy.TLSSubAlternativeName.Apply(c.TLSSubjectAlternativeName); err != nil {
		return client.Meta{}, err
	}

	if c.TLSSubjectAlternativeNameIP, err = policy.TLSSubAlternativeNameIp.Apply(c.TLSSubjectAlternativeNameIP); err != nil {
		return client.Meta{}, err
	}

	if c.TLSTokenBindingIsRequired, err = policy.TLSTokenBindingIsRequired.Apply(c.TLSTokenBindingIsRequired); err != nil {
		return client.Meta{}, err
	}

	if c.AuthDetailTypes, err = policy.AuthDetailTypes.Apply(c.AuthDetailTypes); err != nil {
		return client.Meta{}, err
	}

	if c.DefaultMaxAgeSecs, err = policy.DefaultMaxAgeSecs.Apply(c.DefaultMaxAgeSecs); err != nil {
		return client.Meta{}, err
	}

	if c.DefaultACRValues, err = policy.DefaultACRValues.Apply(c.DefaultACRValues); err != nil {
		return client.Meta{}, err
	}

	if c.PARIsRequired, err = policy.PARIsRequired.Apply(c.PARIsRequired); err != nil {
		return client.Meta{}, err
	}

	if c.CIBATokenDeliveryMode, err = policy.CIBATokenDeliveryMode.Apply(c.CIBATokenDeliveryMode); err != nil {
		return client.Meta{}, err
	}

	if c.CIBANotificationEndpoint, err = policy.CIBANotificationEndpoint.Apply(c.CIBANotificationEndpoint); err != nil {
		return client.Meta{}, err
	}

	if c.CIBAJARSigAlg, err = policy.CIBAJARSigAlg.Apply(c.CIBAJARSigAlg); err != nil {
		return client.Meta{}, err
	}

	if c.CIBAUserCodeIsEnabled, err = policy.CIBAUserCodeIsEnabled.Apply(c.CIBAUserCodeIsEnabled); err != nil {
		return client.Meta{}, err
	}

	if c.SignedJWKSURI, err = policy.SignedJWKSURI.Apply(c.SignedJWKSURI); err != nil {
		return client.Meta{}, err
	}

	if c.OrganizationName, err = policy.OrganizationName.Apply(c.OrganizationName); err != nil {
		return client.Meta{}, err
	}

	if c.ClientRegistrationTypes, err = policy.ClientRegistrationTypes.Apply(c.ClientRegistrationTypes); err != nil {
		return client.Meta{}, err
	}

	if c.PostLogoutRedirectURIs, err = policy.PostLogoutRedirectURIs.Apply(c.PostLogoutRedirectURIs); err != nil {
		return client.Meta{}, err
	}

	if c.DisplayName, err = policy.DisplayName.Apply(c.DisplayName); err != nil {
		return client.Meta{}, err
	}

	if c.Description, err = policy.Description.Apply(c.Description); err != nil {
		return client.Meta{}, err
	}

	if c.Keywords, err = policy.Keywords.Apply(c.Keywords); err != nil {
		return client.Meta{}, err
	}

	if c.InformationURI, err = policy.InformationURI.Apply(c.InformationURI); err != nil {
		return client.Meta{}, err
	}

	if c.OrganizationURI, err = policy.OrganizationURI.Apply(c.OrganizationURI); err != nil {
		return client.Meta{}, err
	}

	if c.CredentialOfferEndpoint, err = policy.CredentialOfferEndpoint.Apply(c.CredentialOfferEndpoint); err != nil {
		return client.Meta{}, err
	}

	if c.SubIdentifierTypes, err = policy.SubIdentifierTypes.Apply(c.SubIdentifierTypes); err != nil {
		return client.Meta{}, err
	}

	if c.IDTokenSigAlgs, err = policy.IDTokenSigAlgs.Apply(c.IDTokenSigAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.IDTokenKeyEncAlgs, err = policy.IDTokenKeyEncAlgs.Apply(c.IDTokenKeyEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.IDTokenContentEncAlgs, err = policy.IDTokenContentEncAlgs.Apply(c.IDTokenContentEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.UserInfoSigAlgs, err = policy.UserInfoSigAlgs.Apply(c.UserInfoSigAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.UserInfoKeyEncAlgs, err = policy.UserInfoKeyEncAlgs.Apply(c.UserInfoKeyEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.UserInfoContentEncAlgs, err = policy.UserInfoContentEncAlgs.Apply(c.UserInfoContentEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.JARSigAlgs, err = policy.JARSigAlgs.Apply(c.JARSigAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.JARKeyEncAlgs, err = policy.JARKeyEncAlgs.Apply(c.JARKeyEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.JARContentEncAlgs, err = policy.JARContentEncAlgs.Apply(c.JARContentEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.TokenAuthnMethods, err = policy.TokenAuthnMethods.Apply(c.TokenAuthnMethods); err != nil {
		return client.Meta{}, err
	}

	if c.TokenAuthnSigAlgs, err = policy.TokenAuthnSigAlgs.Apply(c.TokenAuthnSigAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.CIBAJARSigAlgs, err = policy.CIBAJARSigAlgs.Apply(c.CIBAJARSigAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.JARMSigAlgs, err = policy.JARMSigAlgs.Apply(c.JARMSigAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.JARMKeyEncAlgs, err = policy.JARMKeyEncAlgs.Apply(c.JARMKeyEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.JARMContentEncAlgs, err = policy.JARMContentEncAlgs.Apply(c.JARMContentEncAlgs); err != nil {
		return client.Meta{}, err
	}

	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	for att, ops := range policy.CustomAttributes {
		if c.CustomAttributes[att], err = ops.Apply(c.CustomAttributes[att]); err != nil {
			return client.Meta{}, err
		}
	}

	return c, nil
}

type openIDProviderMetadataPolicy struct {
	Issuer                              metadataOperators[string]                             `json:"issuer"`
	ClientRegistrationEndpoint          metadataOperators[string]                             `json:"registration_endpoint"`
	AuthorizationEndpoint               metadataOperators[string]                             `json:"authorization_endpoint"`
	TokenEndpoint                       metadataOperators[string]                             `json:"token_endpoint"`
	UserInfoEndpoint                    metadataOperators[string]                             `json:"userinfo_endpoint"`
	JWKSEndpoint                        metadataOperators[string]                             `json:"jwks_uri"`
	PAREndpoint                         metadataOperators[string]                             `json:"pushed_authorization_request_endpoint"`
	PARIsRequired                       metadataOperators[bool]                               `json:"require_pushed_authorization_requests"`
	ResponseTypes                       metadataOperators[[]goidc.ResponseType]               `json:"response_types_supported"`
	ResponseModes                       metadataOperators[[]goidc.ResponseMode]               `json:"response_modes_supported"`
	GrantTypes                          metadataOperators[[]goidc.GrantType]                  `json:"grant_types_supported"`
	Scopes                              metadataOperators[[]string]                           `json:"scopes_supported"`
	UserClaimsSupported                 metadataOperators[[]string]                           `json:"claims_supported"`
	ClaimTypesSupported                 metadataOperators[[]goidc.ClaimType]                  `json:"claim_types_supported"`
	SubIdentifierTypes                  metadataOperators[[]goidc.SubIdentifierType]          `json:"subject_types_supported"`
	IDTokenSigAlgs                      metadataOperators[[]goidc.SignatureAlgorithm]         `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncAlgs                   metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"id_token_encryption_alg_values_supported"`
	IDTokenContentEncAlgs               metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"id_token_encryption_enc_values_supported"`
	UserInfoKeyEncAlgs                  metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"userinfo_encryption_alg_values_supported"`
	UserInfoContentEncAlgs              metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"userinfo_encryption_enc_values_supported"`
	UserInfoSigAlgs                     metadataOperators[[]goidc.SignatureAlgorithm]         `json:"userinfo_signing_alg_values_supported"`
	TokenAuthnMethods                   metadataOperators[[]goidc.AuthnMethod]                `json:"token_endpoint_auth_methods_supported"`
	TokenAuthnSigAlgs                   metadataOperators[[]goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg_values_supported"`
	JARIsEnabled                        metadataOperators[bool]                               `json:"request_parameter_supported"`
	JARIsRequired                       metadataOperators[bool]                               `json:"require_signed_request_object"`
	JARAlgs                             metadataOperators[[]goidc.SignatureAlgorithm]         `json:"request_object_signing_alg_values_supported"`
	JARKeyEncAlgs                       metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"request_object_encryption_alg_values_supported"`
	JARContentEncAlgs                   metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"request_object_encryption_enc_values_supported"`
	JARByReferenceIsEnabled             metadataOperators[bool]                               `json:"request_uri_parameter_supported"`
	JARRequestURIRegistrationIsRequired metadataOperators[bool]                               `json:"require_request_uri_registration"`
	JARMAlgs                            metadataOperators[[]goidc.SignatureAlgorithm]         `json:"authorization_signing_alg_values_supported"`
	JARMKeyEncAlgs                      metadataOperators[[]goidc.KeyEncryptionAlgorithm]     `json:"authorization_encryption_alg_values_supported"`
	JARMContentEncAlgs                  metadataOperators[[]goidc.ContentEncryptionAlgorithm] `json:"authorization_encryption_enc_values_supported"`
	IssuerResponseParamIsEnabled        metadataOperators[bool]                               `json:"authorization_response_iss_parameter_supported"`
	ClaimsParamIsEnabled                metadataOperators[bool]                               `json:"claims_parameter_supported"`
	AuthDetailsIsEnabled                metadataOperators[bool]                               `json:"authorization_details_supported"`
	AuthDetailTypesSupported            metadataOperators[[]goidc.AuthDetailType]             `json:"authorization_details_types_supported"`
	DPoPSigAlgs                         metadataOperators[[]goidc.SignatureAlgorithm]         `json:"dpop_signing_alg_values_supported"`
	TokenIntrospectionEndpoint          metadataOperators[string]                             `json:"introspection_endpoint"`
	TokenIntrospectionAuthnMethods      metadataOperators[[]goidc.AuthnMethod]                `json:"introspection_endpoint_auth_methods_supported"`
	TokenIntrospectionAuthnSigAlgs      metadataOperators[[]goidc.SignatureAlgorithm]         `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	TokenRevocationEndpoint             metadataOperators[string]                             `json:"revocation_endpoint"`
	TokenRevocationAuthnMethods         metadataOperators[[]goidc.AuthnMethod]                `json:"revocation_endpoint_auth_methods_supported"`
	TokenRevocationAuthnSigAlgs         metadataOperators[[]goidc.SignatureAlgorithm]         `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	DeviceAuthorizationEndpoint         metadataOperators[string]                             `json:"device_authorization_endpoint"`
	CIBATokenDeliveryModes              metadataOperators[[]goidc.CIBATokenDeliveryMode]      `json:"backchannel_token_delivery_modes_supported"`
	CIBAEndpoint                        metadataOperators[string]                             `json:"backchannel_authentication_endpoint"`
	CIBAJARSigAlgs                      metadataOperators[[]goidc.SignatureAlgorithm]         `json:"backchannel_authentication_request_signing_alg_values_supported"`
	CIBAUserCodeIsEnabled               metadataOperators[bool]                               `json:"backchannel_user_code_parameter_supported"`
	TLSBoundTokensIsEnabled             metadataOperators[bool]                               `json:"tls_client_certificate_bound_access_tokens"`
	ACRs                                metadataOperators[[]goidc.ACR]                        `json:"acr_values_supported"`
	DisplayValues                       metadataOperators[[]goidc.DisplayValue]               `json:"display_values_supported"`
	CodeChallengeMethods                metadataOperators[[]goidc.CodeChallengeMethod]        `json:"code_challenge_methods_supported"`
	EndSessionEndpoint                  metadataOperators[string]                             `json:"end_session_endpoint"`
	ClientRegistrationTypes             metadataOperators[[]goidc.ClientRegistrationType]     `json:"client_registration_types_supported"`
	OrganizationName                    metadataOperators[string]                             `json:"organization_name"`
	FederationRegistrationEndpoint      metadataOperators[string]                             `json:"federation_registration_endpoint"`
	SignedJWKSEndpoint                  metadataOperators[string]                             `json:"signed_jwks_uri"`
	PreAuthCodeAnonymousAccess          metadataOperators[bool]                               `json:"pre-authorized_grant_anonymous_access_supported"`
}

func (p openIDProviderMetadataPolicy) Validate() error {
	validators := []func() error{
		p.Issuer.Validate,
		p.ClientRegistrationEndpoint.Validate,
		p.AuthorizationEndpoint.Validate,
		p.TokenEndpoint.Validate,
		p.UserInfoEndpoint.Validate,
		p.JWKSEndpoint.Validate,
		p.PAREndpoint.Validate,
		p.PARIsRequired.Validate,
		p.ResponseTypes.Validate,
		p.ResponseModes.Validate,
		p.GrantTypes.Validate,
		p.Scopes.Validate,
		p.UserClaimsSupported.Validate,
		p.ClaimTypesSupported.Validate,
		p.SubIdentifierTypes.Validate,
		p.IDTokenSigAlgs.Validate,
		p.IDTokenKeyEncAlgs.Validate,
		p.IDTokenContentEncAlgs.Validate,
		p.UserInfoKeyEncAlgs.Validate,
		p.UserInfoContentEncAlgs.Validate,
		p.UserInfoSigAlgs.Validate,
		p.TokenAuthnMethods.Validate,
		p.TokenAuthnSigAlgs.Validate,
		p.JARIsEnabled.Validate,
		p.JARIsRequired.Validate,
		p.JARAlgs.Validate,
		p.JARKeyEncAlgs.Validate,
		p.JARContentEncAlgs.Validate,
		p.JARByReferenceIsEnabled.Validate,
		p.JARRequestURIRegistrationIsRequired.Validate,
		p.JARMAlgs.Validate,
		p.JARMKeyEncAlgs.Validate,
		p.JARMContentEncAlgs.Validate,
		p.IssuerResponseParamIsEnabled.Validate,
		p.ClaimsParamIsEnabled.Validate,
		p.AuthDetailsIsEnabled.Validate,
		p.AuthDetailTypesSupported.Validate,
		p.DPoPSigAlgs.Validate,
		p.TokenIntrospectionEndpoint.Validate,
		p.TokenIntrospectionAuthnMethods.Validate,
		p.TokenIntrospectionAuthnSigAlgs.Validate,
		p.TokenRevocationEndpoint.Validate,
		p.TokenRevocationAuthnMethods.Validate,
		p.TokenRevocationAuthnSigAlgs.Validate,
		p.DeviceAuthorizationEndpoint.Validate,
		p.CIBATokenDeliveryModes.Validate,
		p.CIBAEndpoint.Validate,
		p.CIBAJARSigAlgs.Validate,
		p.CIBAUserCodeIsEnabled.Validate,
		p.TLSBoundTokensIsEnabled.Validate,
		p.ACRs.Validate,
		p.DisplayValues.Validate,
		p.CodeChallengeMethods.Validate,
		p.EndSessionEndpoint.Validate,
		p.ClientRegistrationTypes.Validate,
		p.OrganizationName.Validate,
		p.FederationRegistrationEndpoint.Validate,
		p.SignedJWKSEndpoint.Validate,
		p.PreAuthCodeAnonymousAccess.Validate,
	}

	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}

	return nil
}

func (high openIDProviderMetadataPolicy) Merge(low openIDProviderMetadataPolicy) (openIDProviderMetadataPolicy, error) {
	var err error

	if high.Issuer, err = high.Issuer.Merge(low.Issuer); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ClientRegistrationEndpoint, err = high.ClientRegistrationEndpoint.Merge(low.ClientRegistrationEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.AuthorizationEndpoint, err = high.AuthorizationEndpoint.Merge(low.AuthorizationEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenEndpoint, err = high.TokenEndpoint.Merge(low.TokenEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.UserInfoEndpoint, err = high.UserInfoEndpoint.Merge(low.UserInfoEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JWKSEndpoint, err = high.JWKSEndpoint.Merge(low.JWKSEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.PAREndpoint, err = high.PAREndpoint.Merge(low.PAREndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.PARIsRequired, err = high.PARIsRequired.Merge(low.PARIsRequired); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ResponseTypes, err = high.ResponseTypes.Merge(low.ResponseTypes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ResponseModes, err = high.ResponseModes.Merge(low.ResponseModes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.GrantTypes, err = high.GrantTypes.Merge(low.GrantTypes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.Scopes, err = high.Scopes.Merge(low.Scopes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.UserClaimsSupported, err = high.UserClaimsSupported.Merge(low.UserClaimsSupported); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ClaimTypesSupported, err = high.ClaimTypesSupported.Merge(low.ClaimTypesSupported); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.SubIdentifierTypes, err = high.SubIdentifierTypes.Merge(low.SubIdentifierTypes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.IDTokenSigAlgs, err = high.IDTokenSigAlgs.Merge(low.IDTokenSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.IDTokenKeyEncAlgs, err = high.IDTokenKeyEncAlgs.Merge(low.IDTokenKeyEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.IDTokenContentEncAlgs, err = high.IDTokenContentEncAlgs.Merge(low.IDTokenContentEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.UserInfoKeyEncAlgs, err = high.UserInfoKeyEncAlgs.Merge(low.UserInfoKeyEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.UserInfoContentEncAlgs, err = high.UserInfoContentEncAlgs.Merge(low.UserInfoContentEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.UserInfoSigAlgs, err = high.UserInfoSigAlgs.Merge(low.UserInfoSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenAuthnMethods, err = high.TokenAuthnMethods.Merge(low.TokenAuthnMethods); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenAuthnSigAlgs, err = high.TokenAuthnSigAlgs.Merge(low.TokenAuthnSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARIsEnabled, err = high.JARIsEnabled.Merge(low.JARIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARIsRequired, err = high.JARIsRequired.Merge(low.JARIsRequired); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARAlgs, err = high.JARAlgs.Merge(low.JARAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARKeyEncAlgs, err = high.JARKeyEncAlgs.Merge(low.JARKeyEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARContentEncAlgs, err = high.JARContentEncAlgs.Merge(low.JARContentEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARByReferenceIsEnabled, err = high.JARByReferenceIsEnabled.Merge(low.JARByReferenceIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARRequestURIRegistrationIsRequired, err = high.JARRequestURIRegistrationIsRequired.Merge(low.JARRequestURIRegistrationIsRequired); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARMAlgs, err = high.JARMAlgs.Merge(low.JARMAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARMKeyEncAlgs, err = high.JARMKeyEncAlgs.Merge(low.JARMKeyEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.JARMContentEncAlgs, err = high.JARMContentEncAlgs.Merge(low.JARMContentEncAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.IssuerResponseParamIsEnabled, err = high.IssuerResponseParamIsEnabled.Merge(low.IssuerResponseParamIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ClaimsParamIsEnabled, err = high.ClaimsParamIsEnabled.Merge(low.ClaimsParamIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.AuthDetailsIsEnabled, err = high.AuthDetailsIsEnabled.Merge(low.AuthDetailsIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.AuthDetailTypesSupported, err = high.AuthDetailTypesSupported.Merge(low.AuthDetailTypesSupported); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.DPoPSigAlgs, err = high.DPoPSigAlgs.Merge(low.DPoPSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenIntrospectionEndpoint, err = high.TokenIntrospectionEndpoint.Merge(low.TokenIntrospectionEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenIntrospectionAuthnMethods, err = high.TokenIntrospectionAuthnMethods.Merge(low.TokenIntrospectionAuthnMethods); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenIntrospectionAuthnSigAlgs, err = high.TokenIntrospectionAuthnSigAlgs.Merge(low.TokenIntrospectionAuthnSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenRevocationEndpoint, err = high.TokenRevocationEndpoint.Merge(low.TokenRevocationEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenRevocationAuthnMethods, err = high.TokenRevocationAuthnMethods.Merge(low.TokenRevocationAuthnMethods); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TokenRevocationAuthnSigAlgs, err = high.TokenRevocationAuthnSigAlgs.Merge(low.TokenRevocationAuthnSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.DeviceAuthorizationEndpoint, err = high.DeviceAuthorizationEndpoint.Merge(low.DeviceAuthorizationEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.CIBATokenDeliveryModes, err = high.CIBATokenDeliveryModes.Merge(low.CIBATokenDeliveryModes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.CIBAEndpoint, err = high.CIBAEndpoint.Merge(low.CIBAEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.CIBAJARSigAlgs, err = high.CIBAJARSigAlgs.Merge(low.CIBAJARSigAlgs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.CIBAUserCodeIsEnabled, err = high.CIBAUserCodeIsEnabled.Merge(low.CIBAUserCodeIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.TLSBoundTokensIsEnabled, err = high.TLSBoundTokensIsEnabled.Merge(low.TLSBoundTokensIsEnabled); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ACRs, err = high.ACRs.Merge(low.ACRs); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.DisplayValues, err = high.DisplayValues.Merge(low.DisplayValues); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.CodeChallengeMethods, err = high.CodeChallengeMethods.Merge(low.CodeChallengeMethods); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.EndSessionEndpoint, err = high.EndSessionEndpoint.Merge(low.EndSessionEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.ClientRegistrationTypes, err = high.ClientRegistrationTypes.Merge(low.ClientRegistrationTypes); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.OrganizationName, err = high.OrganizationName.Merge(low.OrganizationName); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.FederationRegistrationEndpoint, err = high.FederationRegistrationEndpoint.Merge(low.FederationRegistrationEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.SignedJWKSEndpoint, err = high.SignedJWKSEndpoint.Merge(low.SignedJWKSEndpoint); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	if high.PreAuthCodeAnonymousAccess, err = high.PreAuthCodeAnonymousAccess.Merge(low.PreAuthCodeAnonymousAccess); err != nil {
		return openIDProviderMetadataPolicy{}, err
	}

	return high, nil
}

func (p openIDProviderMetadataPolicy) Apply(c goidc.Configuration) (goidc.Configuration, error) {
	var err error

	if c.Issuer, err = p.Issuer.Apply(c.Issuer); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ClientRegistrationEndpoint, err = p.ClientRegistrationEndpoint.Apply(c.ClientRegistrationEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.AuthorizationEndpoint, err = p.AuthorizationEndpoint.Apply(c.AuthorizationEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenEndpoint, err = p.TokenEndpoint.Apply(c.TokenEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.UserInfoEndpoint, err = p.UserInfoEndpoint.Apply(c.UserInfoEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JWKSEndpoint, err = p.JWKSEndpoint.Apply(c.JWKSEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.PAREndpoint, err = p.PAREndpoint.Apply(c.PAREndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.PARIsRequired, err = p.PARIsRequired.Apply(c.PARIsRequired); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ResponseTypes, err = p.ResponseTypes.Apply(c.ResponseTypes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ResponseModes, err = p.ResponseModes.Apply(c.ResponseModes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.GrantTypes, err = p.GrantTypes.Apply(c.GrantTypes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.Scopes, err = p.Scopes.Apply(c.Scopes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.UserClaimsSupported, err = p.UserClaimsSupported.Apply(c.UserClaimsSupported); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ClaimTypesSupported, err = p.ClaimTypesSupported.Apply(c.ClaimTypesSupported); err != nil {
		return goidc.Configuration{}, err
	}

	if c.SubIdentifierTypes, err = p.SubIdentifierTypes.Apply(c.SubIdentifierTypes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.IDTokenSigAlgs, err = p.IDTokenSigAlgs.Apply(c.IDTokenSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.IDTokenKeyEncAlgs, err = p.IDTokenKeyEncAlgs.Apply(c.IDTokenKeyEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.IDTokenContentEncAlgs, err = p.IDTokenContentEncAlgs.Apply(c.IDTokenContentEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.UserInfoKeyEncAlgs, err = p.UserInfoKeyEncAlgs.Apply(c.UserInfoKeyEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.UserInfoContentEncAlgs, err = p.UserInfoContentEncAlgs.Apply(c.UserInfoContentEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.UserInfoSigAlgs, err = p.UserInfoSigAlgs.Apply(c.UserInfoSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenAuthnMethods, err = p.TokenAuthnMethods.Apply(c.TokenAuthnMethods); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenAuthnSigAlgs, err = p.TokenAuthnSigAlgs.Apply(c.TokenAuthnSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARIsEnabled, err = p.JARIsEnabled.Apply(c.JARIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARIsRequired, err = p.JARIsRequired.Apply(c.JARIsRequired); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARAlgs, err = p.JARAlgs.Apply(c.JARAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARKeyEncAlgs, err = p.JARKeyEncAlgs.Apply(c.JARKeyEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARContentEncAlgs, err = p.JARContentEncAlgs.Apply(c.JARContentEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARByReferenceIsEnabled, err = p.JARByReferenceIsEnabled.Apply(c.JARByReferenceIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARRequestURIRegistrationIsRequired, err = p.JARRequestURIRegistrationIsRequired.Apply(c.JARRequestURIRegistrationIsRequired); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARMAlgs, err = p.JARMAlgs.Apply(c.JARMAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARMKeyEncAlgs, err = p.JARMKeyEncAlgs.Apply(c.JARMKeyEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.JARMContentEncAlgs, err = p.JARMContentEncAlgs.Apply(c.JARMContentEncAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.IssuerResponseParamIsEnabled, err = p.IssuerResponseParamIsEnabled.Apply(c.IssuerResponseParamIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ClaimsParamIsEnabled, err = p.ClaimsParamIsEnabled.Apply(c.ClaimsParamIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.AuthDetailsIsEnabled, err = p.AuthDetailsIsEnabled.Apply(c.AuthDetailsIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.AuthDetailTypesSupported, err = p.AuthDetailTypesSupported.Apply(c.AuthDetailTypesSupported); err != nil {
		return goidc.Configuration{}, err
	}

	if c.DPoPSigAlgs, err = p.DPoPSigAlgs.Apply(c.DPoPSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenIntrospectionEndpoint, err = p.TokenIntrospectionEndpoint.Apply(c.TokenIntrospectionEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenIntrospectionAuthnMethods, err = p.TokenIntrospectionAuthnMethods.Apply(c.TokenIntrospectionAuthnMethods); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenIntrospectionAuthnSigAlgs, err = p.TokenIntrospectionAuthnSigAlgs.Apply(c.TokenIntrospectionAuthnSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenRevocationEndpoint, err = p.TokenRevocationEndpoint.Apply(c.TokenRevocationEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenRevocationAuthnMethods, err = p.TokenRevocationAuthnMethods.Apply(c.TokenRevocationAuthnMethods); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TokenRevocationAuthnSigAlgs, err = p.TokenRevocationAuthnSigAlgs.Apply(c.TokenRevocationAuthnSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.DeviceAuthorizationEndpoint, err = p.DeviceAuthorizationEndpoint.Apply(c.DeviceAuthorizationEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.CIBATokenDeliveryModes, err = p.CIBATokenDeliveryModes.Apply(c.CIBATokenDeliveryModes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.CIBAEndpoint, err = p.CIBAEndpoint.Apply(c.CIBAEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.CIBAJARSigAlgs, err = p.CIBAJARSigAlgs.Apply(c.CIBAJARSigAlgs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.CIBAUserCodeIsEnabled, err = p.CIBAUserCodeIsEnabled.Apply(c.CIBAUserCodeIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.TLSBoundTokensIsEnabled, err = p.TLSBoundTokensIsEnabled.Apply(c.TLSBoundTokensIsEnabled); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ACRs, err = p.ACRs.Apply(c.ACRs); err != nil {
		return goidc.Configuration{}, err
	}

	if c.DisplayValues, err = p.DisplayValues.Apply(c.DisplayValues); err != nil {
		return goidc.Configuration{}, err
	}

	if c.CodeChallengeMethods, err = p.CodeChallengeMethods.Apply(c.CodeChallengeMethods); err != nil {
		return goidc.Configuration{}, err
	}

	if c.EndSessionEndpoint, err = p.EndSessionEndpoint.Apply(c.EndSessionEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.ClientRegistrationTypes, err = p.ClientRegistrationTypes.Apply(c.ClientRegistrationTypes); err != nil {
		return goidc.Configuration{}, err
	}

	if c.OrganizationName, err = p.OrganizationName.Apply(c.OrganizationName); err != nil {
		return goidc.Configuration{}, err
	}

	if c.FederationRegistrationEndpoint, err = p.FederationRegistrationEndpoint.Apply(c.FederationRegistrationEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.SignedJWKSEndpoint, err = p.SignedJWKSEndpoint.Apply(c.SignedJWKSEndpoint); err != nil {
		return goidc.Configuration{}, err
	}

	if c.PreAuthCodeAnonymousAccess, err = p.PreAuthCodeAnonymousAccess.Apply(c.PreAuthCodeAnonymousAccess); err != nil {
		return goidc.Configuration{}, err
	}

	return c, nil
}
