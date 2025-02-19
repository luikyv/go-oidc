package federation

import (
	"strings"

	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type metadataPolicy struct {
	OpenIDClient *openIDClientMetadataPolicy `json:"openid_relying_party,omitempty"`
}

func (policy metadataPolicy) validate() error {
	if policy.OpenIDClient != nil {
		if err := policy.OpenIDClient.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (highPolicy metadataPolicy) merge(lowPolicy metadataPolicy) (metadataPolicy, error) {
	if lowPolicy.OpenIDClient != nil {
		var highOpenIDClient openIDClientMetadataPolicy
		if highPolicy.OpenIDClient != nil {
			highOpenIDClient = *highPolicy.OpenIDClient
		}

		result, err := highOpenIDClient.merge(*lowPolicy.OpenIDClient)
		if err != nil {
			return metadataPolicy{}, err
		}

		highPolicy.OpenIDClient = &result
	}

	return highPolicy, nil
}

func (policy metadataPolicy) apply(statement entityStatement) (entityStatement, error) {
	if statement.Metadata.OpenIDClient != nil && policy.OpenIDClient != nil {
		clientPolicy := *policy.OpenIDClient
		client := *statement.Metadata.OpenIDClient
		client, err := clientPolicy.apply(client)
		if err != nil {
			return entityStatement{}, err
		}
		statement.Metadata.OpenIDClient = &client
	}

	return statement, nil
}

type openIDClientMetadataPolicy struct {
	Name                          metadataOperators[string]                           `json:"client_name,omitempty"`
	ApplicationType               metadataOperators[goidc.ApplicationType]            `json:"application_type,omitempty"`
	LogoURI                       metadataOperators[string]                           `json:"logo_uri,omitempty"`
	Contacts                      metadataOperators[[]string]                         `json:"contacts,omitempty"`
	PolicyURI                     metadataOperators[string]                           `json:"policy_uri,omitempty"`
	TermsOfServiceURI             metadataOperators[string]                           `json:"tos_uri,omitempty"`
	RedirectURIs                  metadataOperators[[]string]                         `json:"redirect_uris,omitempty"`
	RequestURIs                   metadataOperators[[]string]                         `json:"request_uris,omitempty"`
	GrantTypes                    metadataOperators[[]goidc.GrantType]                `json:"grant_types"`
	ResponseTypes                 metadataOperators[[]goidc.ResponseType]             `json:"response_types"`
	PublicJWKSURI                 metadataOperators[string]                           `json:"jwks_uri,omitempty"`
	PublicJWKS                    metadataOperators[string]                           `json:"jwks,omitempty"`
	ScopeIDs                      metadataOperators[[]string]                         `json:"scope,omitempty"`
	SubIdentifierType             metadataOperators[goidc.SubIdentifierType]          `json:"subject_type,omitempty"`
	SectorIdentifierURI           metadataOperators[string]                           `json:"sector_identifier_uri,omitempty"`
	IDTokenSigAlg                 metadataOperators[goidc.SignatureAlgorithm]         `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncAlg              metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncAlg          metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSigAlg                metadataOperators[goidc.SignatureAlgorithm]         `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncAlg             metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncAlg         metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"userinfo_encrypted_response_enc,omitempty"`
	JARIsRequired                 metadataOperators[bool]                             `json:"require_signed_request_object,omitempty"`
	JARSigAlg                     metadataOperators[goidc.SignatureAlgorithm]         `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg                  metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg              metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg                    metadataOperators[goidc.SignatureAlgorithm]         `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg                 metadataOperators[goidc.KeyEncryptionAlgorithm]     `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg             metadataOperators[goidc.ContentEncryptionAlgorithm] `json:"authorization_encrypted_response_enc,omitempty"`
	TokenAuthnMethod              metadataOperators[goidc.ClientAuthnType]            `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              metadataOperators[goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg,omitempty"`
	TokenIntrospectionAuthnMethod metadataOperators[goidc.ClientAuthnType]            `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg metadataOperators[goidc.SignatureAlgorithm]         `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    metadataOperators[goidc.ClientAuthnType]            `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    metadataOperators[goidc.SignatureAlgorithm]         `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingIsRequired    metadataOperators[bool]                             `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName       metadataOperators[string]                           `json:"tls_client_auth_subject_dn,omitempty"`
	TLSSubAlternativeName         metadataOperators[string]                           `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp       metadataOperators[string]                           `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingIsRequired     metadataOperators[bool]                             `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthDetailTypes               metadataOperators[[]string]                         `json:"authorization_data_types,omitempty"`
	DefaultMaxAgeSecs             metadataOperators[*int]                             `json:"default_max_age,omitempty"`
	DefaultACRValues              metadataOperators[string]                           `json:"default_acr_values,omitempty"`
	PARIsRequired                 metadataOperators[bool]                             `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode         metadataOperators[goidc.CIBATokenDeliveryMode]      `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint      metadataOperators[string]                           `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg                 metadataOperators[goidc.SignatureAlgorithm]         `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeIsEnabled         metadataOperators[bool]                             `json:"backchannel_user_code_parameter,omitempty"`
	// TODO: CustomAttributes.
}

func (p openIDClientMetadataPolicy) validate() error {
	if err := p.Name.validate(); err != nil {
		return err
	}

	if err := p.ApplicationType.validate(); err != nil {
		return err
	}

	if err := p.LogoURI.validate(); err != nil {
		return err
	}

	if err := p.Contacts.validate(); err != nil {
		return err
	}

	if err := p.PolicyURI.validate(); err != nil {
		return err
	}

	if err := p.TermsOfServiceURI.validate(); err != nil {
		return err
	}

	if err := p.RedirectURIs.validate(); err != nil {
		return err
	}

	if err := p.RequestURIs.validate(); err != nil {
		return err
	}

	if err := p.GrantTypes.validate(); err != nil {
		return err
	}

	if err := p.ResponseTypes.validate(); err != nil {
		return err
	}

	if err := p.PublicJWKSURI.validate(); err != nil {
		return err
	}

	if err := p.PublicJWKS.validate(); err != nil {
		return err
	}

	if err := p.ScopeIDs.validate(); err != nil {
		return err
	}

	if err := p.SubIdentifierType.validate(); err != nil {
		return err
	}

	if err := p.SectorIdentifierURI.validate(); err != nil {
		return err
	}

	if err := p.IDTokenSigAlg.validate(); err != nil {
		return err
	}

	if err := p.IDTokenKeyEncAlg.validate(); err != nil {
		return err
	}

	if err := p.IDTokenContentEncAlg.validate(); err != nil {
		return err
	}

	if err := p.UserInfoSigAlg.validate(); err != nil {
		return err
	}

	if err := p.UserInfoKeyEncAlg.validate(); err != nil {
		return err
	}

	if err := p.UserInfoContentEncAlg.validate(); err != nil {
		return err
	}

	if err := p.JARIsRequired.validate(); err != nil {
		return err
	}

	if err := p.JARSigAlg.validate(); err != nil {
		return err
	}

	if err := p.JARKeyEncAlg.validate(); err != nil {
		return err
	}

	if err := p.JARContentEncAlg.validate(); err != nil {
		return err
	}

	if err := p.JARMSigAlg.validate(); err != nil {
		return err
	}

	if err := p.JARMKeyEncAlg.validate(); err != nil {
		return err
	}

	if err := p.JARMContentEncAlg.validate(); err != nil {
		return err
	}

	if err := p.TokenAuthnMethod.validate(); err != nil {
		return err
	}

	if err := p.TokenAuthnSigAlg.validate(); err != nil {
		return err
	}

	if err := p.TokenIntrospectionAuthnMethod.validate(); err != nil {
		return err
	}

	if err := p.TokenIntrospectionAuthnSigAlg.validate(); err != nil {
		return err
	}

	if err := p.TokenRevocationAuthnMethod.validate(); err != nil {
		return err
	}

	if err := p.TokenRevocationAuthnSigAlg.validate(); err != nil {
		return err
	}

	if err := p.DPoPTokenBindingIsRequired.validate(); err != nil {
		return err
	}

	if err := p.TLSSubDistinguishedName.validate(); err != nil {
		return err
	}

	if err := p.TLSSubAlternativeName.validate(); err != nil {
		return err
	}

	if err := p.TLSSubAlternativeNameIp.validate(); err != nil {
		return err
	}

	if err := p.TLSTokenBindingIsRequired.validate(); err != nil {
		return err
	}

	if err := p.AuthDetailTypes.validate(); err != nil {
		return err
	}

	if err := p.DefaultMaxAgeSecs.validate(); err != nil {
		return err
	}

	if err := p.DefaultACRValues.validate(); err != nil {
		return err
	}

	if err := p.PARIsRequired.validate(); err != nil {
		return err
	}

	if err := p.CIBATokenDeliveryMode.validate(); err != nil {
		return err
	}

	if err := p.CIBANotificationEndpoint.validate(); err != nil {
		return err
	}

	if err := p.CIBAJARSigAlg.validate(); err != nil {
		return err
	}

	if err := p.CIBAUserCodeIsEnabled.validate(); err != nil {
		return err
	}

	return nil
}

func (high openIDClientMetadataPolicy) merge(low openIDClientMetadataPolicy) (openIDClientMetadataPolicy, error) {
	opName, err := high.Name.merge(low.Name)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.Name = opName

	opApplicationType, err := high.ApplicationType.merge(low.ApplicationType)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ApplicationType = opApplicationType

	opLogoURI, err := high.LogoURI.merge(low.LogoURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.LogoURI = opLogoURI

	opContacts, err := high.Contacts.merge(low.Contacts)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.Contacts = opContacts

	opPolicyURI, err := high.PolicyURI.merge(low.PolicyURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PolicyURI = opPolicyURI

	opTermsOfServiceURI, err := high.TermsOfServiceURI.merge(low.TermsOfServiceURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TermsOfServiceURI = opTermsOfServiceURI

	opRedirectURIs, err := high.RedirectURIs.merge(low.RedirectURIs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.RedirectURIs = opRedirectURIs

	opRequestURIs, err := high.RequestURIs.merge(low.RequestURIs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.RequestURIs = opRequestURIs

	opGrantTypes, err := high.GrantTypes.merge(low.GrantTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.GrantTypes = opGrantTypes

	opResponseTypes, err := high.ResponseTypes.merge(low.ResponseTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ResponseTypes = opResponseTypes

	opPublicJWKSURI, err := high.PublicJWKSURI.merge(low.PublicJWKSURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PublicJWKSURI = opPublicJWKSURI

	opPublicJWKS, err := high.PublicJWKS.merge(low.PublicJWKS)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PublicJWKS = opPublicJWKS

	opScopeIDs, err := high.ScopeIDs.merge(low.ScopeIDs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.ScopeIDs = opScopeIDs

	opSubIdentifierType, err := high.SubIdentifierType.merge(low.SubIdentifierType)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.SubIdentifierType = opSubIdentifierType

	opSectorIdentifierURI, err := high.SectorIdentifierURI.merge(low.SectorIdentifierURI)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.SectorIdentifierURI = opSectorIdentifierURI

	opIDTokenSigAlg, err := high.IDTokenSigAlg.merge(low.IDTokenSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenSigAlg = opIDTokenSigAlg

	opIDTokenKeyEncAlg, err := high.IDTokenKeyEncAlg.merge(low.IDTokenKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenKeyEncAlg = opIDTokenKeyEncAlg

	opIDTokenContentEncAlg, err := high.IDTokenContentEncAlg.merge(low.IDTokenContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.IDTokenContentEncAlg = opIDTokenContentEncAlg

	opUserInfoSigAlg, err := high.UserInfoSigAlg.merge(low.UserInfoSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoSigAlg = opUserInfoSigAlg

	opUserInfoKeyEncAlg, err := high.UserInfoKeyEncAlg.merge(low.UserInfoKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoKeyEncAlg = opUserInfoKeyEncAlg

	opUserInfoContentEncAlg, err := high.UserInfoContentEncAlg.merge(low.UserInfoContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.UserInfoContentEncAlg = opUserInfoContentEncAlg

	opJARIsRequired, err := high.JARIsRequired.merge(low.JARIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARIsRequired = opJARIsRequired

	opJARSigAlg, err := high.JARSigAlg.merge(low.JARSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARSigAlg = opJARSigAlg

	opJARKeyEncAlg, err := high.JARKeyEncAlg.merge(low.JARKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARKeyEncAlg = opJARKeyEncAlg

	opJARContentEncAlg, err := high.JARContentEncAlg.merge(low.JARContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARContentEncAlg = opJARContentEncAlg

	opJARMSigAlg, err := high.JARMSigAlg.merge(low.JARMSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMSigAlg = opJARMSigAlg

	opJARMKeyEncAlg, err := high.JARMKeyEncAlg.merge(low.JARMKeyEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMKeyEncAlg = opJARMKeyEncAlg

	opJARMContentEncAlg, err := high.JARMContentEncAlg.merge(low.JARMContentEncAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.JARMContentEncAlg = opJARMContentEncAlg

	opTokenAuthnMethod, err := high.TokenAuthnMethod.merge(low.TokenAuthnMethod)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenAuthnMethod = opTokenAuthnMethod

	opTokenAuthnSigAlg, err := high.TokenAuthnSigAlg.merge(low.TokenAuthnSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenAuthnSigAlg = opTokenAuthnSigAlg

	opTokenIntrospectionAuthnMethod, err := high.TokenIntrospectionAuthnMethod.merge(low.TokenIntrospectionAuthnMethod)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenIntrospectionAuthnMethod = opTokenIntrospectionAuthnMethod

	opTokenIntrospectionAuthnSigAlg, err := high.TokenIntrospectionAuthnSigAlg.merge(low.TokenIntrospectionAuthnSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenIntrospectionAuthnSigAlg = opTokenIntrospectionAuthnSigAlg

	opTokenRevocationAuthnMethod, err := high.TokenRevocationAuthnMethod.merge(low.TokenRevocationAuthnMethod)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenRevocationAuthnMethod = opTokenRevocationAuthnMethod

	opTokenRevocationAuthnSigAlg, err := high.TokenRevocationAuthnSigAlg.merge(low.TokenRevocationAuthnSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TokenRevocationAuthnSigAlg = opTokenRevocationAuthnSigAlg

	opDPoPTokenBindingIsRequired, err := high.DPoPTokenBindingIsRequired.merge(low.DPoPTokenBindingIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DPoPTokenBindingIsRequired = opDPoPTokenBindingIsRequired

	opTLSSubDistinguishedName, err := high.TLSSubDistinguishedName.merge(low.TLSSubDistinguishedName)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSSubDistinguishedName = opTLSSubDistinguishedName

	opTLSSubAlternativeName, err := high.TLSSubAlternativeName.merge(low.TLSSubAlternativeName)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSSubAlternativeName = opTLSSubAlternativeName

	opTLSSubAlternativeNameIp, err := high.TLSSubAlternativeNameIp.merge(low.TLSSubAlternativeNameIp)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSSubAlternativeNameIp = opTLSSubAlternativeNameIp

	opTLSTokenBindingIsRequired, err := high.TLSTokenBindingIsRequired.merge(low.TLSTokenBindingIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.TLSTokenBindingIsRequired = opTLSTokenBindingIsRequired

	opAuthDetailTypes, err := high.AuthDetailTypes.merge(low.AuthDetailTypes)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.AuthDetailTypes = opAuthDetailTypes

	opDefaultMaxAgeSecs, err := high.DefaultMaxAgeSecs.merge(low.DefaultMaxAgeSecs)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DefaultMaxAgeSecs = opDefaultMaxAgeSecs

	opDefaultACRValues, err := high.DefaultACRValues.merge(low.DefaultACRValues)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.DefaultACRValues = opDefaultACRValues

	opPARIsRequired, err := high.PARIsRequired.merge(low.PARIsRequired)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.PARIsRequired = opPARIsRequired

	opCIBATokenDeliveryMode, err := high.CIBATokenDeliveryMode.merge(low.CIBATokenDeliveryMode)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBATokenDeliveryMode = opCIBATokenDeliveryMode

	opCIBANotificationEndpoint, err := high.CIBANotificationEndpoint.merge(low.CIBANotificationEndpoint)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBANotificationEndpoint = opCIBANotificationEndpoint

	opCIBAJARSigAlg, err := high.CIBAJARSigAlg.merge(low.CIBAJARSigAlg)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBAJARSigAlg = opCIBAJARSigAlg

	opCIBAUserCodeIsEnabled, err := high.CIBAUserCodeIsEnabled.merge(low.CIBAUserCodeIsEnabled)
	if err != nil {
		return openIDClientMetadataPolicy{}, err
	}
	high.CIBAUserCodeIsEnabled = opCIBAUserCodeIsEnabled

	return high, nil
}

func (policy openIDClientMetadataPolicy) apply(client openIDClient) (openIDClient, error) {
	name, err := policy.Name.apply(client.Name)
	if err != nil {
		return openIDClient{}, err
	}
	client.Name = name

	applicationType, err := policy.ApplicationType.apply(client.ApplicationType)
	if err != nil {
		return openIDClient{}, err
	}
	client.ApplicationType = applicationType

	logoURI, err := policy.LogoURI.apply(client.LogoURI)
	if err != nil {
		return openIDClient{}, err
	}
	client.LogoURI = logoURI

	contacts, err := policy.Contacts.apply(client.Contacts)
	if err != nil {
		return openIDClient{}, err
	}
	client.Contacts = contacts

	policyURI, err := policy.PolicyURI.apply(client.PolicyURI)
	if err != nil {
		return openIDClient{}, err
	}
	client.PolicyURI = policyURI

	termsOfServiceURI, err := policy.TermsOfServiceURI.apply(client.TermsOfServiceURI)
	if err != nil {
		return openIDClient{}, err
	}
	client.TermsOfServiceURI = termsOfServiceURI

	redirectURIs, err := policy.RedirectURIs.apply(client.RedirectURIs)
	if err != nil {
		return openIDClient{}, err
	}
	client.RedirectURIs = redirectURIs

	requestURIs, err := policy.RequestURIs.apply(client.RequestURIs)
	if err != nil {
		return openIDClient{}, err
	}
	client.RequestURIs = requestURIs

	grantTypes, err := policy.GrantTypes.apply(client.GrantTypes)
	if err != nil {
		return openIDClient{}, err
	}
	client.GrantTypes = grantTypes

	responseTypes, err := policy.ResponseTypes.apply(client.ResponseTypes)
	if err != nil {
		return openIDClient{}, err
	}
	client.ResponseTypes = responseTypes

	publicJWKSURI, err := policy.PublicJWKSURI.apply(client.PublicJWKSURI)
	if err != nil {
		return openIDClient{}, err
	}
	client.PublicJWKSURI = publicJWKSURI

	publicJWKS, err := policy.PublicJWKS.apply(string(client.PublicJWKS))
	if err != nil {
		return openIDClient{}, err
	}
	client.PublicJWKS = []byte(publicJWKS)

	scopesIDs := strutil.SplitWithSpaces(client.ScopeIDs)
	scopeIDs, err := policy.ScopeIDs.apply(scopesIDs)
	if err != nil {
		return openIDClient{}, err
	}
	client.ScopeIDs = strings.Join(scopeIDs, " ")

	subIdentifierType, err := policy.SubIdentifierType.apply(client.SubIdentifierType)
	if err != nil {
		return openIDClient{}, err
	}
	client.SubIdentifierType = subIdentifierType

	sectorIdentifierURI, err := policy.SectorIdentifierURI.apply(client.SectorIdentifierURI)
	if err != nil {
		return openIDClient{}, err
	}
	client.SectorIdentifierURI = sectorIdentifierURI

	idTokenSigAlg, err := policy.IDTokenSigAlg.apply(client.IDTokenSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.IDTokenSigAlg = idTokenSigAlg

	idTokenKeyEncAlg, err := policy.IDTokenKeyEncAlg.apply(client.IDTokenKeyEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.IDTokenKeyEncAlg = idTokenKeyEncAlg

	idTokenContentEncAlg, err := policy.IDTokenContentEncAlg.apply(client.IDTokenContentEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.IDTokenContentEncAlg = idTokenContentEncAlg

	userInfoSigAlg, err := policy.UserInfoSigAlg.apply(client.UserInfoSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.UserInfoSigAlg = userInfoSigAlg

	userInfoKeyEncAlg, err := policy.UserInfoKeyEncAlg.apply(client.UserInfoKeyEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.UserInfoKeyEncAlg = userInfoKeyEncAlg

	userInfoContentEncAlg, err := policy.UserInfoContentEncAlg.apply(client.UserInfoContentEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.UserInfoContentEncAlg = userInfoContentEncAlg

	jarIsRequired, err := policy.JARIsRequired.apply(client.JARIsRequired)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARIsRequired = jarIsRequired

	jarSigAlg, err := policy.JARSigAlg.apply(client.JARSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARSigAlg = jarSigAlg

	jarKeyEncAlg, err := policy.JARKeyEncAlg.apply(client.JARKeyEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARKeyEncAlg = jarKeyEncAlg

	jarContentEncAlg, err := policy.JARContentEncAlg.apply(client.JARContentEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARContentEncAlg = jarContentEncAlg

	jarmSigAlg, err := policy.JARMSigAlg.apply(client.JARMSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARMSigAlg = jarmSigAlg

	jarmKeyEncAlg, err := policy.JARMKeyEncAlg.apply(client.JARMKeyEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARMKeyEncAlg = jarmKeyEncAlg

	jarmContentEncAlg, err := policy.JARMContentEncAlg.apply(client.JARMContentEncAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.JARMContentEncAlg = jarmContentEncAlg

	tokenAuthnMethod, err := policy.TokenAuthnMethod.apply(client.TokenAuthnMethod)
	if err != nil {
		return openIDClient{}, err
	}
	client.TokenAuthnMethod = tokenAuthnMethod

	tokenAuthnSigAlg, err := policy.TokenAuthnSigAlg.apply(client.TokenAuthnSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.TokenAuthnSigAlg = tokenAuthnSigAlg

	tokenIntrospectionAuthnMethod, err := policy.TokenIntrospectionAuthnMethod.apply(client.TokenIntrospectionAuthnMethod)
	if err != nil {
		return openIDClient{}, err
	}
	client.TokenIntrospectionAuthnMethod = tokenIntrospectionAuthnMethod

	tokenIntrospectionAuthnSigAlg, err := policy.TokenIntrospectionAuthnSigAlg.apply(client.TokenIntrospectionAuthnSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.TokenIntrospectionAuthnSigAlg = tokenIntrospectionAuthnSigAlg

	tokenRevocationAuthnMethod, err := policy.TokenRevocationAuthnMethod.apply(client.TokenRevocationAuthnMethod)
	if err != nil {
		return openIDClient{}, err
	}
	client.TokenRevocationAuthnMethod = tokenRevocationAuthnMethod

	tokenRevocationAuthnSigAlg, err := policy.TokenRevocationAuthnSigAlg.apply(client.TokenRevocationAuthnSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.TokenRevocationAuthnSigAlg = tokenRevocationAuthnSigAlg

	dpopTokenBindingIsRequired, err := policy.DPoPTokenBindingIsRequired.apply(client.DPoPTokenBindingIsRequired)
	if err != nil {
		return openIDClient{}, err
	}
	client.DPoPTokenBindingIsRequired = dpopTokenBindingIsRequired

	tlsSubDistinguishedName, err := policy.TLSSubDistinguishedName.apply(client.TLSSubDistinguishedName)
	if err != nil {
		return openIDClient{}, err
	}
	client.TLSSubDistinguishedName = tlsSubDistinguishedName

	tlsSubAlternativeName, err := policy.TLSSubAlternativeName.apply(client.TLSSubAlternativeName)
	if err != nil {
		return openIDClient{}, err
	}
	client.TLSSubAlternativeName = tlsSubAlternativeName

	tlsSubAlternativeNameIp, err := policy.TLSSubAlternativeNameIp.apply(client.TLSSubAlternativeNameIp)
	if err != nil {
		return openIDClient{}, err
	}
	client.TLSSubAlternativeNameIp = tlsSubAlternativeNameIp

	tlsTokenBindingIsRequired, err := policy.TLSTokenBindingIsRequired.apply(client.TLSTokenBindingIsRequired)
	if err != nil {
		return openIDClient{}, err
	}
	client.TLSTokenBindingIsRequired = tlsTokenBindingIsRequired

	authDetailTypes, err := policy.AuthDetailTypes.apply(client.AuthDetailTypes)
	if err != nil {
		return openIDClient{}, err
	}
	client.AuthDetailTypes = authDetailTypes

	defaultMaxAgeSecs, err := policy.DefaultMaxAgeSecs.apply(client.DefaultMaxAgeSecs)
	if err != nil {
		return openIDClient{}, err
	}
	client.DefaultMaxAgeSecs = defaultMaxAgeSecs

	defaultACRValues, err := policy.DefaultACRValues.apply(client.DefaultACRValues)
	if err != nil {
		return openIDClient{}, err
	}
	client.DefaultACRValues = defaultACRValues

	parIsRequired, err := policy.PARIsRequired.apply(client.PARIsRequired)
	if err != nil {
		return openIDClient{}, err
	}
	client.PARIsRequired = parIsRequired

	cibaTokenDeliveryMode, err := policy.CIBATokenDeliveryMode.apply(client.CIBATokenDeliveryMode)
	if err != nil {
		return openIDClient{}, err
	}
	client.CIBATokenDeliveryMode = cibaTokenDeliveryMode

	cibaNotificationEndpoint, err := policy.CIBANotificationEndpoint.apply(client.CIBANotificationEndpoint)
	if err != nil {
		return openIDClient{}, err
	}
	client.CIBANotificationEndpoint = cibaNotificationEndpoint

	cibaJARSigAlg, err := policy.CIBAJARSigAlg.apply(client.CIBAJARSigAlg)
	if err != nil {
		return openIDClient{}, err
	}
	client.CIBAJARSigAlg = cibaJARSigAlg

	cibaUserCodeIsEnabled, err := policy.CIBAUserCodeIsEnabled.apply(client.CIBAUserCodeIsEnabled)
	if err != nil {
		return openIDClient{}, err
	}
	client.CIBAUserCodeIsEnabled = cibaUserCodeIsEnabled

	return client, nil
}
