package federation

import (
	"strings"

	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type metadataPolicy struct {
	OpenIDProvider *openIDProviderMetadataPolicy `json:"openid_provider,omitempty"`
	OpenIDClient   *openIDClientMetadataPolicy   `json:"openid_relying_party,omitempty"`
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

	if lowPolicy.OpenIDProvider != nil {
		var highOpenIDProvider openIDProviderMetadataPolicy
		if highPolicy.OpenIDProvider != nil {
			highOpenIDProvider = *highPolicy.OpenIDProvider
		}

		result, err := highOpenIDProvider.merge(*lowPolicy.OpenIDProvider)
		if err != nil {
			return metadataPolicy{}, err
		}

		highPolicy.OpenIDProvider = &result
	}

	return highPolicy, nil
}

func (policy metadataPolicy) apply(statement openIDEntityStatement) (openIDEntityStatement, error) {
	if statement.Metadata.OpenIDClient != nil && policy.OpenIDClient != nil {
		clientPolicy := *policy.OpenIDClient
		client := *statement.Metadata.OpenIDClient
		client, err := clientPolicy.apply(client)
		if err != nil {
			return openIDEntityStatement{}, err
		}
		statement.Metadata.OpenIDClient = &client
	}

	if statement.Metadata.OpenIDProvider != nil && policy.OpenIDProvider != nil {
		providerPolicy := *policy.OpenIDProvider
		provider := *statement.Metadata.OpenIDProvider
		provider, err := providerPolicy.apply(provider)
		if err != nil {
			return openIDEntityStatement{}, err
		}
		statement.Metadata.OpenIDProvider = &provider
	}

	return statement, nil
}

type openIDClientMetadataPolicy struct {
	Name                          metadataPolicyPrimitiveOps[string]                           `json:"client_name,omitempty"`
	ApplicationType               metadataPolicyPrimitiveOps[goidc.ApplicationType]            `json:"application_type,omitempty"`
	LogoURI                       metadataPolicyPrimitiveOps[string]                           `json:"logo_uri,omitempty"`
	Contacts                      metadataPolicySliceOps[string]                               `json:"contacts,omitempty"`
	PolicyURI                     metadataPolicyPrimitiveOps[string]                           `json:"policy_uri,omitempty"`
	TermsOfServiceURI             metadataPolicyPrimitiveOps[string]                           `json:"tos_uri,omitempty"`
	RedirectURIs                  metadataPolicySliceOps[string]                               `json:"redirect_uris,omitempty"`
	RequestURIs                   metadataPolicySliceOps[string]                               `json:"request_uris,omitempty"`
	GrantTypes                    metadataPolicySliceOps[goidc.GrantType]                      `json:"grant_types"`
	ResponseTypes                 metadataPolicySliceOps[goidc.ResponseType]                   `json:"response_types"`
	PublicJWKSURI                 metadataPolicyPrimitiveOps[string]                           `json:"jwks_uri,omitempty"`
	PublicJWKS                    metadataPolicyPrimitiveOps[string]                           `json:"jwks,omitempty"`
	ScopeIDs                      metadataPolicySliceOps[string]                               `json:"scope,omitempty"`
	SubIdentifierType             metadataPolicyPrimitiveOps[goidc.SubIdentifierType]          `json:"subject_type,omitempty"`
	SectorIdentifierURI           metadataPolicyPrimitiveOps[string]                           `json:"sector_identifier_uri,omitempty"`
	IDTokenSigAlg                 metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncAlg              metadataPolicyPrimitiveOps[goidc.KeyEncryptionAlgorithm]     `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncAlg          metadataPolicyPrimitiveOps[goidc.ContentEncryptionAlgorithm] `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSigAlg                metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncAlg             metadataPolicyPrimitiveOps[goidc.KeyEncryptionAlgorithm]     `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncAlg         metadataPolicyPrimitiveOps[goidc.ContentEncryptionAlgorithm] `json:"userinfo_encrypted_response_enc,omitempty"`
	JARIsRequired                 metadataPolicyPrimitiveOps[bool]                             `json:"require_signed_request_object,omitempty"`
	JARSigAlg                     metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg                  metadataPolicyPrimitiveOps[goidc.KeyEncryptionAlgorithm]     `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg              metadataPolicyPrimitiveOps[goidc.ContentEncryptionAlgorithm] `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg                    metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg                 metadataPolicyPrimitiveOps[goidc.KeyEncryptionAlgorithm]     `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg             metadataPolicyPrimitiveOps[goidc.ContentEncryptionAlgorithm] `json:"authorization_encrypted_response_enc,omitempty"`
	TokenAuthnMethod              metadataPolicyPrimitiveOps[goidc.ClientAuthnType]            `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg,omitempty"`
	TokenIntrospectionAuthnMethod metadataPolicyPrimitiveOps[goidc.ClientAuthnType]            `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    metadataPolicyPrimitiveOps[goidc.ClientAuthnType]            `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingIsRequired    metadataPolicyPrimitiveOps[bool]                             `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName       metadataPolicyPrimitiveOps[string]                           `json:"tls_client_auth_subject_dn,omitempty"`
	TLSSubAlternativeName         metadataPolicyPrimitiveOps[string]                           `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp       metadataPolicyPrimitiveOps[string]                           `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingIsRequired     metadataPolicyPrimitiveOps[bool]                             `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthDetailTypes               metadataPolicySliceOps[string]                               `json:"authorization_data_types,omitempty"`
	DefaultMaxAgeSecs             metadataPolicyPrimitiveOps[*int]                             `json:"default_max_age,omitempty"`
	DefaultACRValues              metadataPolicyPrimitiveOps[string]                           `json:"default_acr_values,omitempty"`
	PARIsRequired                 metadataPolicyPrimitiveOps[bool]                             `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode         metadataPolicyPrimitiveOps[goidc.CIBATokenDeliveryMode]      `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint      metadataPolicyPrimitiveOps[string]                           `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg                 metadataPolicyPrimitiveOps[goidc.SignatureAlgorithm]         `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeIsEnabled         metadataPolicyPrimitiveOps[bool]                             `json:"backchannel_user_code_parameter,omitempty"`
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

type openIDProviderMetadataPolicy struct {
	Issuer                              metadataPolicyPrimitiveOps[string]                       `json:"issuer"`
	ClientRegistrationEndpoint          metadataPolicyPrimitiveOps[string]                       `json:"registration_endpoint,omitempty"`
	AuthorizationEndpoint               metadataPolicyPrimitiveOps[string]                       `json:"authorization_endpoint"`
	TokenEndpoint                       metadataPolicyPrimitiveOps[string]                       `json:"token_endpoint"`
	UserinfoEndpoint                    metadataPolicyPrimitiveOps[string]                       `json:"userinfo_endpoint"`
	JWKSEndpoint                        metadataPolicyPrimitiveOps[string]                       `json:"jwks_uri"`
	PAREndpoint                         metadataPolicyPrimitiveOps[string]                       `json:"pushed_authorization_request_endpoint,omitempty"`
	PARIsRequired                       metadataPolicyPrimitiveOps[bool]                         `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypes                       metadataPolicySliceOps[goidc.ResponseType]               `json:"response_types_supported,omitempty"`
	ResponseModes                       metadataPolicySliceOps[goidc.ResponseMode]               `json:"response_modes_supported,omitempty"`
	GrantTypes                          metadataPolicySliceOps[goidc.GrantType]                  `json:"grant_types_supported,omitempty"`
	Scopes                              metadataPolicySliceOps[string]                           `json:"scopes_supported"`
	UserClaimsSupported                 metadataPolicySliceOps[string]                           `json:"claims_supported,omitempty"`
	ClaimTypesSupported                 metadataPolicySliceOps[goidc.ClaimType]                  `json:"claim_types_supported,omitempty"`
	SubIdentifierTypes                  metadataPolicySliceOps[goidc.SubIdentifierType]          `json:"subject_types_supported,omitempty"`
	IDTokenSigAlgs                      metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"id_token_signing_alg_values_supported"`
	IDTokenKeyEncAlgs                   metadataPolicySliceOps[goidc.KeyEncryptionAlgorithm]     `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenContentEncAlgs               metadataPolicySliceOps[goidc.ContentEncryptionAlgorithm] `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoKeyEncAlgs                  metadataPolicySliceOps[goidc.KeyEncryptionAlgorithm]     `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoContentEncAlgs              metadataPolicySliceOps[goidc.ContentEncryptionAlgorithm] `json:"userinfo_encryption_enc_values_supported,omitempty"`
	UserInfoSigAlgs                     metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"userinfo_signing_alg_values_supported,omitempty"`
	TokenAuthnMethods                   metadataPolicySliceOps[goidc.ClientAuthnType]            `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenAuthnSigAlgs                   metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	JARIsEnabled                        metadataPolicyPrimitiveOps[bool]                         `json:"request_parameter_supported,omitempty"`
	JARIsRequired                       metadataPolicyPrimitiveOps[bool]                         `json:"require_signed_request_object,omitempty"`
	JARAlgs                             metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncAlgs                       metadataPolicySliceOps[goidc.KeyEncryptionAlgorithm]     `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncAlgs                   metadataPolicySliceOps[goidc.ContentEncryptionAlgorithm] `json:"request_object_encryption_enc_values_supported,omitempty"`
	JARByReferenceIsEnabled             metadataPolicyPrimitiveOps[bool]                         `json:"request_uri_parameter_supported,omitempty"`
	JARRequestURIRegistrationIsRequired metadataPolicyPrimitiveOps[bool]                         `json:"require_request_uri_registration,omitempty"`
	JARMAlgs                            metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncAlgs                      metadataPolicySliceOps[goidc.KeyEncryptionAlgorithm]     `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncAlgs                  metadataPolicySliceOps[goidc.ContentEncryptionAlgorithm] `json:"authorization_encryption_enc_values_supported,omitempty"`
	IssuerResponseParamIsEnabled        metadataPolicyPrimitiveOps[bool]                         `json:"authorization_response_iss_parameter_supported,omitempty"`
	ClaimsParamIsEnabled                metadataPolicyPrimitiveOps[bool]                         `json:"claims_parameter_supported,omitempty"`
	AuthDetailsIsEnabled                metadataPolicyPrimitiveOps[bool]                         `json:"authorization_details_supported,omitempty"`
	AuthDetailTypesSupported            metadataPolicySliceOps[string]                           `json:"authorization_data_types_supported,omitempty"`
	DPoPSigAlgs                         metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"dpop_signing_alg_values_supported,omitempty"`
	TokenIntrospectionEndpoint          metadataPolicyPrimitiveOps[string]                       `json:"introspection_endpoint,omitempty"`
	TokenIntrospectionAuthnMethods      metadataPolicySliceOps[goidc.ClientAuthnType]            `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	TokenIntrospectionAuthnSigAlgs      metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	TokenRevocationEndpoint             metadataPolicyPrimitiveOps[string]                       `json:"revocation_endpoint,omitempty"`
	TokenRevocationAuthnMethods         metadataPolicySliceOps[goidc.ClientAuthnType]            `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	TokenRevocationAuthnSigAlgs         metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	CIBATokenDeliveryModes              metadataPolicySliceOps[goidc.CIBATokenDeliveryMode]      `json:"backchannel_token_delivery_modes_supported,omitempty"`
	CIBAEndpoint                        metadataPolicyPrimitiveOps[string]                       `json:"backchannel_authentication_endpoint,omitempty"`
	CIBAJARSigAlgs                      metadataPolicySliceOps[goidc.SignatureAlgorithm]         `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	CIBAUserCodeIsEnabled               metadataPolicyPrimitiveOps[bool]                         `json:"backchannel_user_code_parameter_supported,omitempty"`
	TLSBoundTokensIsEnabled             metadataPolicyPrimitiveOps[bool]                         `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	ACRs                                metadataPolicySliceOps[goidc.ACR]                        `json:"acr_values_supported,omitempty"`
	DisplayValues                       metadataPolicySliceOps[goidc.DisplayValue]               `json:"display_values_supported,omitempty"`
	CodeChallengeMethods                metadataPolicySliceOps[goidc.CodeChallengeMethod]        `json:"code_challenge_methods_supported,omitempty"`
}

func (highOps openIDProviderMetadataPolicy) merge(lowOps openIDProviderMetadataPolicy) (openIDProviderMetadataPolicy, error) {
	opIssuer, err := highOps.Issuer.merge(lowOps.Issuer)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.Issuer = opIssuer

	opClientRegistrationEndpoint, err := highOps.ClientRegistrationEndpoint.merge(lowOps.ClientRegistrationEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.ClientRegistrationEndpoint = opClientRegistrationEndpoint

	opAuthorizationEndpoint, err := highOps.AuthorizationEndpoint.merge(lowOps.AuthorizationEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.AuthorizationEndpoint = opAuthorizationEndpoint

	opTokenEndpoint, err := highOps.TokenEndpoint.merge(lowOps.TokenEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenEndpoint = opTokenEndpoint

	opUserinfoEndpoint, err := highOps.UserinfoEndpoint.merge(lowOps.UserinfoEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.UserinfoEndpoint = opUserinfoEndpoint

	opJWKSEndpoint, err := highOps.JWKSEndpoint.merge(lowOps.JWKSEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JWKSEndpoint = opJWKSEndpoint

	opPAREndpoint, err := highOps.PAREndpoint.merge(lowOps.PAREndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.PAREndpoint = opPAREndpoint

	opPARIsRequired, err := highOps.PARIsRequired.merge(lowOps.PARIsRequired)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.PARIsRequired = opPARIsRequired

	opResponseTypes, err := highOps.ResponseTypes.merge(lowOps.ResponseTypes)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.ResponseTypes = opResponseTypes

	opResponseModes, err := highOps.ResponseModes.merge(lowOps.ResponseModes)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.ResponseModes = opResponseModes

	opGrantTypes, err := highOps.GrantTypes.merge(lowOps.GrantTypes)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.GrantTypes = opGrantTypes

	opScopes, err := highOps.Scopes.merge(lowOps.Scopes)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.Scopes = opScopes

	opUserClaimsSupported, err := highOps.UserClaimsSupported.merge(lowOps.UserClaimsSupported)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.UserClaimsSupported = opUserClaimsSupported

	opClaimTypesSupported, err := highOps.ClaimTypesSupported.merge(lowOps.ClaimTypesSupported)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.ClaimTypesSupported = opClaimTypesSupported

	opSubIdentifierTypes, err := highOps.SubIdentifierTypes.merge(lowOps.SubIdentifierTypes)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.SubIdentifierTypes = opSubIdentifierTypes

	opIDTokenSigAlgs, err := highOps.IDTokenSigAlgs.merge(lowOps.IDTokenSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.IDTokenSigAlgs = opIDTokenSigAlgs

	opIDTokenKeyEncAlgs, err := highOps.IDTokenKeyEncAlgs.merge(lowOps.IDTokenKeyEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.IDTokenKeyEncAlgs = opIDTokenKeyEncAlgs

	opIDTokenContentEncAlgs, err := highOps.IDTokenContentEncAlgs.merge(lowOps.IDTokenContentEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.IDTokenContentEncAlgs = opIDTokenContentEncAlgs

	opUserInfoKeyEncAlgs, err := highOps.UserInfoKeyEncAlgs.merge(lowOps.UserInfoKeyEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.UserInfoKeyEncAlgs = opUserInfoKeyEncAlgs

	opUserInfoContentEncAlgs, err := highOps.UserInfoContentEncAlgs.merge(lowOps.UserInfoContentEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.UserInfoContentEncAlgs = opUserInfoContentEncAlgs

	opUserInfoSigAlgs, err := highOps.UserInfoSigAlgs.merge(lowOps.UserInfoSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.UserInfoSigAlgs = opUserInfoSigAlgs

	opTokenAuthnMethods, err := highOps.TokenAuthnMethods.merge(lowOps.TokenAuthnMethods)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenAuthnMethods = opTokenAuthnMethods

	opTokenAuthnSigAlgs, err := highOps.TokenAuthnSigAlgs.merge(lowOps.TokenAuthnSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenAuthnSigAlgs = opTokenAuthnSigAlgs

	opJARIsEnabled, err := highOps.JARIsEnabled.merge(lowOps.JARIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARIsEnabled = opJARIsEnabled

	opJARIsRequired, err := highOps.JARIsRequired.merge(lowOps.JARIsRequired)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARIsRequired = opJARIsRequired

	opJARAlgs, err := highOps.JARAlgs.merge(lowOps.JARAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARAlgs = opJARAlgs

	opJARKeyEncAlgs, err := highOps.JARKeyEncAlgs.merge(lowOps.JARKeyEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARKeyEncAlgs = opJARKeyEncAlgs

	opJARContentEncAlgs, err := highOps.JARContentEncAlgs.merge(lowOps.JARContentEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARContentEncAlgs = opJARContentEncAlgs

	opJARByReferenceIsEnabled, err := highOps.JARByReferenceIsEnabled.merge(lowOps.JARByReferenceIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARByReferenceIsEnabled = opJARByReferenceIsEnabled

	opJARRequestURIRegistrationIsRequired, err := highOps.JARRequestURIRegistrationIsRequired.merge(lowOps.JARRequestURIRegistrationIsRequired)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARRequestURIRegistrationIsRequired = opJARRequestURIRegistrationIsRequired

	opJARMAlgs, err := highOps.JARMAlgs.merge(lowOps.JARMAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARMAlgs = opJARMAlgs

	opJARMKeyEncAlgs, err := highOps.JARMKeyEncAlgs.merge(lowOps.JARMKeyEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARMKeyEncAlgs = opJARMKeyEncAlgs

	opJARMContentEncAlgs, err := highOps.JARMContentEncAlgs.merge(lowOps.JARMContentEncAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.JARMContentEncAlgs = opJARMContentEncAlgs

	opIssuerResponseParamIsEnabled, err := highOps.IssuerResponseParamIsEnabled.merge(lowOps.IssuerResponseParamIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.IssuerResponseParamIsEnabled = opIssuerResponseParamIsEnabled

	opClaimsParamIsEnabled, err := highOps.ClaimsParamIsEnabled.merge(lowOps.ClaimsParamIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.ClaimsParamIsEnabled = opClaimsParamIsEnabled

	opAuthDetailsIsEnabled, err := highOps.AuthDetailsIsEnabled.merge(lowOps.AuthDetailsIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.AuthDetailsIsEnabled = opAuthDetailsIsEnabled

	opAuthDetailTypesSupported, err := highOps.AuthDetailTypesSupported.merge(lowOps.AuthDetailTypesSupported)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.AuthDetailTypesSupported = opAuthDetailTypesSupported

	opDPoPSigAlgs, err := highOps.DPoPSigAlgs.merge(lowOps.DPoPSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.DPoPSigAlgs = opDPoPSigAlgs

	opTokenIntrospectionEndpoint, err := highOps.TokenIntrospectionEndpoint.merge(lowOps.TokenIntrospectionEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenIntrospectionEndpoint = opTokenIntrospectionEndpoint

	opTokenIntrospectionAuthnMethods, err := highOps.TokenIntrospectionAuthnMethods.merge(lowOps.TokenIntrospectionAuthnMethods)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenIntrospectionAuthnMethods = opTokenIntrospectionAuthnMethods

	opTokenIntrospectionAuthnSigAlgs, err := highOps.TokenIntrospectionAuthnSigAlgs.merge(lowOps.TokenIntrospectionAuthnSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenIntrospectionAuthnSigAlgs = opTokenIntrospectionAuthnSigAlgs

	opTokenRevocationEndpoint, err := highOps.TokenRevocationEndpoint.merge(lowOps.TokenRevocationEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenRevocationEndpoint = opTokenRevocationEndpoint

	opTokenRevocationAuthnMethods, err := highOps.TokenRevocationAuthnMethods.merge(lowOps.TokenRevocationAuthnMethods)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenRevocationAuthnMethods = opTokenRevocationAuthnMethods

	opTokenRevocationAuthnSigAlgs, err := highOps.TokenRevocationAuthnSigAlgs.merge(lowOps.TokenRevocationAuthnSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TokenRevocationAuthnSigAlgs = opTokenRevocationAuthnSigAlgs

	opCIBATokenDeliveryModes, err := highOps.CIBATokenDeliveryModes.merge(lowOps.CIBATokenDeliveryModes)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.CIBATokenDeliveryModes = opCIBATokenDeliveryModes

	opCIBAEndpoint, err := highOps.CIBAEndpoint.merge(lowOps.CIBAEndpoint)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.CIBAEndpoint = opCIBAEndpoint

	opCIBAJARSigAlgs, err := highOps.CIBAJARSigAlgs.merge(lowOps.CIBAJARSigAlgs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.CIBAJARSigAlgs = opCIBAJARSigAlgs

	opCIBAUserCodeIsEnabled, err := highOps.CIBAUserCodeIsEnabled.merge(lowOps.CIBAUserCodeIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.CIBAUserCodeIsEnabled = opCIBAUserCodeIsEnabled

	opTLSBoundTokensIsEnabled, err := highOps.TLSBoundTokensIsEnabled.merge(lowOps.TLSBoundTokensIsEnabled)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.TLSBoundTokensIsEnabled = opTLSBoundTokensIsEnabled

	opACRs, err := highOps.ACRs.merge(lowOps.ACRs)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.ACRs = opACRs

	opDisplayValues, err := highOps.DisplayValues.merge(lowOps.DisplayValues)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.DisplayValues = opDisplayValues

	opCodeChallengeMethods, err := highOps.CodeChallengeMethods.merge(lowOps.CodeChallengeMethods)
	if err != nil {
		return openIDProviderMetadataPolicy{}, err
	}
	highOps.CodeChallengeMethods = opCodeChallengeMethods

	return highOps, nil
}

func (policy openIDProviderMetadataPolicy) apply(provider openIDProvider) (openIDProvider, error) {
	var err error

	provider.Issuer, err = policy.Issuer.apply(provider.Issuer)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.ClientRegistrationEndpoint, err = policy.ClientRegistrationEndpoint.apply(provider.ClientRegistrationEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.AuthorizationEndpoint, err = policy.AuthorizationEndpoint.apply(provider.AuthorizationEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenEndpoint, err = policy.TokenEndpoint.apply(provider.TokenEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.UserinfoEndpoint, err = policy.UserinfoEndpoint.apply(provider.UserinfoEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JWKSEndpoint, err = policy.JWKSEndpoint.apply(provider.JWKSEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.PAREndpoint, err = policy.PAREndpoint.apply(provider.PAREndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.PARIsRequired, err = policy.PARIsRequired.apply(provider.PARIsRequired)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.ResponseTypes, err = policy.ResponseTypes.apply(provider.ResponseTypes)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.ResponseModes, err = policy.ResponseModes.apply(provider.ResponseModes)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.GrantTypes, err = policy.GrantTypes.apply(provider.GrantTypes)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.Scopes, err = policy.Scopes.apply(provider.Scopes)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.UserClaimsSupported, err = policy.UserClaimsSupported.apply(provider.UserClaimsSupported)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.ClaimTypesSupported, err = policy.ClaimTypesSupported.apply(provider.ClaimTypesSupported)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.SubIdentifierTypes, err = policy.SubIdentifierTypes.apply(provider.SubIdentifierTypes)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.IDTokenSigAlgs, err = policy.IDTokenSigAlgs.apply(provider.IDTokenSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.IDTokenKeyEncAlgs, err = policy.IDTokenKeyEncAlgs.apply(provider.IDTokenKeyEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.IDTokenContentEncAlgs, err = policy.IDTokenContentEncAlgs.apply(provider.IDTokenContentEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.UserInfoKeyEncAlgs, err = policy.UserInfoKeyEncAlgs.apply(provider.UserInfoKeyEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.UserInfoContentEncAlgs, err = policy.UserInfoContentEncAlgs.apply(provider.UserInfoContentEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.UserInfoSigAlgs, err = policy.UserInfoSigAlgs.apply(provider.UserInfoSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenAuthnMethods, err = policy.TokenAuthnMethods.apply(provider.TokenAuthnMethods)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenAuthnSigAlgs, err = policy.TokenAuthnSigAlgs.apply(provider.TokenAuthnSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARIsEnabled, err = policy.JARIsEnabled.apply(provider.JARIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARIsRequired, err = policy.JARIsRequired.apply(provider.JARIsRequired)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARAlgs, err = policy.JARAlgs.apply(provider.JARAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARKeyEncAlgs, err = policy.JARKeyEncAlgs.apply(provider.JARKeyEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARContentEncAlgs, err = policy.JARContentEncAlgs.apply(provider.JARContentEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARByReferenceIsEnabled, err = policy.JARByReferenceIsEnabled.apply(provider.JARByReferenceIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARRequestURIRegistrationIsRequired, err = policy.JARRequestURIRegistrationIsRequired.apply(provider.JARRequestURIRegistrationIsRequired)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARMAlgs, err = policy.JARMAlgs.apply(provider.JARMAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARMKeyEncAlgs, err = policy.JARMKeyEncAlgs.apply(provider.JARMKeyEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.JARMContentEncAlgs, err = policy.JARMContentEncAlgs.apply(provider.JARMContentEncAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.IssuerResponseParamIsEnabled, err = policy.IssuerResponseParamIsEnabled.apply(provider.IssuerResponseParamIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.ClaimsParamIsEnabled, err = policy.ClaimsParamIsEnabled.apply(provider.ClaimsParamIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.AuthDetailsIsEnabled, err = policy.AuthDetailsIsEnabled.apply(provider.AuthDetailsIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.AuthDetailTypesSupported, err = policy.AuthDetailTypesSupported.apply(provider.AuthDetailTypesSupported)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.DPoPSigAlgs, err = policy.DPoPSigAlgs.apply(provider.DPoPSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenIntrospectionEndpoint, err = policy.TokenIntrospectionEndpoint.apply(provider.TokenIntrospectionEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenIntrospectionAuthnMethods, err = policy.TokenIntrospectionAuthnMethods.apply(provider.TokenIntrospectionAuthnMethods)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenIntrospectionAuthnSigAlgs, err = policy.TokenIntrospectionAuthnSigAlgs.apply(provider.TokenIntrospectionAuthnSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenRevocationEndpoint, err = policy.TokenRevocationEndpoint.apply(provider.TokenRevocationEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenRevocationAuthnMethods, err = policy.TokenRevocationAuthnMethods.apply(provider.TokenRevocationAuthnMethods)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TokenRevocationAuthnSigAlgs, err = policy.TokenRevocationAuthnSigAlgs.apply(provider.TokenRevocationAuthnSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.CIBATokenDeliveryModes, err = policy.CIBATokenDeliveryModes.apply(provider.CIBATokenDeliveryModes)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.CIBAEndpoint, err = policy.CIBAEndpoint.apply(provider.CIBAEndpoint)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.CIBAJARSigAlgs, err = policy.CIBAJARSigAlgs.apply(provider.CIBAJARSigAlgs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.CIBAUserCodeIsEnabled, err = policy.CIBAUserCodeIsEnabled.apply(provider.CIBAUserCodeIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.TLSBoundTokensIsEnabled, err = policy.TLSBoundTokensIsEnabled.apply(provider.TLSBoundTokensIsEnabled)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.ACRs, err = policy.ACRs.apply(provider.ACRs)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.DisplayValues, err = policy.DisplayValues.apply(provider.DisplayValues)
	if err != nil {
		return openIDProvider{}, err
	}

	provider.CodeChallengeMethods, err = policy.CodeChallengeMethods.apply(provider.CodeChallengeMethods)
	if err != nil {
		return openIDProvider{}, err
	}

	return provider, nil
}
