package federation

import (
	"encoding/json"
	"reflect"
	"slices"
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
	TokenAuthnMethod              metadataOperators[goidc.ClientAuthnType]            `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              metadataOperators[goidc.SignatureAlgorithm]         `json:"token_endpoint_auth_signing_alg"`
	TokenIntrospectionAuthnMethod metadataOperators[goidc.ClientAuthnType]            `json:"introspection_endpoint_auth_method"`
	TokenIntrospectionAuthnSigAlg metadataOperators[goidc.SignatureAlgorithm]         `json:"introspection_endpoint_auth_signing_alg"`
	TokenRevocationAuthnMethod    metadataOperators[goidc.ClientAuthnType]            `json:"revocation_endpoint_auth_method"`
	TokenRevocationAuthnSigAlg    metadataOperators[goidc.SignatureAlgorithm]         `json:"revocation_endpoint_auth_signing_alg"`
	DPoPTokenBindingIsRequired    metadataOperators[bool]                             `json:"dpop_bound_access_tokens"`
	TLSSubDistinguishedName       metadataOperators[string]                           `json:"tls_client_auth_subject_dn"`
	TLSSubAlternativeName         metadataOperators[string]                           `json:"tls_client_auth_san_dns"`
	TLSSubAlternativeNameIp       metadataOperators[string]                           `json:"tls_client_auth_san_ip"`
	TLSTokenBindingIsRequired     metadataOperators[bool]                             `json:"tls_client_certificate_bound_access_tokens"`
	AuthDetailTypes               metadataOperators[[]string]                         `json:"authorization_data_types"`
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
	knownKeys := jsonKeys(info)
	for key, value := range allFields {
		if !slices.Contains(knownKeys, key) {
			info.CustomAttributes[key] = value
		}
	}

	*policy = openIDClientMetadataPolicy(info)
	return nil
}

// jsonKeys returns a slice of JSON field names for a given struct.
func jsonKeys(v any) []string {
	var keys []string
	val := reflect.ValueOf(v)
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")

		if tag != "" && tag != "-" {
			keys = append(keys, strings.Split(tag, ",")[0])
		}
	}
	return keys
}

func (p openIDClientMetadataPolicy) validate() error {
	v := reflect.ValueOf(p)
	for i := 0; i < v.NumField(); i++ {
		if v.Type().Field(i).Name == "CustomAttributes" {
			continue
		}

		field := v.Field(i)
		validateMethod := field.MethodByName("validate")
		if !validateMethod.IsValid() {
			continue
		}

		result := validateMethod.Call(nil)
		if !result[0].IsNil() {
			return result[0].Interface().(error)
		}
	}

	for _, ops := range p.CustomAttributes {
		if err := ops.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (high openIDClientMetadataPolicy) merge(low openIDClientMetadataPolicy) (openIDClientMetadataPolicy, error) {
	highV := reflect.ValueOf(&high).Elem()
	lowV := reflect.ValueOf(low)

	for i := 0; i < highV.NumField(); i++ {
		if highV.Type().Field(i).Name == "CustomAttributes" {
			continue
		}

		highField := highV.Field(i)
		lowField := lowV.Field(i)

		mergeMethod := highField.MethodByName("merge")
		if !mergeMethod.IsValid() {
			continue
		}

		result := mergeMethod.Call([]reflect.Value{lowField})
		if !result[1].IsNil() {
			return openIDClientMetadataPolicy{}, result[1].Interface().(error)
		}

		highField.Set(result[0])
	}

	for att, lowOps := range low.CustomAttributes {
		ops, err := high.customAttribute(att).merge(lowOps)
		if err != nil {
			return openIDClientMetadataPolicy{}, err
		}
		high.setCustomAttribute(att, ops)
	}

	return high, nil
}

func (policy openIDClientMetadataPolicy) apply(c goidc.ClientMeta) (goidc.ClientMeta, error) {
	policyV := reflect.ValueOf(policy)
	clientV := reflect.ValueOf(&c).Elem()

	for i := 0; i < policyV.NumField(); i++ {
		fieldName := policyV.Type().Field(i).Name
		if fieldName == "CustomAttributes" || fieldName == "ScopeIDs" {
			continue
		}

		policyField := policyV.Field(i)
		clientField := clientV.FieldByName(fieldName)
		if !clientField.IsValid() {
			continue
		}

		applyMethod := policyField.MethodByName("apply")
		if !applyMethod.IsValid() {
			continue
		}

		result := applyMethod.Call([]reflect.Value{clientField})
		if !result[1].IsNil() {
			return goidc.ClientMeta{}, result[1].Interface().(error)
		}

		clientField.Set(result[0])
	}

	// Handle ScopeIDs specially ([]string in policy, space-separated string in client).
	scopeIDs := strutil.SplitWithSpaces(c.ScopeIDs)
	scopeIDs, err := policy.ScopeIDs.apply(scopeIDs)
	if err != nil {
		return goidc.ClientMeta{}, err
	}
	c.ScopeIDs = strings.Join(scopeIDs, " ")

	for att, ops := range policy.CustomAttributes {
		attValue, err := ops.apply(c.CustomAttribute(att))
		if err != nil {
			return goidc.ClientMeta{}, err
		}
		c.SetCustomAttribute(att, attValue)
	}

	return c, nil
}
