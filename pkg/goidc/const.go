package goidc

import (
	"slices"
	"strings"
)

const (
	EndpointWellKnown                  = "/.well-known/openid-configuration"
	EndpointJSONWebKeySet              = "/jwks"
	EndpointPushedAuthorizationRequest = "/par"
	EndpointAuthorize                  = "/authorize"
	EndpointToken                      = "/token"
	EndpointUserInfo                   = "/userinfo"
	EndpointDynamicClient              = "/register"
	EndpointTokenIntrospection         = "/introspect"
)

type Profile string

const (
	ProfileOpenID Profile = "oidc_profile"
	ProfileFAPI2  Profile = "fapi2_profile"
)

type GrantType string

const (
	GrantClientCredentials GrantType = "client_credentials"
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantImplicit          GrantType = "implicit"
	GrantIntrospection     GrantType = "urn:goidc:oauth2:grant_type:token_intropection"
)

type ResponseType string

const (
	ResponseTypeCode                   ResponseType = "code"
	ResponseTypeIDToken                ResponseType = "id_token"
	ResponseTypeToken                  ResponseType = "token"
	ResponseTypeCodeAndIDToken         ResponseType = "code id_token"
	ResponseTypeCodeAndToken           ResponseType = "code token"
	ResponseTypeIDTokenAndToken        ResponseType = "id_token token"
	ResponseTypeCodeAndIDTokenAndToken ResponseType = "code id_token token"
)

func (rt ResponseType) Contains(responseType ResponseType) bool {
	return slices.Contains(strings.Split(string(rt), " "), string(responseType))
}

func (rt ResponseType) IsImplicit() bool {
	return rt.Contains(ResponseTypeIDToken) || rt.Contains(ResponseTypeToken)
}

type ResponseMode string

const (
	ResponseModeQuery       ResponseMode = "query"
	ResponseModeFragment    ResponseMode = "fragment"
	ResponseModeFormPost    ResponseMode = "form_post"
	ResponseModeQueryJWT    ResponseMode = "query.jwt"
	ResponseModeFragmentJWT ResponseMode = "fragment.jwt"
	ResponseModeFormPostJWT ResponseMode = "form_post.jwt"
	ResponseModeJWT         ResponseMode = "jwt"
)

func (rm ResponseMode) IsJARM() bool {
	return rm == ResponseModeQueryJWT || rm == ResponseModeFragmentJWT ||
		rm == ResponseModeFormPostJWT || rm == ResponseModeJWT
}

func (rm ResponseMode) IsPlain() bool {
	return rm == ResponseModeQuery || rm == ResponseModeFragment ||
		rm == ResponseModeFormPost
}

func (rm ResponseMode) IsQuery() bool {
	return rm == ResponseModeQuery || rm == ResponseModeQueryJWT
}

type ClientAuthnType string

const (
	ClientAuthnNone          ClientAuthnType = "none"
	ClientAuthnSecretBasic   ClientAuthnType = "client_secret_basic"
	ClientAuthnSecretPost    ClientAuthnType = "client_secret_post"
	ClientAuthnSecretJWT     ClientAuthnType = "client_secret_jwt"
	ClientAuthnPrivateKeyJWT ClientAuthnType = "private_key_jwt"
	ClientAuthnTLS           ClientAuthnType = "tls_client_auth"
	ClientAuthnSelfSignedTLS ClientAuthnType = "self_signed_tls_client_auth"
)

type ClientAssertionType string

const (
	AssertionTypeJWTBearer ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeDPoP   TokenType = "DPoP"
)

const (
	ClaimTokenID                        string = "jti"
	ClaimIssuer                         string = "iss"
	ClaimSubject                        string = "sub"
	ClaimAudience                       string = "aud"
	ClaimClientID                       string = "client_id"
	ClaimExpiry                         string = "exp"
	ClaimIssuedAt                       string = "iat"
	ClaimScope                          string = "scope"
	ClaimNonce                          string = "nonce"
	ClaimAuthenticationTime             string = "auth_time"
	ClaimAuthenticationMethodReferences string = "amr"
	ClaimAuthenticationContextReference string = "acr"
	ClaimProfile                        string = "profile"
	ClaimEmail                          string = "email"
	ClaimEmailVerified                  string = "email_verified"
	ClaimAddress                        string = "address"
	ClaimAuthorizationDetails           string = "authorization_details"
	ClaimAccessTokenHash                string = "at_hash"
	ClaimAuthorizationCodeHash          string = "c_hash"
	ClaimStateHash                      string = "s_hash"
)

type KeyUsage string

const (
	KeyUsageSignature  KeyUsage = "sig"
	KeyUsageEncryption KeyUsage = "enc"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodSHA256 CodeChallengeMethod = "S256"
	CodeChallengeMethodPlain  CodeChallengeMethod = "plain"
)

// SubjectIdentifierType defines how the auth server provides subject
// identifiers to its clients.
// For more information,
// see: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
type SubjectIdentifierType string

const (
	// SubjectIdentifierPublic makes the server provide the same subject
	// identifier to all clients.
	SubjectIdentifierPublic SubjectIdentifierType = "public"
	// TODO: Implement pairwise.
)

const (
	HeaderDPoP string = "DPoP"
	// HeaderClientCertificate is the header used to transmit a client
	// certificate that was validated by a trusted source.
	// The value in this header is expected to be the URL encoding of the
	// client's certificate in PEM format.
	HeaderClientCertificate string = "X-Client-Cert"
)

type AuthnStatus string

const (
	StatusSuccess    AuthnStatus = "success"
	StatusInProgress AuthnStatus = "in_progress"
	StatusFailure    AuthnStatus = "failure"
)

type TokenFormat string

const (
	TokenFormatJWT    TokenFormat = "jwt"
	TokenFormatOpaque TokenFormat = "opaque"
)

// AMR defines a type for authentication method references.
type AMR string

const (
	AMRFacialRecognition            AMR = "face"
	AMRFingerPrint                  AMR = "fpt"
	AMRGeolocation                  AMR = "geo"
	AMRHardwareSecuredKey           AMR = "hwk"
	AMRIrisScan                     AMR = "iris"
	AMRMultipleFactor               AMR = "mfa"
	AMROneTimePassoword             AMR = "otp"
	AMRPassword                     AMR = "pwd"
	AMRPersonalIDentificationNumber AMR = "pin"
	AMRRiskBased                    AMR = "rba"
	AMRSMS                          AMR = "sms"
	AMRSoftwareSecuredKey           AMR = "swk"
)

type DisplayValue string

const (
	DisplayValuePage  DisplayValue = "page"
	DisplayValuePopUp DisplayValue = "popup"
	DisplayValueTouch DisplayValue = "touch"
	DisplayValueWAP   DisplayValue = "wap"
)

type PromptType string

const (
	PromptTypeNone          PromptType = "none"
	PromptTypeLogin         PromptType = "login"
	PromptTypeConsent       PromptType = "consent"
	PromptTypeSelectAccount PromptType = "select_account"
)

type ClaimType string

const (
	ClaimTypeNormal      ClaimType = "normal"
	ClaimTypeAggregated  ClaimType = "aggregated"
	ClaimTypeDistributed ClaimType = "distributed"
)

type TokenTypeHint string

const (
	TokenHintAccess  TokenTypeHint = "access_token"
	TokenHintRefresh TokenTypeHint = "refresh_token"
)

// ACR defines a type for authentication context references.
type ACR string

const (
	ACRNoAssuranceLevel      ACR = "0"
	ACRMaceIncommonIAPSilver ACR = "urn:mace:incommon:iap:silver"
	ACRMaceIncommonIAPBronze ACR = "urn:mace:incommon:iap:bronze"
)
