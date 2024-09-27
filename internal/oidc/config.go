package oidc

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Configuration struct {
	ClientManager       goidc.ClientManager
	AuthnSessionManager goidc.AuthnSessionManager
	GrantSessionManager goidc.GrantSessionManager

	Profile goidc.Profile
	// Host is the domain where the server runs. This value will be used as the
	// authorization server issuer.
	Host string
	// PrivateJWKS contains the server JWKS with private and public information.
	// When exposing it, the private information is removed.
	PrivateJWKS             jose.JSONWebKeySet
	HandleGrantFunc         goidc.HandleGrantFunc
	TokenOptionsFunc        goidc.TokenOptionsFunc
	Policies                []goidc.AuthnPolicy
	Scopes                  []goidc.Scope
	OpenIDIsRequired        bool
	GrantTypes              []goidc.GrantType
	ResponseTypes           []goidc.ResponseType
	ResponseModes           []goidc.ResponseMode
	AuthnSessionTimeoutSecs int
	ACRs                    []goidc.ACR
	DisplayValues           []goidc.DisplayValue
	// Claims defines the user claims that can be returned in the userinfo
	// endpoint or in ID tokens.
	// This will be published in the /.well-known/openid-configuration endpoint.
	Claims             []string
	ClaimTypes         []goidc.ClaimType
	SubIdentifierTypes []goidc.SubjectIdentifierType
	StaticClients      []*goidc.Client
	// IssuerRespParamIsEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerRespParamIsEnabled bool
	// ClaimsParamIsEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParamIsEnabled bool
	// TokenBindingIsRequired indicates that at least one mechanism of sender
	// contraining tokens is required, either DPoP or client TLS.
	TokenBindingIsRequired bool
	RenderErrorFunc        goidc.RenderErrorFunc
	HandleErrorFunc        goidc.HandleErrorFunc

	EndpointWellKnown           string
	EndpointJWKS                string
	EndpointToken               string
	EndpointAuthorize           string
	EndpointPushedAuthorization string
	EndpointDCR                 string
	EndpointUserInfo            string
	EndpointIntrospection       string
	EndpointTokenRevocation     string
	EndpointPrefix              string

	// DefaultSigKeyID defines the default key used to sign ID
	// tokens and the user info endpoint response.
	// The key can be overridden depending on the client properties
	// "id_token_signed_response_alg" and "userinfo_signed_response_alg".
	UserDefaultSigKeyID string
	// SigKeyIDs contains the IDs of the keys used to sign ID tokens
	// and the user info endpoint response.
	// There should be at most one per algorithm, in other words, there should
	// not be two key IDs that point to two keys that have the same algorithm.
	UserSigKeyIDs            []string
	UserEncIsEnabled         bool
	UserKeyEncAlgs           []jose.KeyAlgorithm
	UserDefaultContentEncAlg jose.ContentEncryption
	UserContentEncAlgs       []jose.ContentEncryption
	// IDTokenLifetimeSecs defines the expiry time of ID tokens.
	IDTokenLifetimeSecs int

	ClientAuthnMethods []goidc.ClientAuthnType
	// PrivateKeyJWTSigAlgs contains algorithms accepted for signing
	// client assertions during private_key_jwt.
	PrivateKeyJWTSigAlgs []jose.SignatureAlgorithm
	// ClientSecretJWTSigAlgs constains algorithms accepted for
	// signing client assertions during client_secret_jwt.
	ClientSecretJWTSigAlgs []jose.SignatureAlgorithm
	// AssertionLifetimeSecs is used to validate that the client assertions
	// will expire in the near future during private_key_jwt and
	// client_secret_jwt.
	AssertionLifetimeSecs int

	DCRIsEnabled              bool
	DCRTokenRotationIsEnabled bool
	HandleDynamicClientFunc   goidc.HandleDynamicClientFunc

	IntrospectionIsEnabled          bool
	IntrospectionClientAuthnMethods []goidc.ClientAuthnType

	TokenRevocationIsEnabled bool

	ShouldIssueRefreshTokenFunc   goidc.ShouldIssueRefreshTokenFunc
	RefreshTokenRotationIsEnabled bool
	RefreshTokenLifetimeSecs      int

	JARMIsEnabled bool
	// JARMDefaultSigKeyID indicates the key that will be used to sign the
	// response object if the client doesn't have an algorithm defined.
	JARMDefaultSigKeyID string
	// JARMSigKeyIDs indicates all the keys available to sign the response object.
	JARMSigKeyIDs []string
	// JARMLifetimeSecs defines how long response objects are valid for.
	JARMLifetimeSecs         int
	JARMEncIsEnabled         bool
	JARMKeyEncAlgs           []jose.KeyAlgorithm
	JARMDefaultContentEncAlg jose.ContentEncryption
	JARMContentEncAlgs       []jose.ContentEncryption

	JARIsEnabled  bool
	JARIsRequired bool
	JARSigAlgs    []jose.SignatureAlgorithm
	// JARLifetimeSecs defines the max difference allowed between the claims "iat"
	// and "exp" for request objects.
	JARLifetimeSecs         int
	JARLeewayTimeSecs       int
	JAREncIsEnabled         bool
	JARKeyEncIDs            []string
	JARDefaultContentEncAlg jose.ContentEncryption
	JARContentEncAlgs       []jose.ContentEncryption

	// PARIsEnabled allows client to push authorization requests.
	PARIsEnabled bool
	// PARIsRequired indicates that authorization requests can only be made if
	// they were pushed.
	PARIsRequired   bool
	PARLifetimeSecs int
	// PARAllowUnregisteredRedirectURI indicates whether the redirect URIs
	// informed during PAR must be previously registered or not.
	PARAllowUnregisteredRedirectURI bool

	MTLSIsEnabled              bool
	MTLSHost                   string
	MTLSTokenBindingIsEnabled  bool
	MTLSTokenBindingIsRequired bool
	ClientCertFunc             goidc.ClientCertFunc

	DPoPIsEnabled      bool
	DPoPIsRequired     bool
	DPoPLifetimeSecs   int
	DPoPLeewayTimeSecs int
	DPoPSigAlgs        []jose.SignatureAlgorithm

	PKCEIsEnabled              bool
	PKCEIsRequired             bool
	PKCEDefaultChallengeMethod goidc.CodeChallengeMethod
	PKCEChallengeMethods       []goidc.CodeChallengeMethod

	AuthDetailsIsEnabled bool // TODO: Allow custom comparison.
	AuthDetailTypes      []string

	ResourceIndicatorsIsEnabled  bool
	ResourceIndicatorsIsRequired bool
	Resources                    []string

	HTTPClientFunc goidc.HTTPClientFunc
}
