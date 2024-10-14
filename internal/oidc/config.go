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

	UserDefaultSigAlg        jose.SignatureAlgorithm
	UserSigAlgs              []jose.SignatureAlgorithm
	UserEncIsEnabled         bool
	UserKeyEncAlgs           []jose.KeyAlgorithm
	UserDefaultContentEncAlg jose.ContentEncryption
	UserContentEncAlgs       []jose.ContentEncryption
	// IDTokenLifetimeSecs defines the expiry time of ID tokens.
	IDTokenLifetimeSecs int

	TokenAuthnMethods []goidc.ClientAuthnType

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

	DCRIsEnabled                   bool
	DCRTokenRotationIsEnabled      bool
	HandleDynamicClientFunc        goidc.HandleDynamicClientFunc
	ValidateInitialAccessTokenFunc goidc.ValidateInitialAccessTokenFunc

	TokenIntrospectionIsEnabled           bool
	TokenIntrospectionAuthnMethods        []goidc.ClientAuthnType
	IsClientAllowedTokenIntrospectionFunc goidc.IsClientAllowedFunc

	TokenRevocationIsEnabled           bool
	TokenRevocationAuthnMethods        []goidc.ClientAuthnType
	IsClientAllowedTokenRevocationFunc goidc.IsClientAllowedFunc

	ShouldIssueRefreshTokenFunc   goidc.ShouldIssueRefreshTokenFunc
	RefreshTokenRotationIsEnabled bool
	RefreshTokenLifetimeSecs      int

	JARMIsEnabled     bool
	JARMDefaultSigAlg jose.SignatureAlgorithm
	JARMSigAlgs       []jose.SignatureAlgorithm
	// JARMLifetimeSecs defines how long response objects are valid for.
	JARMLifetimeSecs         int
	JARMEncIsEnabled         bool
	JARMKeyEncAlgs           []jose.KeyAlgorithm
	JARMDefaultContentEncAlg jose.ContentEncryption
	JARMContentEncAlgs       []jose.ContentEncryption

	JARIsEnabled                        bool
	JARIsRequired                       bool
	JARSigAlgs                          []jose.SignatureAlgorithm
	JARByReferenceIsEnabled             bool
	JARRequestURIRegistrationIsRequired bool
	// JARLifetimeSecs defines the max difference allowed between the claims "iat"
	// and "exp" for request objects.
	JARLifetimeSecs   int
	JARLeewayTimeSecs int
	JAREncIsEnabled   bool
	JARKeyEncAlgs     []jose.KeyAlgorithm
	JARContentEncAlgs []jose.ContentEncryption

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

	AuthDetailsIsEnabled   bool
	AuthDetailTypes        []string
	CompareAuthDetailsFunc goidc.CompareAuthDetailsFunc

	ResourceIndicatorsIsEnabled bool
	// ResourceIndicatorsIsRequired indicates that the resource parameter is
	// required during authorization requests.
	ResourceIndicatorsIsRequired bool
	Resources                    []string

	HTTPClientFunc goidc.HTTPClientFunc
	CheckJTIFunc   goidc.CheckJTIFunc

	JWTBearerGrantClientAuthnIsRequired bool
	HandleJWTBearerGrantAssertionFunc   goidc.HandleJWTBearerGrantAssertionFunc
}
