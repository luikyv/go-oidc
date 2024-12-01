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

	// JWKSFunc retrieves the server's JWKS.
	// The returned JWKS must include private keys if SignFunc or DecryptFunc
	// (when server-side encryption is enabled) are not provided.
	// When exposing it at the jwks endpoint, any private information is removed.
	JWKSFunc goidc.JWKSFunc
	// SignFunc performs signing operations for the server.
	SignFunc goidc.SignFunc
	// DecryptFunc handles decryption when server-side encryption is enabled.
	DecryptFunc goidc.DecryptFunc

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
	Claims                    []string
	ClaimTypes                []goidc.ClaimType
	DefaultSubIdentifierType  goidc.SubIdentifierType
	SubIdentifierTypes        []goidc.SubIdentifierType
	GeneratePairwiseSubIDFunc goidc.GeneratePairwiseSubIDFunc
	StaticClients             []*goidc.Client
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
	NotifyErrorFunc        goidc.NotifyErrorFunc

	EndpointWellKnown           string
	EndpointJWKS                string
	EndpointToken               string
	EndpointAuthorize           string
	EndpointPushedAuthorization string
	EndpointCIBA                string
	EndpointDCR                 string
	EndpointUserInfo            string
	EndpointIntrospection       string
	EndpointTokenRevocation     string
	EndpointPrefix              string

	UserInfoDefaultSigAlg        jose.SignatureAlgorithm
	UserInfoSigAlgs              []jose.SignatureAlgorithm
	UserInfoEncIsEnabled         bool
	UserInfoKeyEncAlgs           []jose.KeyAlgorithm
	UserInfoDefaultContentEncAlg jose.ContentEncryption
	UserInfoContentEncAlgs       []jose.ContentEncryption

	IDTokenDefaultSigAlg        jose.SignatureAlgorithm
	IDTokenSigAlgs              []jose.SignatureAlgorithm
	IDTokenEncIsEnabled         bool
	IDTokenKeyEncAlgs           []jose.KeyAlgorithm
	IDTokenDefaultContentEncAlg jose.ContentEncryption
	IDTokenContentEncAlgs       []jose.ContentEncryption
	// IDTokenLifetimeSecs defines the expiry time of ID tokens.
	IDTokenLifetimeSecs int

	TokenAuthnMethods []goidc.ClientAuthnType

	// PrivateKeyJWTSigAlgs contains algorithms accepted for signing
	// client assertions during private_key_jwt.
	PrivateKeyJWTSigAlgs []jose.SignatureAlgorithm
	// ClientSecretJWTSigAlgs constains algorithms accepted for
	// signing client assertions during client_secret_jwt.
	ClientSecretJWTSigAlgs []jose.SignatureAlgorithm

	JWTLifetimeSecs   int
	JWTLeewayTimeSecs int

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

	JARIsEnabled  bool
	JARIsRequired bool
	JARSigAlgs    []jose.SignatureAlgorithm
	// JARByReferenceIsEnabled determines whether Request Objects can be provided
	// by reference using the "request_uri" parameter. When enabled, the authorization
	// server retrieves the request object from the specified URI.
	JARByReferenceIsEnabled             bool
	JARRequestURIRegistrationIsRequired bool
	JAREncIsEnabled                     bool
	JARKeyEncAlgs                       []jose.KeyAlgorithm
	JARContentEncAlgs                   []jose.ContentEncryption

	// PARIsEnabled allows client to push authorization requests.
	PARIsEnabled bool
	// PARIsRequired indicates that authorization requests can only be made if
	// they were pushed.
	PARIsRequired   bool
	PARLifetimeSecs int
	// PARAllowUnregisteredRedirectURI indicates whether the redirect URIs
	// informed during PAR must be previously registered or not.
	PARAllowUnregisteredRedirectURI bool

	CIBAIsEnabled                  bool
	CIBATokenDeliveryModels        []goidc.CIBATokenDeliveryMode
	InitBackAuthFunc               goidc.InitBackAuthFunc
	ValidateBackAuthFunc           goidc.ValidateBackAuthFunc
	CIBAUserCodeIsEnabled          bool
	CIBADefaultSessionLifetimeSecs int
	CIBAPollingIntervalSecs        int

	CIBAJARIsEnabled  bool
	CIBAJARIsRequired bool
	CIBAJARSigAlgs    []jose.SignatureAlgorithm

	MTLSIsEnabled              bool
	MTLSHost                   string
	MTLSTokenBindingIsEnabled  bool
	MTLSTokenBindingIsRequired bool
	ClientCertFunc             goidc.ClientCertFunc

	DPoPIsEnabled  bool
	DPoPIsRequired bool
	DPoPSigAlgs    []jose.SignatureAlgorithm

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

	ErrorURI string
}
