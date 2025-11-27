package oidc

import (
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
	JWKSFunc      goidc.JWKSFunc
	SignerFunc    goidc.SignerFunc
	DecrypterFunc goidc.DecrypterFunc

	HandleGrantFunc         goidc.HandleGrantFunc
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
	RenderErrorFunc      goidc.RenderErrorFunc
	NotifyErrorFunc      goidc.NotifyErrorFunc

	TokenAuthnMethods []goidc.ClientAuthnType
	TokenEndpoint     string
	TokenOptionsFunc  goidc.TokenOptionsFunc
	// TokenBindingIsRequired indicates that at least one mechanism of sender
	// contraining tokens is required, either DPoP or client TLS.
	TokenBindingIsRequired bool

	WellKnownEndpoint     string
	JWKSEndpoint          string
	AuthorizationEndpoint string
	EndpointPrefix        string

	UserInfoEndpoint             string
	UserInfoDefaultSigAlg        goidc.SignatureAlgorithm
	UserInfoSigAlgs              []goidc.SignatureAlgorithm
	UserInfoEncIsEnabled         bool
	UserInfoKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	UserInfoDefaultContentEncAlg goidc.ContentEncryptionAlgorithm
	UserInfoContentEncAlgs       []goidc.ContentEncryptionAlgorithm

	IDTokenDefaultSigAlg        goidc.SignatureAlgorithm
	IDTokenSigAlgs              []goidc.SignatureAlgorithm
	IDTokenEncIsEnabled         bool
	IDTokenKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	IDTokenDefaultContentEncAlg goidc.ContentEncryptionAlgorithm
	IDTokenContentEncAlgs       []goidc.ContentEncryptionAlgorithm
	// IDTokenLifetimeSecs defines the expiry time of ID tokens.
	IDTokenLifetimeSecs int

	// PrivateKeyJWTSigAlgs contains algorithms accepted for signing
	// client assertions during private_key_jwt.
	PrivateKeyJWTSigAlgs []goidc.SignatureAlgorithm
	// ClientSecretJWTSigAlgs constains algorithms accepted for
	// signing client assertions during client_secret_jwt.
	ClientSecretJWTSigAlgs []goidc.SignatureAlgorithm

	JWTLifetimeSecs   int
	JWTLeewayTimeSecs int

	DCRIsEnabled                   bool
	DCREndpoint                    string
	DCRTokenRotationIsEnabled      bool
	HandleDynamicClientFunc        goidc.HandleDynamicClientFunc
	ValidateInitialAccessTokenFunc goidc.ValidateInitialAccessTokenFunc
	ClientIDFunc                   goidc.ClientIDFunc

	TokenIntrospectionIsEnabled           bool
	IntrospectionEndpoint                 string
	TokenIntrospectionAuthnMethods        []goidc.ClientAuthnType
	IsClientAllowedTokenIntrospectionFunc goidc.IsClientAllowedTokenInstrospectionFunc

	TokenRevocationIsEnabled           bool
	TokenRevocationEndpoint            string
	TokenRevocationAuthnMethods        []goidc.ClientAuthnType
	IsClientAllowedTokenRevocationFunc goidc.IsClientAllowedFunc

	ShouldIssueRefreshTokenFunc   goidc.ShouldIssueRefreshTokenFunc
	RefreshTokenRotationIsEnabled bool
	RefreshTokenLifetimeSecs      int

	JARMIsEnabled     bool
	JARMDefaultSigAlg goidc.SignatureAlgorithm
	JARMSigAlgs       []goidc.SignatureAlgorithm
	// JARMLifetimeSecs defines how long response objects are valid for.
	JARMLifetimeSecs         int
	JARMEncIsEnabled         bool
	JARMKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	JARMDefaultContentEncAlg goidc.ContentEncryptionAlgorithm
	JARMContentEncAlgs       []goidc.ContentEncryptionAlgorithm

	JARIsEnabled  bool
	JARIsRequired bool
	JARSigAlgs    []goidc.SignatureAlgorithm
	// JARByReferenceIsEnabled determines whether Request Objects can be provided
	// by reference using the "request_uri" parameter. When enabled, the authorization
	// server retrieves the request object from the specified URI.
	JARByReferenceIsEnabled             bool
	JARRequestURIRegistrationIsRequired bool
	JAREncIsEnabled                     bool
	JARKeyEncAlgs                       []goidc.KeyEncryptionAlgorithm
	JARContentEncAlgs                   []goidc.ContentEncryptionAlgorithm

	// PARIsEnabled allows client to push authorization requests.
	PARIsEnabled bool
	// PARIsRequired indicates that authorization requests can only be made if
	// they were pushed.
	PARIsRequired        bool
	PAREndpoint          string
	HandlePARSessionFunc goidc.HandleSessionFunc
	PARLifetimeSecs      int
	// PARAllowUnregisteredRedirectURI indicates whether the redirect URIs
	// informed during PAR must be previously registered or not.
	PARAllowUnregisteredRedirectURI bool

	CIBAIsEnabled                  bool
	CIBAEndpoint                   string
	CIBATokenDeliveryModels        []goidc.CIBATokenDeliveryMode
	InitBackAuthFunc               goidc.InitBackAuthFunc
	ValidateBackAuthFunc           goidc.ValidateBackAuthFunc
	CIBAUserCodeIsEnabled          bool
	CIBADefaultSessionLifetimeSecs int
	CIBAPollingIntervalSecs        int

	CIBAJARIsEnabled  bool
	CIBAJARIsRequired bool
	CIBAJARSigAlgs    []goidc.SignatureAlgorithm

	MTLSIsEnabled              bool
	MTLSHost                   string
	MTLSTokenBindingIsEnabled  bool
	MTLSTokenBindingIsRequired bool
	ClientCertFunc             goidc.ClientCertFunc

	DPoPIsEnabled  bool
	DPoPIsRequired bool
	DPoPSigAlgs    []goidc.SignatureAlgorithm

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

	OpenIDFedIsEnabled              bool
	OpenIDFedEndpoint               string
	OpenIDFedJWKSFunc               goidc.JWKSFunc
	OpenIDFedSignerFunc             goidc.SignerFunc
	OpenIDFedAuthorityHints         []string
	OpenIDFedTrustedAuthorities     []string
	OpenIDFedEntityStatementSigAlgs []goidc.SignatureAlgorithm
	OpenIDFedTrustChainMaxDepth     int
	OpenIDFedClientFunc             func(Context, string) (*goidc.Client, error)
	OpenIDFedClientRegTypes         []goidc.ClientRegistrationType
	OpenIDFedRequiredTrustMarksFunc goidc.RequiredTrustMarksFunc
	OpenIDFedTrustMarkSigAlgs       []goidc.SignatureAlgorithm

	LogoutIsEnabled             bool
	LogoutEndpoint              string
	LogoutSessionManager        goidc.LogoutSessionManager
	LogoutSessionTimeoutSecs    int
	LogoutPolicies              []goidc.LogoutPolicy
	HandleDefaultPostLogoutFunc goidc.HandleDefaultPostLogoutFunc
}
