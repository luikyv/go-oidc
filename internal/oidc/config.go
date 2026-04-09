package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Configuration struct {
	ClientManager       goidc.ClientManager
	AuthnSessionManager goidc.AuthnSessionManager
	GrantManager        goidc.GrantManager
	TokenManager        goidc.TokenManager

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

	HandleGrantFunc            goidc.HandleGrantFunc
	HandleTokenFunc            goidc.HandleTokenFunc
	IDTokenClaimsFunc          goidc.IDTokenClaimsFunc
	UserInfoClaimsFunc         goidc.UserInfoClaimsFunc
	TokenClaimsFunc            goidc.TokenClaimsFunc
	Policies                   []goidc.AuthnPolicy
	Scopes                     []goidc.Scope
	OpenIDIsRequired           bool
	GrantTypes                 []goidc.GrantType
	ResponseTypes              []goidc.ResponseType
	ResponseModes              []goidc.ResponseMode
	AuthnSessionTimeoutSecs    int
	AuthnSessionGenerateIDFunc goidc.RandomFunc
	GrantIDFunc                goidc.RandomFunc
	ACRs                       []goidc.ACR
	DisplayValues              []goidc.DisplayValue
	// Claims defines the user claims that can be returned in the userinfo endpoint or in ID tokens.
	// This will be published in the /.well-known/openid-configuration endpoint.
	Claims                   []string
	ClaimTypes               []goidc.ClaimType
	DefaultSubIdentifierType goidc.SubIdentifierType
	SubIdentifierTypes       []goidc.SubIdentifierType
	PairwiseSubjectFunc      goidc.PairwiseSubjectFunc
	StaticClients            []*goidc.Client
	// IssuerRespParamIsEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerRespParamIsEnabled bool
	// ClaimsParamIsEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParamIsEnabled          bool
	RenderErrorFunc               goidc.RenderErrorFunc
	NotifyErrorFunc               goidc.NotifyErrorFunc
	AuthorizationCodeFunc         goidc.RandomFunc
	AuthorizationCodeLifetimeSecs int
	CallbackIDFunc                goidc.RandomFunc

	TokenAuthnMethods []goidc.AuthnMethod
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
	JWTIDFunc         goidc.RandomFunc

	DCRIsEnabled                  bool
	DCREndpoint                   string
	DCRTokenRotationIsEnabled     bool
	DCRHandleClientFunc           goidc.DCRHandleClientFunc
	DCRValidateInitialTokenFunc   goidc.DCRValidateInitialTokenFunc
	LocalhostRedirectURIIsEnabled bool
	ClientIDFunc                  goidc.ClientIDFunc

	TokenIntrospectionIsEnabled           bool
	IntrospectionEndpoint                 string
	TokenIntrospectionAuthnMethods        []goidc.AuthnMethod
	IsClientAllowedTokenIntrospectionFunc goidc.IsClientAllowedTokenInstrospectionFunc

	TokenRevocationIsEnabled           bool
	TokenRevocationEndpoint            string
	TokenRevocationAuthnMethods        []goidc.AuthnMethod
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
	PARHandleSessionFunc goidc.HandleSessionFunc
	PARLifetimeSecs      int
	// PARUnregisteredRedirectURIIsEnabled indicates whether the redirect URIs
	// informed during PAR must be previously registered or not.
	PARUnregisteredRedirectURIIsEnabled bool
	PARIDFunc                           goidc.RandomFunc

	CIBAEndpoint                   string
	CIBAProfile                    goidc.CIBAProfile // TODO: Use this.
	CIBATokenDeliveryModels        []goidc.CIBATokenDeliveryMode
	CIBAHandleSessionFunc          goidc.HandleSessionFunc
	CIBAUserCodeIsEnabled          bool
	CIBADefaultSessionLifetimeSecs int
	CIBAPollingIntervalSecs        int
	CIBAAuthReqIDFunc              goidc.RandomFunc

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

	RARIsEnabled          bool
	RARDetailTypes        []goidc.AuthDetailType
	RARValidateDetailFunc func(context.Context, goidc.AuthDetail) error
	RARCompareDetailsFunc goidc.RARCompareDetailsFunc

	ResourceIndicatorsIsEnabled bool
	// ResourceIndicatorsIsRequired indicates that the resource parameter is
	// required during authorization requests.
	ResourceIndicatorsIsRequired bool
	Resources                    []string

	HTTPClientFunc goidc.HTTPClientFunc
	CheckJTIFunc   goidc.CheckJTIFunc

	JWTBearerClientAuthnIsRequired bool
	JWTBearerHandleAssertionFunc   goidc.JWTBearerHandleAssertionFunc

	ErrorURI string

	OpenIDFedIsEnabled              bool
	OpenIDFedEndpoint               string
	OpenIDFedRegistrationEndpoint   string
	OpenIDFedJWKSFunc               goidc.JWKSFunc
	OpenIDFedSignerFunc             goidc.SignerFunc
	OpenIDFedAuthorityHints         []string
	OpenIDFedTrustedAnchors         []string
	OpenIDFedDefaultSigAlg          goidc.SignatureAlgorithm
	OpenIDFedSigAlgs                []goidc.SignatureAlgorithm
	OpenIDFedTrustChainMaxDepth     int
	OpenIDFedClientRegTypes         []goidc.ClientRegistrationType
	OpenIDFedRequiredTrustMarksFunc goidc.RequiredTrustMarksFunc
	// OpenIDFedTrustMarks is a map of trust mark type to the trust mark issuer.
	OpenIDFedTrustMarks             map[goidc.TrustMark]string
	OpenIDFedJWKSRepresentations    []goidc.JWKSRepresentation
	OpenIDFedSignedJWKSEndpoint     string
	OpenIDFedSignedJWKSLifetimeSecs int
	OpenIDFedOrganizationName       string
	OpenIDFedHTTPClientFunc         goidc.HTTPClientFunc
	OpenIDFedHandleClientFunc       goidc.HandleClientFunc
	OpenIDFedEntityJWKSFunc         func(ctx Context, id string) (goidc.JSONWebKeySet, error)

	LogoutIsEnabled             bool
	LogoutEndpoint              string
	LogoutSessionManager        goidc.LogoutSessionManager
	LogoutSessionTimeoutSecs    int
	LogoutPolicies              []goidc.LogoutPolicy
	LogoutSessionIDFunc         goidc.RandomFunc
	HandleDefaultPostLogoutFunc goidc.HandleDefaultPostLogoutFunc

	SSFIsEnabled                           bool
	SSFJWKSEndpoint                        string
	SSFEventsSupported                     []goidc.SSFEventType
	SSFDeliveryMethods                     []goidc.SSFDeliveryMethod
	SSFEventStreamManager                  goidc.SSFEventStreamManager
	SSFConfigurationEndpoint               string
	SSFPollingEndpoint                     string
	SSFEventPollManager                    goidc.SSFEventPollManager
	SSFIsStatusManagementEnabled           bool
	SSFStatusEndpoint                      string
	SSFIsSubjectManagementEnabled          bool
	SSFAddSubjectEndpoint                  string
	SSFRemoveSubjectEndpoint               string
	SSFIsVerificationEnabled               bool
	SSFScheduleVerificationEventFunc       goidc.SSFScheduleVerificationEventFunc
	SSFVerificationEndpoint                string
	SSFMinVerificationInterval             int
	SSFCriticalSubjectMembers              []string
	SSFAuthorizationSchemes                []goidc.SSFAuthorizationScheme
	SSFDefaultSubjects                     goidc.SSFDefaultSubject
	SSFJWKSFunc                            goidc.JWKSFunc
	SSFDefaultSigAlg                       goidc.SignatureAlgorithm
	SSFSignerFunc                          goidc.SignerFunc
	SSFAuthenticatedReceiverFunc           goidc.SSFAuthenticatedReceiverFunc
	SSFEventStreamIDFunc                   goidc.RandomFunc
	SSFHTTPClientFunc                      goidc.HTTPClientFunc
	SSFInactivityTimeoutSecs               int
	SSFHandleExpiredEventStreamFunc        goidc.SSFHandleExpiredEventStreamFunc
	SSFMultipleStreamsPerReceiverIsEnabled bool

	VCIsEnabled                           bool
	VCIssuers                             []goidc.VCIssuer
	VCOfferEndpoint                       string
	VCOfferIDFunc                         goidc.RandomFunc
	VCIssuerStateFunc                     goidc.RandomFunc
	VCManager                             goidc.VCManager
	VCHandlePreAuthCodeFunc               goidc.VCHandlePreAuthCodeFunc
	VCPreAuthCodeAnonymousAccessIsEnabled bool
}
