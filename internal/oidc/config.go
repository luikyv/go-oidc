package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Configuration struct {
	GrantManager goidc.GrantManager

	Profile goidc.Profile
	// Host is the domain where the server runs. This value will be used as the
	// authorization server issuer.
	Host string

	AuthManager          goidc.AuthManager
	AuthTimeoutSecs      int
	AuthCodeFunc         goidc.RandomFunc
	AuthCodeLifetimeSecs int
	AuthSessionIDFunc    goidc.RandomFunc

	// JWKSFunc retrieves the server's JWKS.
	// The returned JWKS must include private keys if SignFunc or DecryptFunc
	// (when server-side encryption is enabled) are not provided.
	// When exposing it at the jwks endpoint, any private information is removed.
	JWKSFunc      goidc.JWKSFunc
	SignerFunc    goidc.SignerFunc
	DecrypterFunc goidc.DecrypterFunc

	HandleGrantFunc    goidc.HandleGrantFunc
	HandleTokenFunc    goidc.HandleTokenFunc
	IDTokenClaimsFunc  goidc.IDTokenClaimsFunc
	UserInfoClaimsFunc goidc.UserInfoClaimsFunc
	TokenClaimsFunc    goidc.TokenClaimsFunc
	Policies           []goidc.AuthnPolicy
	Scopes             []goidc.Scope
	OpenIDIsRequired   bool
	GrantTypes         []goidc.GrantType
	ResponseTypes      []goidc.ResponseType
	ResponseModes      []goidc.ResponseMode
	GrantIDFunc        goidc.RandomFunc
	ACRs               []goidc.ACR
	DisplayValues      []goidc.DisplayValue
	// Claims defines the user claims that can be returned in the userinfo endpoint or in ID tokens.
	// This will be published in the /.well-known/openid-configuration endpoint.
	Claims                   []string
	ClaimTypes               []goidc.ClaimType
	SubIdentifierTypeDefault goidc.SubIdentifierType
	SubIdentifierTypes       []goidc.SubIdentifierType
	PairwiseSubjectFunc      goidc.PairwiseSubjectFunc
	StaticClients            []*goidc.Client
	// IssuerRespParamIsEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerRespParamIsEnabled bool
	// ClaimsParamIsEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParamIsEnabled bool
	RenderErrorFunc      goidc.RenderErrorFunc
	HandleErrorFunc      goidc.HandleErrorFunc

	TokenAuthnMethodDefault        goidc.AuthnMethod
	TokenAuthnMethods              []goidc.AuthnMethod
	TokenAuthnPrivateKeyJWTSigAlgs []goidc.SignatureAlgorithm
	TokenAuthnSecretJWTSigAlgs     []goidc.SignatureAlgorithm
	TokenEndpoint                  string
	OpaqueTokenFunc                goidc.OpaqueTokenFunc
	TokenOptionsFunc               goidc.TokenOptionsFunc
	VerifyClientSecretFunc         goidc.VerifyClientSecretFunc
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

	JWTLifetimeSecs   int
	JWTLeewayTimeSecs int
	JWTIDFunc         goidc.RandomFunc

	RPMetadataChoicesIsEnabled bool

	DCRIsEnabled                  bool
	DCRManager                    goidc.DCRManager
	DCREndpoint                   string
	DCRTokenRotationIsEnabled     bool
	DCRHandleClientFunc           goidc.DCRHandleClientFunc
	DCRValidateInitialTokenFunc   goidc.DCRValidateInitialTokenFunc
	DCRRegistrationTokenFunc      goidc.RandomFunc
	LocalhostRedirectURIIsEnabled bool
	DCRClientIDFunc               goidc.ClientIDFunc
	DCRSecretRotationIsEnabled    bool
	DCRSecretLifetimeSecs         int

	TokenIntrospectionIsEnabled           bool
	TokenIntrospectionEndpoint            string
	TokenIntrospectionIsClientAllowedFunc goidc.IsClientAllowedTokenIntrospectionFunc

	TokenRevocationIsEnabled                         bool
	TokenRevocationEndpoint                          string
	TokenRevocationIsClientAllowedFunc               goidc.IsClientAllowedFunc
	TokenRevocationDeleteGrantOnAccessTokenIsEnabled bool

	RefreshTokenManager           goidc.RefreshTokenManager
	RefreshTokenFunc              goidc.RandomFunc
	RefreshTokenShouldIssueFunc   goidc.RefreshTokenShouldIssueFunc
	RefreshTokenRotationIsEnabled bool
	RefreshTokenLifetimeSecs      int

	JARMIsEnabled     bool
	JARMSigAlgDefault goidc.SignatureAlgorithm
	JARMSigAlgs       []goidc.SignatureAlgorithm
	// JARMLifetimeSecs defines how long response objects are valid for.
	JARMLifetimeSecs         int
	JARMEncIsEnabled         bool
	JARMKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	JARMContentEncAlgDefault goidc.ContentEncryptionAlgorithm
	JARMContentEncAlgs       []goidc.ContentEncryptionAlgorithm

	JARIsEnabled  bool
	JARIsRequired bool
	JARSigAlgs    []goidc.SignatureAlgorithm
	// JARByReferenceIsEnabled determines whether Request Objects can be provided
	// by reference using the "request_uri" parameter. When enabled, the authorization
	// server retrieves the request object from the specified URI.
	JARByReferenceIsEnabled                bool
	JARByReferenceUnregisteredURIIsEnabled bool
	JAREncIsEnabled                        bool
	JARKeyEncAlgs                          []goidc.KeyEncryptionAlgorithm
	JARContentEncAlgs                      []goidc.ContentEncryptionAlgorithm

	// PARIsEnabled allows client to push authorization requests.
	PARIsEnabled bool
	// PARIsRequired indicates that authorization requests can only be made if
	// they were pushed.
	PARIsRequired        bool
	PARManager           goidc.PARManager
	PARIDFunc            goidc.RandomFunc
	PAREndpoint          string
	PARHandleSessionFunc goidc.HandleSessionFunc
	PARLifetimeSecs      int
	// PARUnregisteredRedirectURIIsEnabled indicates whether the redirect URIs
	// informed during PAR must be previously registered or not.
	PARUnregisteredRedirectURIIsEnabled bool

	CIBAEndpoint                   string
	CIBAManager                    goidc.CIBAManager
	CIBAProfile                    goidc.CIBAProfile // TODO: Use this.
	CIBATokenDeliveryModes         []goidc.CIBATokenDeliveryMode
	CIBAIDFunc                     goidc.RandomFunc
	CIBAHandleSessionFunc          goidc.HandleSessionFunc
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
	OpenIDFedManager                goidc.OpenIDFedManager
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
	LogoutManager               goidc.LogoutManager
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

	DeviceAuthManager                          goidc.DeviceAuthManager
	DeviceAuthEndpoint                         string
	DeviceAuthVerificationEndpoint             string
	DeviceAuthVerificationURICompleteIsEnabled bool
	DeviceAuthLifetimeSecs                     int
	DeviceAuthPollingIntervalSecs              int
	DeviceCodeFunc                             goidc.RandomFunc
	DeviceAuthGenerateUserCodeFunc             goidc.RandomFunc
	DeviceAuthPromptUserCodeFunc               goidc.RenderFunc
	DeviceAuthRenderConfirmationFunc           goidc.RenderFunc
}
