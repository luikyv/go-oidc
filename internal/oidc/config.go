package oidc

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Configuration struct {
	GrantManager goidc.GrantManager
	Profile      goidc.Profile
	// Host is the domain where the server runs. This value will be used as the
	// authorization server issuer.
	Host string

	AuthManager          goidc.AuthManager
	AuthTimeoutSecs      int
	AuthCodeFunc         goidc.RandomFunc
	AuthCodeLifetimeSecs int
	AuthSessionIDFunc    goidc.RandomFunc

	OpaqueTokenEnabled bool
	OpaqueTokenManager goidc.OpaqueTokenManager

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
	AuthPolicies       []goidc.AuthnPolicy
	DevicePolicies     []goidc.AuthnPolicy
	Scopes             []goidc.Scope
	OpenIDRequired     bool
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
	// IssuerRespParamEnabled indicates if the "iss" parameter will be
	// returned when redirecting the user back to the client application.
	IssuerRespParamEnabled bool
	// ClaimsParamEnabled informs the clients whether the server accepts
	// the "claims" parameter.
	// This will be published in the /.well-known/openid-configuration endpoint.
	ClaimsParamEnabled bool
	RenderErrorFunc    goidc.RenderErrorFunc
	HandleErrorFunc    goidc.HandleErrorFunc

	AuthnMethods                     []goidc.AuthnMethod
	AuthnMethodDefault               goidc.AuthnMethod
	AuthnMethodPrivateKeyJWTSigAlgs  []goidc.SignatureAlgorithm
	AuthnMethodSecretJWTSigAlgs      []goidc.SignatureAlgorithm
	AuthnMethodAttestationJWTIssuers []goidc.AttestationIssuer

	TokenEndpoint          string
	OpaqueTokenFunc        goidc.OpaqueTokenFunc
	TokenOptionsFunc       goidc.TokenOptionsFunc
	VerifyClientSecretFunc goidc.VerifyClientSecretFunc
	// TokenBindingRequired indicates that at least one mechanism of sender
	// contraining tokens is required, either DPoP or client TLS.
	TokenBindingRequired bool

	WellKnownEndpoint     string
	JWKSEndpoint          string
	AuthorizationEndpoint string
	EndpointPrefix        string // TODO: Do I need this?

	UserInfoEndpoint             string
	UserInfoDefaultSigAlg        goidc.SignatureAlgorithm
	UserInfoSigAlgs              []goidc.SignatureAlgorithm
	UserInfoEncEnabled           bool
	UserInfoKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	UserInfoDefaultContentEncAlg goidc.ContentEncryptionAlgorithm
	UserInfoContentEncAlgs       []goidc.ContentEncryptionAlgorithm

	IDTokenDefaultSigAlg        goidc.SignatureAlgorithm
	IDTokenSigAlgs              []goidc.SignatureAlgorithm
	IDTokenEncEnabled           bool
	IDTokenKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	IDTokenDefaultContentEncAlg goidc.ContentEncryptionAlgorithm
	IDTokenContentEncAlgs       []goidc.ContentEncryptionAlgorithm
	// IDTokenLifetimeSecs defines the expiry time of ID tokens.
	IDTokenLifetimeSecs int

	JWTLifetimeSecs   int
	JWTLeewayTimeSecs int
	JWTIDFunc         goidc.RandomFunc

	RPMetadataChoicesEnabled bool

	DCREnabled                  bool
	DCRManager                  goidc.DCRManager
	DCREndpoint                 string
	DCRTokenRotationEnabled     bool
	DCRHandleClientFunc         goidc.DCRHandleClientFunc
	DCRValidateInitialTokenFunc goidc.DCRValidateInitialTokenFunc
	DCRRegistrationTokenFunc    goidc.RandomFunc
	LocalhostRedirectURIEnabled bool
	DCRClientIDFunc             goidc.ClientIDFunc
	DCRSecretRotationEnabled    bool
	DCRSecretLifetimeSecs       int

	TokenIntrospectionEnabled             bool
	TokenIntrospectionEndpoint            string
	TokenIntrospectionIsClientAllowedFunc goidc.IsClientAllowedTokenIntrospectionFunc

	TokenRevocationEnabled                         bool
	TokenRevocationEndpoint                        string
	TokenRevocationIsClientAllowedFunc             goidc.IsClientAllowedFunc
	TokenRevocationRevokeGrantOnAccessTokenEnabled bool

	RefreshTokenManager         goidc.RefreshTokenManager
	RefreshTokenFunc            goidc.RandomFunc
	RefreshTokenShouldIssueFunc goidc.RefreshTokenShouldIssueFunc
	RefreshTokenRotationEnabled bool
	RefreshTokenLifetimeSecs    int

	JARMEnabled       bool
	JARMSigAlgDefault goidc.SignatureAlgorithm
	JARMSigAlgs       []goidc.SignatureAlgorithm
	// JARMLifetimeSecs defines how long response objects are valid for.
	JARMLifetimeSecs         int
	JARMEncEnabled           bool
	JARMKeyEncAlgs           []goidc.KeyEncryptionAlgorithm
	JARMContentEncAlgDefault goidc.ContentEncryptionAlgorithm
	JARMContentEncAlgs       []goidc.ContentEncryptionAlgorithm

	JAREnabled  bool
	JARRequired bool
	JARSigAlgs  []goidc.SignatureAlgorithm
	// JARByReferenceEnabled determines whether Request Objects can be provided
	// by reference using the "request_uri" parameter. When enabled, the authorization
	// server retrieves the request object from the specified URI.
	JARByReferenceEnabled                bool
	JARByReferenceUnregisteredURIEnabled bool
	JAREncEnabled                        bool
	JARKeyEncAlgs                        []goidc.KeyEncryptionAlgorithm
	JARContentEncAlgs                    []goidc.ContentEncryptionAlgorithm
	JARByReferenceHTTPClientFunc         goidc.HTTPClientFunc

	// PAREnabled allows client to push authorization requests.
	PAREnabled bool
	// PARRequired indicates that authorization requests can only be made if
	// they were pushed.
	PARRequired          bool
	PARManager           goidc.PARManager
	PARIDFunc            goidc.RandomFunc
	PAREndpoint          string
	PARHandleSessionFunc goidc.HandleSessionFunc
	PARLifetimeSecs      int
	// PARUnregisteredRedirectURIEnabled indicates whether the redirect URIs
	// informed during PAR must be previously registered or not.
	PARUnregisteredRedirectURIEnabled bool

	CIBAEndpoint                   string
	CIBAManager                    goidc.CIBAManager
	CIBAProfile                    goidc.CIBAProfile // TODO: Use this.
	CIBATokenDeliveryModes         []goidc.CIBATokenDeliveryMode
	CIBAIDFunc                     goidc.RandomFunc
	CIBAHandleSessionFunc          goidc.HandleSessionFunc
	CIBAUserCodeEnabled            bool
	CIBADefaultSessionLifetimeSecs int
	CIBAPollingIntervalSecs        int
	CIBAHTTPClientFunc             goidc.HTTPClientFunc

	CIBAJAREnabled  bool
	CIBAJARRequired bool
	CIBAJARSigAlgs  []goidc.SignatureAlgorithm

	MTLSEnabled              bool
	MTLSHost                 string
	MTLSTokenBindingEnabled  bool
	MTLSTokenBindingRequired bool
	ClientCertFunc           goidc.ClientCertFunc

	DPoPEnabled  bool
	DPoPRequired bool
	DPoPSigAlgs  []goidc.SignatureAlgorithm

	PKCEEnabled                bool
	PKCERequired               bool
	PKCEDefaultChallengeMethod goidc.CodeChallengeMethod
	PKCEChallengeMethods       []goidc.CodeChallengeMethod

	RAREnabled            bool
	RARDetailTypes        []goidc.AuthDetailType
	RARValidateDetailFunc func(context.Context, goidc.AuthDetail) error
	RARCompareDetailsFunc goidc.RARCompareDetailsFunc

	ResourceIndicatorsEnabled bool
	// ResourceIndicatorsRequired indicates that the resource parameter is
	// required during authorization requests.
	ResourceIndicatorsRequired bool
	ResourceIndicators         []goidc.ResourceIndicator

	HTTPClientFunc goidc.HTTPClientFunc
	ConsumeJTIFunc goidc.ConsumeJTIFunc

	JWTBearerClientAuthnRequired bool
	JWTBearerHandleAssertionFunc goidc.JWTBearerHandleAssertionFunc

	ErrorURI string

	OpenIDFedEnabled              bool
	OpenIDFedManager              goidc.OpenIDFedManager
	OpenIDFedEndpoint             string
	OpenIDFedRegistrationEndpoint string
	OpenIDFedJWKSFunc             goidc.JWKSFunc
	OpenIDFedSignerFunc           goidc.SignerFunc
	OpenIDFedAuthorityHints       []string
	OpenIDFedTrustedAnchors       []string
	// OpenIDFedSigAlg is the algorithm used to sign the provider's entity configuration.
	// The federation JWKS must contain a key matching this algorithm.
	OpenIDFedSigAlg goidc.SignatureAlgorithm
	// OpenIDFedSigAlgs are the algorithms accepted when parsing and verifying entity
	// statements and trust marks from other federation participants.
	OpenIDFedSigAlgs                      []goidc.SignatureAlgorithm
	OpenIDFedTrustChainMaxDepth           int
	OpenIDFedClientRegTypes               []goidc.ClientRegistrationType
	OpenIDFedRequiredClientTrustMarksFunc goidc.RequiredTrustMarksFunc
	OpenIDFedTrustMarkConfigs             []goidc.TrustMarkConfig
	OpenIDFedJWKSRepresentations          []goidc.JWKSRepresentation
	OpenIDFedSignedJWKSEndpoint           string
	OpenIDFedSignedJWKSLifetimeSecs       int
	OpenIDFedOrganizationName             string
	OpenIDFedHTTPClientFunc               goidc.HTTPClientFunc
	OpenIDFedHandleClientFunc             goidc.HandleClientFunc
	OpenIDFedEntityJWKSFunc               func(ctx Context, id string) (goidc.JSONWebKeySet, error)

	LogoutEnabled               bool
	LogoutEndpoint              string
	LogoutManager               goidc.LogoutManager
	LogoutSessionTimeoutSecs    int
	LogoutPolicies              []goidc.LogoutPolicy
	LogoutSessionIDFunc         goidc.RandomFunc
	HandleDefaultPostLogoutFunc goidc.HandleDefaultPostLogoutFunc

	SSFEnabled                           bool
	SSFJWKSEndpoint                      string
	SSFEventTypes                        []goidc.SSFEventType
	SSFDeliveryMethods                   []goidc.SSFDeliveryMethod
	SSFEventStreamManager                goidc.SSFEventStreamManager
	SSFConfigurationEndpoint             string
	SSFPollingEndpoint                   string
	SSFEventPollManager                  goidc.SSFEventPollManager
	SSFIsStatusManagementEnabled         bool
	SSFStatusEndpoint                    string
	SSFIsSubjectManagementEnabled        bool
	SSFAddSubjectEndpoint                string
	SSFRemoveSubjectEndpoint             string
	SSFIsVerificationEnabled             bool
	SSFScheduleVerificationEventFunc     goidc.SSFScheduleVerificationEventFunc
	SSFVerificationEndpoint              string
	SSFMinVerificationInterval           int
	SSFCriticalSubjectMembers            []string
	SSFAuthorizationSchemes              []goidc.SSFAuthorizationScheme
	SSFDefaultSubjects                   goidc.SSFDefaultSubject
	SSFJWKSFunc                          goidc.JWKSFunc
	SSFDefaultSigAlg                     goidc.SignatureAlgorithm
	SSFSignerFunc                        goidc.SignerFunc
	SSFAuthenticatedReceiverFunc         goidc.SSFAuthenticatedReceiverFunc
	SSFEventStreamIDFunc                 goidc.RandomFunc
	SSFHTTPClientFunc                    goidc.HTTPClientFunc
	SSFInactivityTimeoutSecs             int
	SSFHandleExpiredEventStreamFunc      goidc.SSFHandleExpiredEventStreamFunc
	SSFMultipleStreamsPerReceiverEnabled bool

	VCIEnabled                           bool
	VCIIssuers                           []goidc.VCIssuer
	VCISelfEnabled                       bool
	VCISelfHost                          string
	VCISelfConfigurations                map[goidc.VCConfigurationID]goidc.VCConfiguration
	VCISelfOffersEnabled                 bool
	VCISelfOfferManager                  goidc.VCOfferManager
	VCISelfCredentialEndpoint            string
	VCISelfOfferEndpoint                 string
	VCISelfOfferIDFunc                   goidc.RandomFunc
	VCISelfPreAuthCodeGrantEnabled       bool
	VCISelfPreAuthCodeGrantManager       goidc.VCPreAuthCodeGrantManager
	VCISelfPreAuthCodeFunc               goidc.RandomFunc
	VCISelfPreAuthCodeLifetimeSecs       int
	VCISelfJWTIssuerEnabled              bool
	VCISelfJWTIssuerJWKSFunc             goidc.JWKSFunc
	VCISelfJWTIssuerJWKSURI              string
	VCIExternalPreAuthCodeGrantEnabled   bool
	VCIExternalPreAuthCodeHandleFunc     goidc.VCIPreAuthCodeHandleFunc
	VCIIssuerStateEnabled                bool
	VCIIssuerStateHandleFunc             goidc.VCIIssuerStateHandleFunc
	VCIPreAuthCodeAnonymousAccessEnabled bool

	DeviceAuthManager                        goidc.DeviceAuthManager
	DeviceAuthEndpoint                       string
	DeviceAuthVerificationEndpoint           string
	DeviceAuthVerificationURICompleteEnabled bool
	DeviceAuthLifetimeSecs                   int
	DeviceAuthPollingIntervalSecs            int
	DeviceCodeFunc                           goidc.RandomFunc
	DeviceAuthGenerateUserCodeFunc           goidc.RandomFunc
	DeviceAuthPromptUserCodeFunc             goidc.RenderFunc
	DeviceAuthRenderConfirmationFunc         goidc.RenderFunc

	TokenExchangeClientAuthnRequired bool
	TokenExchangeHandleFunc          goidc.TokenExchangeHandleFunc
}
