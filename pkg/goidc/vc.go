package goidc

import (
	"context"
	"crypto/x509"
)

type VCIIssuerStateHandleFunc func(context.Context, string, VCIssuerOptions) (VCIssuerStateResult, error)

type VCIssuerOptions struct {
	Issuer string
}

type VCIssuerStateResult struct {
	ConfigurationIDs []VCConfigurationID
	Store            map[string]any
}

type VCIPreAuthCodeHandleFunc func(context.Context, string, VCPreAuthCodeOptions) (VCPreAuthCodeResult, error)

// VCPreAuthCodeGrantManager resolves grants by pre-authorized code.
type VCPreAuthCodeGrantManager interface {
	// GrantByPreAuthCode returns the grant associated with the pre-authorized
	// code. It must return [ErrNotFound] when the grant does not exist.
	GrantByPreAuthCode(context.Context, string) (*Grant, error)
}

type VCPreAuthCodeOptions struct {
	Issuer string
	TxCode string
}

type VCPreAuthCodeResult struct {
	Subject          string
	ConfigurationIDs map[VCConfigurationID][]VCIdentifier // TODO: Should it be a slice?
	Store            map[string]any
}

// VCOfferManager stores credential offers.
type VCOfferManager interface {
	SaveCredentialOffer(context.Context, *VCOffer) error
	// CredentialOffer returns the offer identified by id.
	// It must return [ErrNotFound] when the offer does not exist.
	CredentialOffer(context.Context, string) (*VCOffer, error)
}

type VCOffer struct {
	ID                 string              `json:"id"`
	ConfigurationIDs   []VCConfigurationID `json:"credential_configuration_ids"`
	Grants             VCOfferGrants       `json:"grants,omitzero"`
	ExpiresAtTimestamp int                 `json:"expires_at"`
	CreatedAtTimestamp int                 `json:"created_at"`
	Store              map[string]any      `json:"store,omitempty"`
}

type VCOfferGrants struct {
	AuthCode    *VCOfferGrantAuthCode    `json:"authorization_code,omitempty"`
	PreAuthCode *VCOfferGrantPreAuthCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

type VCOfferGrantAuthCode struct {
	IssuerState string `json:"issuer_state,omitempty"`
}

type VCOfferGrantPreAuthCode struct {
	Code   string             `json:"pre-authorized_code"`
	TxCode *VCTransactionCode `json:"tx_code,omitempty"`
}

type VCTransactionCode struct {
	InputMode   VCTransactionCodeInputMode `json:"input_mode,omitempty"`
	Length      int                        `json:"length,omitempty"`
	Description string                     `json:"description,omitempty"`
}

type VCTransactionCodeInputMode string

const (
	VCTransactionCodeInputModeNumeric VCTransactionCodeInputMode = "numeric"
	VCTransactionCodeInputModeText    VCTransactionCodeInputMode = "text"
)

type VCOfferOptions struct {
	WalletID         string
	ByReference      bool
	ConfigurationIDs []VCConfigurationID
	GrantAuthCode    *VCOfferGrantAuthCodeOptions
	GrantPreAuthCode *VCOfferGrantPreAuthCodeOptions
}

type VCOfferGrantAuthCodeOptions struct {
	IssuerState string
	AuthServer  string // TODO: Should I allow external auth servers?
}

type VCOfferGrantPreAuthCodeOptions struct {
	Code       string
	TxCode     *VCTransactionCode
	AuthServer string
}

// VCConfigurationID identifies a credential configuration, i.e. the
// credential_configuration_id used in requests and in the
// credential_configurations_supported Credential Issuer metadata.
type VCConfigurationID string

// VCIdentifier identifies a specific credential (dataset) that can be
// issued, i.e. the credential_identifier returned in authorization_details
// and used in credential requests to select it.
type VCIdentifier string

// VCFormat identifies a credential format, as advertised per credential
// configuration in the Credential Issuer metadata. See [OIDC4VCI Appendix A].
type VCFormat string

const (
	VCFormatDCSDJWT VCFormat = "dc+sd-jwt"
)

type VCType string

type VCConfiguration struct {
	// ID identifies this credential configuration, i.e. the
	// credential_configuration_id used in requests and metadata.
	ID             VCConfigurationID
	Format         VCFormat
	Scope          Scope
	SigAlgs        []SignatureAlgorithm
	BindingMethods []VCBindingMethod
	ProofTypes     map[VCProofType]VCProofConfiguration
	Issue          VCIssueCredentialFunc
	// Type identifies the SD-JWT VC type advertised as the "vct" parameter in
	// Credential Issuer metadata. It is required when Format is
	// [VCFormatDCSDJWT]. See [OIDC4VCI Appendix A.3.2].
	Type VCType
	// IsDeferred decides whether a credential request should be deferred
	// instead of issued immediately. It's called once per credential request
	// (never per proof key in a batch) with a freshly built, unsaved
	// [VCDeferral] on the initial request, and with the previously persisted
	// [VCDeferral] on every subsequent poll to the deferred credential
	// endpoint. A nil IsDeferred means this credential configuration never
	// defers.
	IsDeferred VCIsDeferredFunc
}

// VCProofType is the format of the proof of possession of cryptographic key material
// submitted in a credential request. See [OIDC4VCI Appendix F].
type VCProofType string

const (
	VCProofTypeJWT VCProofType = "jwt"
	// VCProofTypeDIVP is the proof type data integrity verifiable presentation.
	VCProofTypeDIVP        VCProofType = "di_vp"
	VCProofTypeAttestation VCProofType = "attestation"
)

type VCProofConfiguration struct {
	SigAlgs      []SignatureAlgorithm
	TrustedRoots *x509.CertPool
}

type VCIssuer struct {
	Issuer         string
	Configurations []VCConfiguration
}

type VCBindingMethod string

const (
	VCBindingMethodJWK     VCBindingMethod = "jwk"
	VCBindingMethodCOSEKey VCBindingMethod = "cose_key"
)

type VCIssuanceOptions struct {
	// CredentialID is optional. It's set when the credential was requested
	// via authorization_details with a credential_identifier, and empty when
	// requested via credential_configuration_id/scope.
	CredentialID VCIdentifier
	// NotificationID identifies the issuance flow for later wallet
	// notifications. It's set when the self credential issuer has the
	// notification endpoint enabled.
	NotificationID string
	// ProofKey is optional. It's nil when no proof of possession was
	// submitted, e.g. because this credential configuration doesn't require
	// one. When present, it's the key the wallet proved possession of and
	// may need to be bound into the issued credential.
	ProofKey *JSONWebKey
}

type VCIssueCredentialFunc func(context.Context, *Grant, VCIssuanceOptions) (string, error)

type VCNotificationEventType string

const (
	VCNotificationEventCredentialAccepted VCNotificationEventType = "credential_accepted" //nolint:gosec
	VCNotificationEventCredentialFailure  VCNotificationEventType = "credential_failure"  //nolint:gosec
	VCNotificationEventCredentialDeleted  VCNotificationEventType = "credential_deleted"  //nolint:gosec
)

type VCNotification struct {
	ID                        string            `json:"id"`
	GrantID                   string            `json:"grant_id"`
	ClientID                  string            `json:"client_id"`
	CredentialConfigurationID VCConfigurationID `json:"credential_configuration_id"`
	CredentialIdentifier      VCIdentifier      `json:"credential_identifier,omitempty"`
	CreatedAt                 int               `json:"created_at"`
}

type VCNotificationEvent struct {
	Type        VCNotificationEventType `json:"event"`
	Description string                  `json:"event_description,omitempty"`
}

type VCNotificationManager interface {
	SaveNotification(context.Context, *VCNotification) error
	Notification(context.Context, string) (*VCNotification, error)
}

type VCNotificationHandleFunc func(context.Context, *VCNotification, VCNotificationEvent) error

type VCDeferral struct {
	ID                        string            `json:"id"`
	GrantID                   string            `json:"grant_id"`
	CredentialConfigurationID VCConfigurationID `json:"credential_configuration_id"`
	CredentialIdentifier      VCIdentifier      `json:"credential_identifier,omitempty"`
	ProofKeys                 []JSONWebKey      `json:"proof_keys,omitempty"`
	CreatedAt                 int               `json:"created_at"`
	// ConsumedAt is populated once the deferral has been resolved and its
	// credential(s) issued, so a repeated poll can be rejected instead of
	// reissuing the credential.
	ConsumedAt int `json:"consumed_at,omitempty"`
	// Store allows [VCIsDeferredFunc] to persist arbitrary state across
	// polls, e.g. an identifier for an external review process.
	Store map[string]any `json:"store,omitempty"`
}

// VCDeferralManager stores deferred credential requests. It's plain storage:
// the decision of whether and for how long a request stays deferred lives in
// [VCIsDeferredFunc], not here.
type VCDeferralManager interface {
	SaveDeferral(context.Context, *VCDeferral) error
	// Deferral returns the deferral identified by id.
	// It must return [ErrNotFound] when the deferral does not exist.
	Deferral(context.Context, string) (*VCDeferral, error)
}

// VCIsDeferredFunc decides whether a credential request should be deferred.
// It's called once per credential request (all proof keys in a batch defer
// or issue together, never partially) on the initial request with a
// freshly built, unsaved deferral, and again on every poll to the deferred
// credential endpoint with the previously persisted deferral. An error fails
// the whole request.
type VCIsDeferredFunc func(context.Context, *Grant, *VCDeferral) (VCDeferralResult, error)

type VCDeferralResult struct {
	// Pending is true when issuance is still not ready: on the initial
	// request it means "defer this"; on a poll it means "keep waiting."
	Pending bool
	// IntervalSecs suggests how long the wallet should wait before polling
	// again. It's only meaningful when Pending is true. A zero value falls
	// back to the provider's default deferred polling interval.
	IntervalSecs int
}
