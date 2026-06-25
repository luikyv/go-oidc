package goidc

import (
	"context"
	"crypto"
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

type VCPreAuthCodeOptions struct {
	Issuer string
	TxCode string
}

type VCPreAuthCodeResult struct {
	Subject          string
	ConfigurationIDs map[VCConfigurationID][]VCCredentialID // TODO: Should it be a slice?
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

type VCConfigurationID string

type VCCredentialID string

type VCFormat string

const (
	VCFormatDCSDJWT VCFormat = "dc+sd-jwt"
)

type VCConfiguration struct {
	Format           VCFormat
	Scope            Scope
	SigAlgs          []SignatureAlgorithm
	BindingMethods   []VCBindingMethod
	ProofTypes       map[VCProofType]VCProofConfiguration
	Issue            VCIssueCredentialFunc
	CustomAttributes map[string]any
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
	Configurations map[VCConfigurationID]VCConfiguration
}

type VCBindingMethod string

const (
	VCBindingMethodJWK     VCBindingMethod = "jwk"
	VCBindingMethodCOSEKey VCBindingMethod = "cose_key"
)

type VCIssuanceOptions struct {
	CredentialID VCCredentialID
	ProofKey     crypto.PublicKey
}

type VCIssueCredentialFunc func(context.Context, *Grant, VCIssuanceOptions) (string, error)
