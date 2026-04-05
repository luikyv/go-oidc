package goidc

import "context"

type VCHandlePreAuthCodeFunc func(ctx context.Context, code string, opts VCPreAuthCodeOptions) (VCPreAuthCodeResult, error)

type VCPreAuthCodeOptions struct {
	Issuer string
	TxCode string
}

type VCPreAuthCodeResult struct {
	Subject          string
	ConfigurationIDs map[VCConfigurationID][]VCCredentialID
}

type VCManager interface {
	SaveOffer(context.Context, *VCOffer) error
	Offer(context.Context, string) (*VCOffer, error)
	OfferByPreAuthCode(context.Context, string) (*VCOffer, error)
}

type VCOffer struct {
	ID                 string              `json:"id"`
	ConfigurationIDs   []VCConfigurationID `json:"credential_configuration_ids"`
	Grants             VCOfferGrants       `json:"grants,omitzero"`
	ExpiresAtTimestamp int                 `json:"expires_at"`
	CreatedAtTimestamp int                 `json:"created_at"`
}

type VCOfferGrants struct {
	AuthCode    *VCOfferGrantAuthCode    `json:"authorization_code,omitempty"`
	PreAuthCode *VCOfferGrantPreAuthCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

type VCOfferGrantAuthCode struct {
	IssuerState string `json:"issuer_state,omitempty"`
	AuthServer  string `json:"authorization_server,omitempty"`
}

type VCOfferGrantPreAuthCode struct {
	Code       string             `json:"pre-authorized_code"`
	TxCode     *VCTransactionCode `json:"tx_code,omitempty"`
	AuthServer string             `json:"authorization_server,omitempty"`
}

type VCTransactionCode struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      string `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

type VCOfferOptions struct {
	ByReference      bool
	ConfigurationIDs []VCConfigurationID
	GrantAuthCode    *VCOfferGrantAuthCodeOptions
	GrantPreAuthCode *VCOfferGrantPreAuthCodeOptions
}

type VCOfferGrantAuthCodeOptions struct {
	IssuerState string
	AuthServer  string
}

type VCOfferGrantPreAuthCodeOptions struct {
	Code       string
	TxCode     *VCTransactionCode
	AuthServer string
}

type VCConfigurationID string

type VCCredentialID string

type VCConfiguration struct {
	Scope Scope
}

type VCIssuer struct {
	ID             string
	Configurations map[VCConfigurationID]VCConfiguration
}
