package vc

type Metadata struct {
	Issuer                     string   `json:"credential_issuer"`
	AuthServers                []string `json:"authorization_servers,omitempty"`
	CredentialEndpoint         string   `json:"credential_endpoint"`
	NonceEndpoint              string   `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint string   `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint       string   `json:"notification_endpoint,omitempty"`
}
