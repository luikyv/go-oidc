package vc

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	jwtTypeProofJWT = "openid4vci-proof+jwt"
)

type metadata struct {
	Issuer                   string   `json:"credential_issuer"`
	CredentialEndpoint       string   `json:"credential_endpoint"`
	AuthorizationServers     []string `json:"authorization_servers,omitempty"`
	CredentialConfigurations map[goidc.VCConfigurationID]struct {
		Format         goidc.VCFormat             `json:"format"`
		Scope          string                     `json:"scope,omitempty"`
		SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
		BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
		ProofTypes     map[goidc.VCProofType]struct {
			SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
		} `json:"proof_types_supported,omitempty"`
	} `json:"credential_configurations_supported"`
}

func newMetadata(ctx oidc.Context) metadata {
	var authServers []string
	if ctx.Host != ctx.VCISelfHost {
		authServers = []string{ctx.Host}
	}

	return metadata{
		Issuer:               ctx.VCISelfHost,
		CredentialEndpoint:   ctx.VCISelfHost + ctx.VCISelfCredentialEndpoint,
		AuthorizationServers: authServers,
		CredentialConfigurations: func() map[goidc.VCConfigurationID]struct {
			Format         goidc.VCFormat             `json:"format"`
			Scope          string                     `json:"scope,omitempty"`
			SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
			BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
			ProofTypes     map[goidc.VCProofType]struct {
				SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
			} `json:"proof_types_supported,omitempty"`
		} {
			configs := make(map[goidc.VCConfigurationID]struct {
				Format         goidc.VCFormat             `json:"format"`
				Scope          string                     `json:"scope,omitempty"`
				SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
				BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
				ProofTypes     map[goidc.VCProofType]struct {
					SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
				} `json:"proof_types_supported,omitempty"`
			}, len(ctx.VCISelfConfigurations))
			for id, c := range ctx.VCISelfConfigurations {
				configs[id] = struct {
					Format         goidc.VCFormat             `json:"format"`
					Scope          string                     `json:"scope,omitempty"`
					SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
					BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
					ProofTypes     map[goidc.VCProofType]struct {
						SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
					} `json:"proof_types_supported,omitempty"`
				}{
					Format:         c.Format,
					Scope:          c.Scope.ID,
					SigAlgs:        c.SigAlgs,
					BindingMethods: c.BindingMethods,
					ProofTypes: func() map[goidc.VCProofType]struct {
						SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
					} {
						proofTypes := make(map[goidc.VCProofType]struct {
							SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
						}, len(c.ProofTypes))
						for pt, pc := range c.ProofTypes {
							proofTypes[pt] = struct {
								SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
							}{SigAlgs: pc.SigAlgs}
						}
						return proofTypes
					}(),
				}
			}
			return configs
		}(),
	}
}

// request represents the credential request at the credential endpoint
// as defined in [OIDC4VCI §8.2].
type request struct {
	// CredentialIdentifier identifies a specific Credential Dataset to be issued.
	// It's required when authorization_details of type openid_credential was returned
	// in the token response. It must not be used together with credential_configuration_id.
	CredentialIdentifier goidc.VCCredentialID `json:"credential_identifier,omitempty"`
	// CredentialConfigurationID identifies the credential configuration to be issued.
	// It's used when only the scope parameter was used in the autho request.
	// It must not be used together with credential_identifier.
	CredentialConfigurationID goidc.VCConfigurationID `json:"credential_configuration_id,omitempty"`
	Proofs                    struct {
		JWT []string `json:"jwt,omitempty"`
	} `json:"proofs,omitzero"`
}

type response struct {
	Credentials []struct {
		Credential string `json:"credential"`
	} `json:"credentials"`
	TransactionID  string `json:"transaction_id,omitempty"`
	Interval       int    `json:"interval,omitempty"`
	NotificationID string `json:"notification_id,omitempty"`
}

func issue(ctx oidc.Context, req request) (response, error) {
	accessToken, _, ok := ctx.AuthorizationToken()
	if !ok {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token", errors.New("authorization bearer token is required"))
	}

	tokenInfo, grant, err := token.Introspect(ctx, accessToken, nil)
	if err != nil {
		return response{}, fmt.Errorf("could not introspect the access token: %w", err)
	}

	if !tokenInfo.IsActive {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token", errors.New("the access token is inactive or expired"))
	}

	if req.CredentialConfigurationID == "" && req.CredentialIdentifier == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
	}

	if req.CredentialIdentifier != "" {
		if req.CredentialConfigurationID != "" {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}

		if slices.ContainsFunc(tokenInfo.AuthDetails, func(detail goidc.AuthDetail) bool {
			return detail.Type() == goidc.AuthDetailTypeOpenIDCredential
		}) {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}

		if !slices.ContainsFunc(tokenInfo.AuthDetails, func(detail goidc.AuthDetail) bool {
			ids, _ := detail["credential_identifiers"].([]string)
			return detail.Type() == goidc.AuthDetailTypeOpenIDCredential && slices.Contains(ids, string(req.CredentialIdentifier))
		}) {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}
	}

	if req.CredentialConfigurationID != "" {
		if req.CredentialIdentifier != "" {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}

		config, ok := ctx.VCISelfConfigurations[req.CredentialConfigurationID]
		if !ok || !slices.Contains(strings.Fields(tokenInfo.Scopes), config.Scope.ID) {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}
	}

	var credConfigID goidc.VCConfigurationID
	var credIdentifier goidc.VCCredentialID
	if req.CredentialConfigurationID != "" {
		credConfigID = req.CredentialConfigurationID
	}

	for _, detail := range tokenInfo.AuthDetails {
		if detail.Type() != goidc.AuthDetailTypeOpenIDCredential {
			continue
		}

		ids, _ := detail["credential_identifiers"].([]string)
		if !slices.Contains(ids, string(req.CredentialIdentifier)) {
			continue
		}

		credConfigID = goidc.VCConfigurationID(detail["credential_configuration_id"].(string))
		credIdentifier = req.CredentialIdentifier
	}

	credConfig := ctx.VCISelfConfigurations[credConfigID]

	var proofKeys []crypto.PublicKey
	if proofConfig, ok := credConfig.ProofTypes[goidc.VCProofTypeJWT]; ok {
		if len(req.Proofs.JWT) == 0 {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}
		for _, proof := range req.Proofs.JWT {
			parsedProof, err := jwt.ParseSigned(proof, proofConfig.SigAlgs)
			if err != nil {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			if len(parsedProof.Headers) != 1 {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			proofHeader := parsedProof.Headers[0]
			if proofHeader.ExtraHeaders["typ"] != jwtTypeProofJWT {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			var proofKey crypto.PublicKey
			switch proofCertChain, proofCertChainErr := proofHeader.Certificates(x509.VerifyOptions{Roots: proofConfig.TrustedRoots}); {
			case proofHeader.JSONWebKey != nil:
				if proofHeader.KeyID != "" || errors.Is(proofCertChainErr, jose.ErrMissingX5cHeader) {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}

				if !proofHeader.JSONWebKey.IsPublic() {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}

				proofKey = proofHeader.JSONWebKey.Key
			case proofCertChainErr == nil:
				if proofConfig.TrustedRoots == nil {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}

				if proofHeader.JSONWebKey != nil || proofHeader.KeyID != "" {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}

				if len(proofCertChain) == 0 || len(proofCertChain[0]) == 0 {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}

				proofKey = proofCertChain[0][0].PublicKey
			// TODO: case proofHeader.KeyID != "":
			default:
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			var proofClaims jwt.Claims
			if err := parsedProof.Claims(proofKey, &proofClaims); err != nil {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			if proofClaims.IssuedAt == nil {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			if err := proofClaims.ValidateWithLeeway(jwt.Expected{
				Issuer:      tokenInfo.ClientID,
				AnyAudience: []string{ctx.VCISelfHost},
			}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
			}

			proofKeys = append(proofKeys, proofKey)
		}
	}

	if proofKeys == nil {
		proofKeys = append(proofKeys, nil)
	}
	var credentials []string
	for _, proofKey := range proofKeys {
		cred, err := credConfig.Issue(ctx, grant, goidc.VCIssuanceOptions{
			CredentialID: credIdentifier,
			ProofKey:     proofKey,
		})
		if err != nil {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}
		credentials = append(credentials, cred)
	}

	return response{
		Credentials: func() []struct {
			Credential string `json:"credential"`
		} {
			creds := make([]struct {
				Credential string `json:"credential"`
			}, len(credentials))
			for i, cred := range credentials {
				creds[i] = struct {
					Credential string `json:"credential"`
				}{
					Credential: cred,
				}
			}
			return creds
		}(),
	}, nil
}

type offerResponse struct {
	Issuer           string                    `json:"credential_issuer"`
	ConfigurationIDs []goidc.VCConfigurationID `json:"credential_configuration_ids"`
	Grants           goidc.VCOfferGrants       `json:"grants,omitzero"`
}

func offer(ctx oidc.Context, id string) (offerResponse, error) {
	offer, err := ctx.VCOffer(id)
	if err != nil {
		return offerResponse{}, err
	}

	return offerResponse{
		Issuer:           ctx.VCIIssuers[0].Issuer,
		ConfigurationIDs: offer.ConfigurationIDs,
		Grants:           offer.Grants,
	}, nil
}

// TODO: I only need an ID per offer if the params are different.
func CreateOffer(ctx oidc.Context, opts goidc.VCOfferOptions) (string, error) {
	credentialURL := "openid-credential-offer://" //nolint:gosec
	if opts.WalletID != "" {
		wallet, err := client.Client(ctx, opts.WalletID)
		if err != nil {
			return "", fmt.Errorf("could not load the wallet client: %w", err)
		}
		if wallet.CredentialOfferEndpoint != "" {
			credentialURL = wallet.CredentialOfferEndpoint
		}
	}

	now := timeutil.TimestampNow()
	offer := &goidc.VCOffer{
		ID:                 ctx.VCIOfferID(),
		ConfigurationIDs:   opts.ConfigurationIDs,
		CreatedAtTimestamp: now,
	}

	if opts.GrantAuthCode != nil {
		offer.Grants.AuthCode = &goidc.VCOfferGrantAuthCode{
			IssuerState: opts.GrantAuthCode.IssuerState,
		}
	}

	if opts.GrantPreAuthCode != nil {
		offer.Grants.PreAuthCode = &goidc.VCOfferGrantPreAuthCode{
			Code:   opts.GrantPreAuthCode.Code,
			TxCode: opts.GrantPreAuthCode.TxCode,
		}
	}

	if err := ctx.VCISaveOffer(offer); err != nil {
		return "", err
	}

	if opts.ByReference {
		return credentialURL + "?credential_offer_uri=" + ctx.VCIIssuers[0].Issuer + ctx.VCISelfOfferEndpoint + "/" + offer.ID, nil
	}

	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("could not marshal offer: %w", err)
	}

	return credentialURL + "?credential_offer=" + url.QueryEscape(string(offerJSON)), nil
}
