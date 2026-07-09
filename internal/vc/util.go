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
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	jwtTypeProofJWT = "openid4vci-proof+jwt"
)

type metadata struct {
	Issuer                       string   `json:"credential_issuer"`
	CredentialEndpoint           string   `json:"credential_endpoint"`
	AuthorizationServers         []string `json:"authorization_servers,omitempty"`
	CredentialResponseEncryption *struct {
		AlgValuesSupported []goidc.KeyEncryptionAlgorithm     `json:"alg_values_supported"`
		EncValuesSupported []goidc.ContentEncryptionAlgorithm `json:"enc_values_supported"`
		ZipAlgs            []goidc.CompressionAlgorithm       `json:"zip_values_supported,omitempty"`
		EncryptionRequired bool                               `json:"encryption_required"`
	} `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance *struct {
		BatchSize int `json:"batch_size"`
	} `json:"batch_credential_issuance,omitempty"`
	DeferredCredentialEndpoint string `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint       string `json:"notification_endpoint,omitempty"`
	CredentialConfigurations   map[goidc.VCConfigurationID]struct {
		Format         goidc.VCFormat             `json:"format"`
		Scope          string                     `json:"scope,omitempty"`
		SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
		BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
		ProofTypes     map[goidc.VCProofType]struct {
			SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
		} `json:"proof_types_supported,omitempty"`
		Type goidc.VCType `json:"vct,omitempty"`
	} `json:"credential_configurations_supported"`
}

func newMetadata(ctx oidc.Context) metadata {
	return metadata{
		Issuer:             ctx.VCISelfHost,
		CredentialEndpoint: ctx.VCISelfHost + ctx.VCISelfCredentialEndpoint,
		AuthorizationServers: func() []string {
			if ctx.Host == ctx.VCISelfHost {
				return nil
			}
			return []string{ctx.Host}
		}(),
		CredentialResponseEncryption: func() *struct {
			AlgValuesSupported []goidc.KeyEncryptionAlgorithm     `json:"alg_values_supported"`
			EncValuesSupported []goidc.ContentEncryptionAlgorithm `json:"enc_values_supported"`
			ZipAlgs            []goidc.CompressionAlgorithm       `json:"zip_values_supported,omitempty"`
			EncryptionRequired bool                               `json:"encryption_required"`
		} {
			if !ctx.VCISelfResponseEncEnabled {
				return nil
			}
			return &struct {
				AlgValuesSupported []goidc.KeyEncryptionAlgorithm     `json:"alg_values_supported"`
				EncValuesSupported []goidc.ContentEncryptionAlgorithm `json:"enc_values_supported"`
				ZipAlgs            []goidc.CompressionAlgorithm       `json:"zip_values_supported,omitempty"`
				EncryptionRequired bool                               `json:"encryption_required"`
			}{
				AlgValuesSupported: ctx.VCISelfResponseEncKeyAlgs,
				EncValuesSupported: ctx.VCISelfResponseEncContentAlgs,
				EncryptionRequired: ctx.VCISelfResponseEncRequired,
			}
		}(),
		BatchCredentialIssuance: func() *struct {
			BatchSize int `json:"batch_size"`
		} {
			if ctx.VCISelfBatchSize <= 1 {
				return nil
			}
			return &struct {
				BatchSize int `json:"batch_size"`
			}{BatchSize: ctx.VCISelfBatchSize}
		}(),
		DeferredCredentialEndpoint: func() string {
			if !ctx.VCISelfDeferredEnabled {
				return ""
			}
			return ctx.VCISelfHost + ctx.VCISelfDeferredCredentialEndpoint
		}(),
		NotificationEndpoint: func() string {
			if !ctx.VCISelfNotificationEnabled {
				return ""
			}
			return ctx.VCISelfHost + ctx.VCISelfNotificationEndpoint
		}(),
		CredentialConfigurations: func() map[goidc.VCConfigurationID]struct {
			Format         goidc.VCFormat             `json:"format"`
			Scope          string                     `json:"scope,omitempty"`
			SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
			BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
			ProofTypes     map[goidc.VCProofType]struct {
				SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
			} `json:"proof_types_supported,omitempty"`
			Type goidc.VCType `json:"vct,omitempty"`
		} {
			configs := make(map[goidc.VCConfigurationID]struct {
				Format         goidc.VCFormat             `json:"format"`
				Scope          string                     `json:"scope,omitempty"`
				SigAlgs        []goidc.SignatureAlgorithm `json:"credential_signing_alg_values_supported,omitempty"`
				BindingMethods []goidc.VCBindingMethod    `json:"cryptographic_binding_methods_supported,omitempty"`
				ProofTypes     map[goidc.VCProofType]struct {
					SigAlgs []goidc.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
				} `json:"proof_types_supported,omitempty"`
				Type goidc.VCType `json:"vct,omitempty"`
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
					Type goidc.VCType `json:"vct,omitempty"`
				}{
					Format:         c.Format,
					Scope:          c.Scope.ID,
					SigAlgs:        c.SigAlgs,
					BindingMethods: c.BindingMethods,
					Type:           c.Type,
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

// credentialResponseEncryption represents the credential_response_encryption
// object as defined in [OIDC4VCI §8.2]. It's shared by the credential
// request and the deferred credential request (§9.1), since the latter
// reuses it verbatim and must be evaluated independently on every poll: the
// Credential Issuer MUST use the object from the Deferred Credential Request,
// not the one from the original Credential Request.
type credentialResponseEncryption struct {
	JWK           goidc.JSONWebKey                 `json:"jwk"`
	ContentEncAlg goidc.ContentEncryptionAlgorithm `json:"enc"`
	ZipAlg        goidc.CompressionAlgorithm       `json:"zip"`
}

// request represents the credential request at the credential endpoint
// as defined in [OIDC4VCI §8.2].
type request struct {
	// CredentialIdentifier identifies a specific Credential Dataset to be issued.
	// It's required when authorization_details of type openid_credential was returned
	// in the token response. It must not be used together with credential_configuration_id.
	CredentialIdentifier goidc.VCIdentifier `json:"credential_identifier,omitempty"`
	// CredentialConfigurationID identifies the credential configuration to be issued.
	// It's used when only the scope parameter was used in the autho request.
	// It must not be used together with credential_identifier.
	CredentialConfigurationID goidc.VCConfigurationID `json:"credential_configuration_id,omitempty"`
	Proofs                    struct {
		JWT         []string `json:"jwt,omitempty"`
		DIVP        []any    `json:"di_vp,omitempty"`
		Attestation []string `json:"attestation,omitempty"`
	} `json:"proofs,omitzero"`
	CredentialResponseEncryption *credentialResponseEncryption `json:"credential_response_encryption,omitempty"`
}

type response struct {
	Credentials    []responseCredential `json:"credentials,omitempty"`
	TransactionID  string               `json:"transaction_id,omitempty"`
	Interval       int                  `json:"interval,omitempty"`
	NotificationID string               `json:"notification_id,omitempty"`
	JWT            string               `json:"-"`
	Deferred       bool                 `json:"-"`
}

type responseCredential struct {
	Credential string `json:"credential"`
}

func issue(ctx oidc.Context, req request) (response, error) {
	resp, err := func() (response, error) {
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
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "either credential_configuration_id or credential_identifier must be provided")
		}

		if req.CredentialIdentifier != "" {
			if req.CredentialConfigurationID != "" {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "credential_identifier and credential_configuration_id must not be used together")
			}

			if !slices.ContainsFunc(tokenInfo.AuthDetails, func(detail goidc.AuthDetail) bool {
				return detail.Type() == goidc.AuthDetailTypeOpenIDCredential
			}) {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "credential_identifier requires an authorization_details of type openid_credential to have been granted to the access token")
			}

			if !slices.ContainsFunc(tokenInfo.AuthDetails, func(detail goidc.AuthDetail) bool {
				ids, _ := detail["credential_identifiers"].([]string)
				return detail.Type() == goidc.AuthDetailTypeOpenIDCredential && slices.Contains(ids, string(req.CredentialIdentifier))
			}) {
				return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "credential_identifier %q was not granted to this access token", req.CredentialIdentifier)
			}
		}

		if req.CredentialConfigurationID != "" {
			if req.CredentialIdentifier != "" {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "credential_identifier and credential_configuration_id must not be used together")
			}

			config, ok := ctx.VCISelfConfigurations[req.CredentialConfigurationID]
			if !ok {
				return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "credential_configuration_id %q is not a known credential configuration", req.CredentialConfigurationID)
			}

			if !slices.Contains(strings.Fields(tokenInfo.Scopes), config.Scope.ID) {
				return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "the scope required by credential_configuration_id %q was not granted to this access token", req.CredentialConfigurationID)
			}
		}

		credConfigID, credIdentifier := func() (goidc.VCConfigurationID, goidc.VCIdentifier) {
			if req.CredentialConfigurationID != "" {
				return req.CredentialConfigurationID, ""
			}

			if req.CredentialIdentifier != "" {
				for _, detail := range tokenInfo.AuthDetails {
					if detail.Type() != goidc.AuthDetailTypeOpenIDCredential {
						continue
					}

					ids, _ := detail["credential_identifiers"].([]string)
					if !slices.Contains(ids, string(req.CredentialIdentifier)) {
						continue
					}

					return goidc.VCConfigurationID(detail["credential_configuration_id"].(string)), req.CredentialIdentifier
				}
			}

			return "", ""
		}()
		credConfig := ctx.VCISelfConfigurations[credConfigID]

		var proofKeys []goidc.JSONWebKey
		if proofConfig, ok := credConfig.ProofTypes[goidc.VCProofTypeJWT]; ok {
			if len(req.Proofs.JWT) == 0 {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "proofs.jwt is required for this credential configuration")
			}

			if len(req.Proofs.JWT) > ctx.VCISelfBatchSize {
				return response{}, goidc.Errorf(goidc.ErrorCodeInvalidCredentialRequest, "proofs.jwt has %d entries, which exceeds the batch_size limit of %d", len(req.Proofs.JWT), ctx.VCISelfBatchSize)
			}

			if len(req.Proofs.DIVP) != 0 {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "proofs.di_vp must not be provided together with proofs.jwt")
			}

			if len(req.Proofs.Attestation) != 0 {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "proofs.attestation must not be provided together with proofs.jwt")
			}

			for _, proof := range req.Proofs.JWT {
				parsedProof, err := jwt.ParseSigned(proof, proofConfig.SigAlgs)
				if err != nil {
					return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the proof jwt", err)
				}

				if len(parsedProof.Headers) != 1 {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt must have exactly one header")
				}

				proofHeader := parsedProof.Headers[0]
				if proofHeader.ExtraHeaders["typ"] != jwtTypeProofJWT {
					return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "the proof jwt \"typ\" header must be %q", jwtTypeProofJWT)
				}

				var proofKey crypto.PublicKey
				switch proofCertChain, proofCertChainErr := proofHeader.Certificates(x509.VerifyOptions{Roots: proofConfig.TrustedRoots}); {
				case proofHeader.JSONWebKey != nil:
					if proofHeader.KeyID != "" || !errors.Is(proofCertChainErr, jose.ErrMissingX5cHeader) {
						return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt's jwk header must not be combined with a kid header or an x5c certificate chain")
					}

					if !proofHeader.JSONWebKey.IsPublic() {
						return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt's jwk header must contain a public key")
					}

					proofKey = proofHeader.JSONWebKey.Key
				case proofCertChainErr == nil:
					if proofConfig.TrustedRoots == nil {
						return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "this credential configuration does not accept proof jwts signed with an x5c certificate chain")
					}

					if proofHeader.JSONWebKey != nil || proofHeader.KeyID != "" {
						return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt's x5c certificate chain must not be combined with a jwk or a kid header")
					}

					if len(proofCertChain) == 0 || len(proofCertChain[0]) == 0 {
						return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt's x5c certificate chain is empty")
					}

					proofKey = proofCertChain[0][0].PublicKey
				// TODO: case proofHeader.KeyID != "":
				default:
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt must carry either a jwk header or a valid x5c certificate chain")
				}

				var proofClaims jwt.Claims
				if err := parsedProof.Claims(proofKey, &proofClaims); err != nil {
					return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not verify the proof jwt signature", err)
				}

				if proofClaims.IssuedAt == nil {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "the proof jwt must include an \"iat\" claim")
				}

				if err := proofClaims.ValidateWithLeeway(jwt.Expected{
					Issuer:      tokenInfo.ClientID,
					AnyAudience: []string{ctx.VCISelfHost},
				}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
					return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "the proof jwt claims are invalid", err)
				}

				proofKeys = append(proofKeys, goidc.JSONWebKey{Key: proofKey})
			}
		}

		if err := validateResponseEncryption(ctx, req.CredentialResponseEncryption); err != nil {
			return response{}, err
		}

		if ctx.VCISelfDeferredEnabled && credConfig.IsDeferred != nil {
			deferral := &goidc.VCDeferral{
				GrantID:                   grant.ID,
				CredentialConfigurationID: credConfigID,
				CredentialIdentifier:      credIdentifier,
				ProofKeys:                 proofKeys,
			}

			result, err := credConfig.IsDeferred(ctx, grant, deferral)
			if err != nil {
				return response{}, fmt.Errorf("could not evaluate the credential deferral: %w", err)
			}

			if result.Pending {
				deferral.ID = ctx.VCDeferredID()
				deferral.CreatedAt = timeutil.TimestampNow()
				if err := ctx.VCSaveDeferral(deferral); err != nil {
					return response{}, fmt.Errorf("could not save the credential deferral: %w", err)
				}

				interval := result.IntervalSecs
				if interval == 0 {
					interval = ctx.VCISelfDeferredIntervalSecs
				}

				return response{TransactionID: deferral.ID, Interval: interval, Deferred: true}, nil
			}
		}

		notificationID := ""
		if ctx.VCISelfNotificationEnabled {
			notificationID = ctx.VCNotificationID()
		}

		var credentials []string
		if len(proofKeys) == 0 {
			cred, err := credConfig.Issue(ctx, grant, goidc.VCIssuanceOptions{
				CredentialID:   credIdentifier,
				NotificationID: notificationID,
			})
			if err != nil {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not issue the credential", err)
			}
			credentials = append(credentials, cred)
		} else {
			for _, proofKey := range proofKeys {
				cred, err := credConfig.Issue(ctx, grant, goidc.VCIssuanceOptions{
					CredentialID:   credIdentifier,
					NotificationID: notificationID,
					ProofKey:       &proofKey,
				})
				if err != nil {
					return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not issue the credential", err)
				}
				credentials = append(credentials, cred)
			}
		}

		if ctx.VCISelfNotificationEnabled {
			if err := ctx.VCSaveNotification(&goidc.VCNotification{
				ID:                        notificationID,
				GrantID:                   grant.ID,
				ClientID:                  tokenInfo.ClientID,
				CredentialConfigurationID: credConfigID,
				CredentialIdentifier:      credIdentifier,
				CreatedAt:                 timeutil.TimestampNow(),
			}); err != nil {
				return response{}, fmt.Errorf("could not save the credential notification: %w", err)
			}
		}

		return response{
			NotificationID: notificationID,
			Credentials: func() []responseCredential {
				creds := make([]responseCredential, len(credentials))
				for i, cred := range credentials {
					creds[i] = responseCredential{Credential: cred}
				}
				return creds
			}(),
		}, nil
	}()
	if err != nil {
		return response{}, err
	}

	if ctx.VCISelfResponseEncEnabled && req.CredentialResponseEncryption != nil {
		return encryptResponse(ctx, resp, *req.CredentialResponseEncryption)
	}
	return resp, nil
}

// deferredRequest represents the request to the deferred credential endpoint
// as defined in [OIDC4VCI §9.1].
type deferredRequest struct {
	TransactionID                string                        `json:"transaction_id"`
	CredentialResponseEncryption *credentialResponseEncryption `json:"credential_response_encryption,omitempty"`
}

// deferredCredential evaluates a poll to the deferred credential endpoint.
func deferredCredential(ctx oidc.Context, req deferredRequest) (response, error) {
	resp, err := func() (response, error) {
		if req.TransactionID == "" {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
		}

		if err := validateResponseEncryption(ctx, req.CredentialResponseEncryption); err != nil {
			return response{}, err
		}

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

		deferral, err := ctx.VCDeferral(req.TransactionID)
		if err != nil {
			if errors.Is(err, goidc.ErrNotFound) {
				return response{}, goidc.NewError(goidc.ErrorCodeInvalidTransactionID, "invalid transaction id")
			}
			return response{}, fmt.Errorf("could not load the credential deferral: %w", err)
		}

		// A grant mismatch and an already consumed deferral are reported
		// identically, so polling doesn't leak whether a transaction_id exists
		// but belongs to someone else.
		if deferral.GrantID != grant.ID || deferral.ConsumedAt != 0 {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidTransactionID, "invalid transaction id")
		}

		credConfig, ok := ctx.VCISelfConfigurations[deferral.CredentialConfigurationID]
		if !ok || credConfig.IsDeferred == nil {
			return response{}, fmt.Errorf("could not find a deferrable credential configuration %q for the deferral", deferral.CredentialConfigurationID)
		}

		result, err := credConfig.IsDeferred(ctx, grant, deferral)
		if err != nil {
			return response{}, fmt.Errorf("could not evaluate the credential deferral: %w", err)
		}

		// Per [OIDC4VCI §9.2], a still-pending poll reuses the same transaction_id
		// and interval shape as the initial deferred response, returned with a
		// 202 status by the caller.
		if result.Pending {
			if err := ctx.VCSaveDeferral(deferral); err != nil {
				return response{}, fmt.Errorf("could not save the credential deferral: %w", err)
			}

			interval := result.IntervalSecs
			if interval == 0 {
				interval = ctx.VCISelfDeferredIntervalSecs
			}
			return response{TransactionID: deferral.ID, Interval: interval, Deferred: true}, err
		}

		deferral.ConsumedAt = timeutil.TimestampNow()
		if err := ctx.VCSaveDeferral(deferral); err != nil {
			return response{}, fmt.Errorf("could not save the credential deferral: %w", err)
		}

		notificationID := ""
		if ctx.VCISelfNotificationEnabled {
			notificationID = ctx.VCNotificationID()
		}

		var credentials []string
		if len(deferral.ProofKeys) == 0 {
			cred, err := credConfig.Issue(ctx, grant, goidc.VCIssuanceOptions{
				CredentialID:   deferral.CredentialIdentifier,
				NotificationID: notificationID,
			})
			if err != nil {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not issue the credential", err)
			}
			credentials = append(credentials, cred)
		} else {
			for _, proofKey := range deferral.ProofKeys {
				cred, err := credConfig.Issue(ctx, grant, goidc.VCIssuanceOptions{
					CredentialID:   deferral.CredentialIdentifier,
					NotificationID: notificationID,
					ProofKey:       &proofKey,
				})
				if err != nil {
					return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}
				credentials = append(credentials, cred)
			}
		}

		if ctx.VCISelfNotificationEnabled {
			if err := ctx.VCSaveNotification(&goidc.VCNotification{
				ID:                        notificationID,
				GrantID:                   grant.ID,
				ClientID:                  tokenInfo.ClientID,
				CredentialConfigurationID: deferral.CredentialConfigurationID,
				CredentialIdentifier:      deferral.CredentialIdentifier,
				CreatedAt:                 timeutil.TimestampNow(),
			}); err != nil {
				return response{}, fmt.Errorf("could not save the credential notification: %w", err)
			}
		}

		return response{
			NotificationID: notificationID,
			Credentials: func() []responseCredential {
				creds := make([]responseCredential, len(credentials))
				for i, cred := range credentials {
					creds[i] = responseCredential{
						Credential: cred,
					}
				}
				return creds
			}(),
		}, nil
	}()
	if err != nil {
		return response{}, err
	}

	if ctx.VCISelfResponseEncEnabled && req.CredentialResponseEncryption != nil {
		return encryptResponse(ctx, resp, *req.CredentialResponseEncryption)
	}
	return resp, nil
}

type notificationRequest struct {
	NotificationID   string                        `json:"notification_id"`
	Event            goidc.VCNotificationEventType `json:"event"`
	EventDescription string                        `json:"event_description,omitempty"`
}

func notify(ctx oidc.Context, req notificationRequest) error {
	accessToken, _, ok := ctx.AuthorizationToken()
	if !ok {
		return goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token", errors.New("authorization bearer token is required"))
	}

	tokenInfo, grant, err := token.Introspect(ctx, accessToken, nil)
	if err != nil {
		return fmt.Errorf("could not introspect the access token: %w", err)
	}

	if !tokenInfo.IsActive {
		return goidc.WrapError(goidc.ErrorCodeInvalidToken, "invalid token", errors.New("the access token is inactive or expired"))
	}

	if req.NotificationID == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "notification_id is required")
	}

	if !slices.Contains([]goidc.VCNotificationEventType{
		goidc.VCNotificationEventCredentialAccepted,
		goidc.VCNotificationEventCredentialFailure,
		goidc.VCNotificationEventCredentialDeleted,
	}, req.Event) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "event is invalid")
	}

	for _, r := range req.EventDescription {
		if r < 0x20 || r > 0x7e || r == 0x22 || r == 0x5c {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "event_description contains invalid characters")
		}
	}

	notification, err := ctx.VCNotification(req.NotificationID)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid notification_id")
		}
		return fmt.Errorf("could not load the credential notification: %w", err)
	}

	if notification.GrantID != grant.ID {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid notification_id",
			errors.New("the notification_id does not belong to the access token grant"))
	}

	return ctx.VCNotificationHandle(notification, goidc.VCNotificationEvent{
		Type:        req.Event,
		Description: req.EventDescription,
	})
}

// validateResponseEncryption checks enc against the provider's credential
// response encryption settings, as defined in [OIDC4VCI §8.2].
func validateResponseEncryption(ctx oidc.Context, enc *credentialResponseEncryption) error {
	if !ctx.VCISelfResponseEncEnabled {
		return nil
	}

	if ctx.VCISelfResponseEncRequired && enc == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "credential_response_encryption is required by this credential issuer")
	}

	if enc == nil {
		return nil
	}

	if !enc.JWK.IsPublic() {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "credential_response_encryption.jwk must be a public key")
	}

	if enc.JWK.Algorithm == "" || !slices.Contains(ctx.VCISelfResponseEncKeyAlgs, goidc.KeyEncryptionAlgorithm(enc.JWK.Algorithm)) {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "credential_response_encryption.jwk algorithm %q is not supported", enc.JWK.Algorithm)
	}

	if !slices.Contains(ctx.VCISelfResponseEncContentAlgs, enc.ContentEncAlg) {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "credential_response_encryption.enc %q is not supported", enc.ContentEncAlg)
	}

	if ctx.VCISelfResponseEncCompressionEnabled && enc.ZipAlg != "" && !slices.Contains(ctx.VCISelfResponseEncCompressionAlgs, enc.ZipAlg) {
		return goidc.Errorf(goidc.ErrorCodeInvalidRequest, "credential_response_encryption.zip %q is not supported", enc.ZipAlg)
	}

	return nil
}

// encryptResponse encrypts resp when enc is set.
func encryptResponse(ctx oidc.Context, resp response, enc credentialResponseEncryption) (response, error) {
	payload, err := json.Marshal(resp)
	if err != nil {
		return response{}, fmt.Errorf("could not marshal the credential response: %w", err)
	}

	opts := (&jose.EncrypterOptions{}).WithContentType("json")
	if ctx.VCISelfResponseEncCompressionEnabled && enc.ZipAlg != "" {
		opts.Compression = enc.ZipAlg
	}

	jwe, err := joseutil.Encrypt(string(payload), enc.JWK, enc.ContentEncAlg, opts)
	if err != nil {
		return response{}, fmt.Errorf("could not encrypt the credential response: %w", err)
	}

	return response{JWT: jwe, Deferred: resp.Deferred}, nil
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

type jwtIssuerMetadata struct {
	Issuer  string               `json:"issuer"`
	JWKS    *goidc.JSONWebKeySet `json:"jwks,omitempty"`
	JWKSURI string               `json:"jwks_uri,omitempty"`
}

func newJWTIssuerMetadata(ctx oidc.Context) (jwtIssuerMetadata, error) {
	if ctx.VCISelfJWTIssuerJWKSURI != "" {
		return jwtIssuerMetadata{
			Issuer:  ctx.VCISelfHost,
			JWKSURI: ctx.VCISelfJWTIssuerJWKSURI,
		}, nil
	}

	jwks, err := ctx.VCISelfJWTIssuerJWKS()
	if err != nil {
		return jwtIssuerMetadata{}, fmt.Errorf("could not load the vci self jwt issuer jwks: %w", err)
	}
	jwks = jwks.Public()

	return jwtIssuerMetadata{
		Issuer: ctx.VCISelfHost,
		JWKS:   &jwks,
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
