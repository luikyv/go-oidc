package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"maps"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/go-sdjwt/sdjwt"
)

const (
	CredentialIssuer                string                  = "https://credential-issuer.localhost" //nolint:gosec
	CredentialConfigurationIdentity goidc.VCConfigurationID = "identity_credential"
	//nolint:gosec
	CredentialIssuerJWKS string = `
		{
			"keys": [
				{
					"p": "-L-GimzlwDHu_1fOMdc_eeY2C9wFse5d36uZch8q8NOv1ZJcBGTqIHy6NI2xcWOPJIFRUCBbWQRtd8jc7eAsK5YdYUrgk5xSDiG_jvRi5NNblnV3pPtEYEtcbXx2n78lN8mjiMR3wvPwqPOLZBsCHUd5sWdcbIfJHSJTvSmhxXE",
					"kty": "RSA",
					"q": "spxderBmWnJfrwRfHMl5m6zG_0LitIzw9vaY-N1t5tzbKYgB3WKsxuFhBT-VqGBKXaMPQ6-RfEeD3Jyd5SC9n48MTTZqcO5Laz7TYIcCz1WvJ4anpQvnhO7ZkuGNr0wdIGMB65nfvugoISH2X9jqm3gnyCXYZqWUOpQbZlDdJc0",
					"d": "BGStCeEuC1zaMDMbyn53kM18Wot7dfQAg3aNzW77LFh8w8VtcFW4TEBNuq1BdxnGNITPNIUPNAa7tUb3blPnw8igIdK9QlW4e5JM_XUp80gCaxLVsQvqKTE-zElOpKjFKhgTCcXAsXwkwT51g0wbEckbWfQfPU10UEFlIkx2X1YgJQLKsVOkbrD9yZnSRysb4daoofqJ6xQMeAIsu1LLbTqEy4EQkVl-180_5YUd8p7tH3Slnhd0gcrnWiRjz89rXoIHDWaXaK2WKqr7Xe-rTOhMrOgdKIuKxLUHEwTCCp_KMFPnbaweij4nbcwnbvXmYoFwPP9q-L-46TZgWfSFwQ",
					"e": "AQAB",
					"use": "sig",
					"kid": "inskvmBn2eANKit1dw-OC_oJHlqQZblzkrT79iVvBAk",
					"qi": "ZxCYrM1bE7dFGnOBh6y5xnUozdo7VM7iEw3OjnsZ-vZzEdridbsncSh19JDQE8Lq-s2TtYoU_K1qhc7fKtP7pZ1Nql8JKJgQLUKLOKVeVBsHDqyYIPlpzSeXYDFLsECF8KSG_I8aUvObI0ZMrgII0dOocDp7yi0GdPWAHRecXR4",
					"dp": "J5hVEjPDXpSUNpEDgWuB7yV19O1Q-sG2r6PhCQltDGil1Jk3jHuDySgRe8wSMrpmTqlHCDoeUE0kH60ZfcPxQ_7hLlt85AI-DYHRvC-qjkIWkhygruJQQAO-8q6dM1B53Cd8oIilh6LM7BfYWFb0PzThahvJ2nzCxqBwM-wslAE",
					"alg": "RS256",
					"dq": "ixO0um8XFACRPv-hbBH57l1ICsWzL7G7hCIalVYeWLDKuvkbsp4-ORKP8H1FdHmeDnGE1kikeWhaZfNSA3NOFCtYAduIYG09LsIZ58TZTEbE_3sbmSm-2kT-CCA3qjMTTv-pJCKKFeZCMSJ37MREUlDqcS_-5Fa0KDThbPc0bFU",
					"n": "rY0bFwafo9xwf_f5dSk1vc8boE124sCmknNPd7YGYIuq3GJT6GpDRk3E5XTVnqreQFl1BIQL5SPpx-9xnhCuA3R9rWyllfxsN10irrPVequL0Uh9SAB-tHNsGVKy_oVL5kRhMQnLG8AnGaX_9l-6izb0lyRyaLqn2CShq2A9E19BXoEPx7T_YWb7TDkEGDfvTBbiyjfani1Ihec6nDwQUy1VhSChzhSKrFsQQcijhfOzlIZlBBfS3ayvIz213rEwg_hjk5nXN0mBcMynGRuEacpUn4D6Mnx-V1gR9zh5icRmFJaaauzpdR_9xTOQ5NqQ_8ve2JxcsWgXgnnfeqFwfQ"
				}
			]
		}
	`
	CredentialType goidc.VCType = goidc.VCType(CredentialIssuer + "/identity_credential")
)

var (
	ScopeIdentityCredential goidc.Scope = goidc.NewScope(string(CredentialConfigurationIdentity))
)

func main() {
	var credIssuerJWKS goidc.JSONWebKeySet
	_ = json.Unmarshal([]byte(CredentialIssuerJWKS), &credIssuerJWKS)
	credIssuerJWK := credIssuerJWKS.Keys[0]

	clientOne, _ := authutil.ClientPrivateKeyJWT("client_one")
	clientTwo, _ := authutil.ClientPrivateKeyJWT("client_two")
	op, err := provider.New(
		provider.Config{
			Issuer:      authutil.Issuer,
			JWKSFunc:    authutil.PrivateJWKSFunc(),
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.RS256},
		},
		provider.WithStaticClients(clientOne, clientTwo),
		provider.WithScopes(goidc.ScopeOpenID, ScopeIdentityCredential),
		provider.WithPrivateKeyJWTAuthn(goidc.RS256),
		provider.WithAttestationJWTAuthn(goidc.AttestationIssuer{}),
		provider.WithAuthCodeGrant(
			provider.AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			provider.WithPAR(nil),
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}),
			provider.WithAuthPolicies(goidc.NewPolicy(
				"main",
				func(r *http.Request, as *goidc.AuthnSession, c *goidc.Client) bool { return true },
				func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client) (goidc.Status, error) {
					as.Subject = uuid.NewString()
					as.Store[goidc.ClaimEmail] = "random@gmail.com"
					as.Store[goidc.ClaimAddress] = map[string]any{
						"street_address": "123 Main St, Suite 500",
						"locality":       "Springfield",
						"region":         "IL",
						"postal_code":    "62701",
						"country":        "USA",
					}
					as.GrantedScopes = as.Scopes
					for _, detail := range as.AuthDetails {
						detail = maps.Clone(detail)
						if detail.Type() == goidc.AuthDetailTypeOpenIDCredential && detail["credential_configuration_id"] == CredentialConfigurationIdentity {
							detail["credential_identifiers"] = []string{string(CredentialConfigurationIdentity) + "." + as.Subject}
						}
						as.GrantedAuthDetails = append(as.GrantedAuthDetails, detail)
					}
					return goidc.StatusSuccess, nil
				},
			)),
		),
		provider.WithVCI(
			provider.WithVCISelf(
				map[goidc.VCConfigurationID]goidc.VCConfiguration{
					CredentialConfigurationIdentity: {
						Format:         goidc.VCFormatDCSDJWT,
						Type:           CredentialType,
						Scope:          ScopeIdentityCredential,
						SigAlgs:        []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(credIssuerJWK.Algorithm)},
						BindingMethods: []goidc.VCBindingMethod{goidc.VCBindingMethodJWK},
						ProofTypes: map[goidc.VCProofType]goidc.VCProofConfiguration{
							goidc.VCProofTypeJWT: {
								SigAlgs: []goidc.SignatureAlgorithm{goidc.RS256, goidc.PS256},
							},
						},
						Issue: func(ctx context.Context, grant *goidc.Grant, opts goidc.VCIssuanceOptions) (string, error) {
							claims := map[string]any{
								goidc.ClaimSubject:                 grant.Subject,
								goidc.ClaimEmail:                   sdjwt.SD(grant.Store["email"]),
								goidc.ClaimAddress:                 sdjwt.SD(grant.Store["address"]),
								goidc.ClaimVerifiableCredentilType: CredentialType,
							}
							if opts.ProofKey != nil {
								claims[goidc.ClaimConfirmation] = map[string]any{
									goidc.ClaimJWK: jose.JSONWebKey{Key: opts.ProofKey},
								}
							}
							signer, _ := jose.NewSigner(
								jose.SigningKey{Algorithm: jose.SignatureAlgorithm(credIssuerJWK.Algorithm), Key: credIssuerJWK},
								(&jose.SignerOptions{}).WithType(jose.ContentType(goidc.VCFormatDCSDJWT)),
							)
							return sdjwt.Signed(signer).Claims(
								jwt.Claims{
									Issuer:   CredentialIssuer,
									Subject:  grant.Subject,
									IssuedAt: jwt.NewNumericDate(time.Now()),
									Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
								},
								claims,
							).Serialize()
						},
					},
				},
				provider.WithVCISelfIssuer(CredentialIssuer),
				provider.WithVCISelfJWTIssuer(provider.WithVCISelfJWTIssuerJWKS(func(ctx context.Context) (goidc.JSONWebKeySet, error) {
					return credIssuerJWKS.Public(), nil
				})),
				provider.WithVCISelfPreAuthCodeGrant(nil)),
		),
		provider.WithRAR([]goidc.AuthDetailType{goidc.AuthDetailTypeOpenIDCredential}),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithErrorHandler(authutil.HandleError),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	server := &http.Server{
		Addr:              authutil.Port,
		Handler:           op.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{authutil.ServerCert()},
			MinVersion:   tls.VersionTLS12,
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
