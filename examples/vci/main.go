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
	CredentialType goidc.VCType = goidc.VCType(authutil.Issuer + "/identity_credential")

	AttestationIssuer     string = "https://attestation-issuer.localhost"
	AttestationIssuerJWKS string = `
		{
			"keys": [
				{
					"p": "9YM72-oaQX5IwAWDS_aBpmLjzfXlrHgAJxhWiB7FBdHmd5lxPkGps1AwvROv9ci0Z1ZztrXv6F7XkkFKyKtppUH5D4ifin0PADJ5FGQd_LYdA0Tw7j__NFU2pYlb9i6LJ4XSVDqZ2TyqnQ5upmWMtFo8cJ1UFdhbKghEwSlLb1c",
					"kty": "RSA",
					"q": "3-g44afblSZIt6kNB81P1I1X_svREVgGF65TzrD-Lvru2oUQiufr8n9iZ16AWs7nYTh0LtQFp7Cuo5T0FDYRy1sjGauPTCBH8vTbdpfsjhBRazZlDvD_VizsFmW2wtw488X-Gmoy1VukWlpsFKtKlG2rmkUUdNNggS98lSQPibE",
					"d": "BcoCPbaPzzyNUdax5hzV3eTI5umOx8H_Zjba6M5j0us7eV2k-R7Fx9Ozk7RT8HtLTkHm4_sOYV7GrYeVaUeLGS0kob29knG8eVFDygRF7HjJzOkiMnfpQuMrMfuAIBPeXEqy9G96ss5ND9sdK_LKhehuRFqqfaZXYD-7WUX2doE-FCtELT5ysgtNaHosGTJCVUYFv2mu4YXl4zenRHp_LQBk_807TYGlN_mherUNSPfPQLXtrIhepvoQ899TYktUIesDezEFJx18CcmaqQc4tHUquaQyBtdqbJIXPQmCOf2lydC0e68BuT8fIDSqLumNMdYSs-6G0TKS4MRzSSEbsQ",
					"e": "AQAB",
					"use": "sig",
					"kid": "w-NgrO2e_w7UeOSuWIbOG8YPu6ZSllB-vCThRCRSj3E",
					"qi": "ZMCTAsvw3Xr8n89y3GDT2f7aK8878Z8iz2IOUIKrzVLV4pDqpYZxGEYeHOv07H4morkagZ_El7SuYJzoC5kL5HCVE6-919kOxdzE8zR_NdNZgv4hdcQ2C7pUE0-smj_48-gYKwPmOmVnwtiIgiANyaPaIe56FxNIfSZGKzT1pmc",
					"dp": "ySloKH6eWL9iWIOr2tf1zyEDysQKFdCVP3M_o3SitmwPzDsbgIlIxLWV2baB3H9A4dMCKNjV462iMCHzZoycmV1-9u1Y254wZlb0wnJt55xIFV-tkWk6b-TKS8RKZ2InfpC1j3IckNSWbu1eWFSofzXYg-VE-kk2GTCBNUvilS0",
					"alg": "PS256",
					"dq": "z57j78rYwErJrxQgsxVcavnNmMShznVS4O6TY9uXNzUT-qjcmBFKJoicVMG6P3oP74SLp0iPHdmldqYOVhd1FJ4jxA_jRnHAhbcrMaLahTj4ZnP_7YTnH590I6iZecL_RHxZjWDgVhsuIWIrSlczRsMTFm_r8hB3MhM4cIsJpWE",
					"n": "1rwGn-6j8LGfH7WVhllMfOULbT4jZjzH4pNTJKDr4W-ZgM1QESgxcl2P6ZOFWHEtmaPGBrSi0uOJIuJoyQ4iJ2W15Sb_RzX13YaxSr_HslgunJIEuUjE4QgBU3AW7auXaUXNHTXYxozdOXmkDQjuTcCDrPeZE2pUjrv2lS_x9weLfOSfga2TrW40GywGTRUyhXOP6rVPmpNVOhPqNcGosHgCrKGUoBMVlpxDkwkSdekjsr6cHw82Fapf8XovV3quQLCpH_iBY7FJver1FruDXQD9_mESz03693noQ-UYjMnSbyq4EE7Ucs6rlPfD9rKkYnj23akBoq-IceFdrdaKJw"
				}
			]
		}
	`
)

var (
	ScopeIdentityCredential goidc.Scope = goidc.NewScope(string(CredentialConfigurationIdentity))
)

func main() {
	var credIssuerJWKS goidc.JSONWebKeySet
	_ = json.Unmarshal([]byte(CredentialIssuerJWKS), &credIssuerJWKS)
	credIssuerJWK := credIssuerJWKS.Keys[0]

	var attestationIssuerJWKS goidc.JSONWebKeySet
	_ = json.Unmarshal([]byte(CredentialIssuerJWKS), &attestationIssuerJWKS)

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
		provider.WithPrivateKeyJWTAuthn(goidc.RS256, goidc.PS256),
		provider.WithAttestationJWTAuthn([]goidc.AttestationIssuer{{
			Issuer: AttestationIssuer,
			JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
				return attestationIssuerJWKS.Public(), nil
			},
		}}),
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
					as.Store["nationalities"] = []string{"US"}
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
				[]goidc.VCConfiguration{{
					ID:             CredentialConfigurationIdentity,
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
						address, _ := grant.Store["address"].(map[string]any)
						nationalities, _ := grant.Store["nationalities"].([]string)
						claims := map[string]any{
							goidc.ClaimSubject: grant.Subject,
							goidc.ClaimEmail:   sdjwt.SD(grant.Store["email"]),
							goidc.ClaimAddress: map[string]any{
								"street_address": sdjwt.SD(address["street_address"]),
								"nationalities":  []any{sdjwt.SD(nationalities[0])},
								"locality":       address["locality"],
								"region":         address["region"],
								"postal_code":    address["postal_code"],
								"country":        address["country"],
							},
							goidc.ClaimVerifiableCredentilType: CredentialType,
						}
						if opts.ProofKey != nil {
							claims[goidc.ClaimConfirmation] = map[string]any{
								goidc.ClaimJWK: goidc.JSONWebKey{Key: opts.ProofKey},
							}
						}
						signer, _ := jose.NewSigner(
							jose.SigningKey{Algorithm: jose.SignatureAlgorithm(credIssuerJWK.Algorithm), Key: credIssuerJWK},
							(&jose.SignerOptions{}).WithType(jose.ContentType(goidc.VCFormatDCSDJWT)),
						)
						return sdjwt.Signed(signer).Claims(
							jwt.Claims{
								Issuer:   authutil.Issuer,
								Subject:  grant.Subject,
								IssuedAt: jwt.NewNumericDate(time.Now()),
								Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
							},
							claims,
						).Serialize()
					},
				}},
				provider.WithVCISelfJWTIssuer(
					provider.WithVCISelfJWTIssuerJWKS(func(ctx context.Context) (goidc.JSONWebKeySet, error) {
						return credIssuerJWKS.Public(), nil
					}),
				),
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
