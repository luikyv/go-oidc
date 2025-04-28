package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const (
	TrustAnchorFedID = "https://federation.pr-2721.ci.raidiam.io/federation_entity/5d0acc74-a8ea-4f9e-8238-3b4b22166e9a"

	OPFedID = "https://ec2-50-19-156-19.compute-1.amazonaws.com"
	// OPFedID   = "https://auth.localhost"
	OPFedJWKS = `
		{
			"keys": [
				{
					"kid": "7GIzGiS15jp-WVQLbwv9KKdUY5gRSREI4J8yvBMCZA0",
					"alg": "RS256",
					"kty": "RSA",
					"n": "3ZvXi_KGOA1oh9BvEU1bUC3orN5yLU3rUJsyxr-rcghKj9PBBOESlnCtCfBP0_CRgE8ealprguJ6rhLemFkLMt1lbRAJWkB8wYlicIR1eVS1lvnPaN81eqCKkk3ckdKQn7r0JqUOUctv075-WAA51BW6H3GTQx6C5mFf2nkpp-kfH-7GreKgd8dLpMjVJD0mBN2FAWmLMpLpNoYbUqIPGtT7eA9WLZVtccYkqq1yer1fXC1rgvWVKLM0ub3Pfuj9EiiSoOhuYtqCp5Bt17slbRhHFlZxG3KHI0DAJ-4jIA-f3KCwUudoKFVeHksEo5izDmenKdGsEtxI_U5xC6omsw",
					"e": "AQAB",
					"d": "uI8WRNqVCdcqWFCPJfrsrdUcVayN0rH6Q0h41pHdFcD35hxv4ZIockff55s3BlAMpHU_9yOGI-f_CvCioN-tgiWUfX2y5AChhv77mSHUCWLTjO3LYaziGqt84mUu4AojHF88xz5G_0m1TsSB00OMTf1Fjkkpj9QzX44hVGTywsGsCBOhz5OnGkXQY_E-H8b8y4xv1MQGx36SnbBDjvgwKnImFb6UFtyDupBdJPJP1kofPaUcs9zHqY3S5i1s9_kClkornLG3cUNIQVz9z34W4jH9kIr4a1T6Kzh_dCmwO74MYuj9hvhjJjFkdjQor7YugD0nceU3ewZKE65dOmO9",
					"p": "9c53Hw3NrO2fTNjxuKExv8tVqL8PBZGvvsKEa4tAU9mUMU8U-c-pyRWvdhiA4jI9WN07GYln7bafh6YEwVo6iK5HVdyHsKMx3qLN3TlIPvB8SiLHZT3nIAJEsZMlFaggr0YZCfuuA2xZWe6mhTvPoJzwMSJDnJ-dz9yt6YJ0u78",
					"q": "5sx8-Qgu8bN4haNUifzOQB1b9JLqPzLF7Pjii5JQW7kv9SCAPv4zfo_ZHHRcfWA3DWWiDEVdAEUX339MPmtm50FBKh43nFeZGE_acFirizPBvWxTUtfHOuaqzrupG2bIpSSqgf5q4bYbV0uiEAC-qyXIXl9ToYKQVRKcCrmC4g0",
					"dp": "QdXPv-iBiuyF-x4r98hsu7LpOW4axuITUSNmNiuwygR_lYlZ0-LT1cDSIu5DLtJH7hIq7xcHV_rO1ZUYtvTEsrEC-DM9wIilJb0zKCpceEcO8whHoY0n50HURj9j8l36ixdaQ3s-Szps4BJ0VUEExj7icjZ8J2n06aRwjBddzp8",
					"dq": "UEP9kn4OFXDdEVzkIbkR4apUOJJ_dMsrmmZUI0YXPE8DJrTO5Rlyvyk30HWHVPMJMleOK8ZTuaxNySR0V6DygKppB0TLAkxUqefbiAbOYfL2BfKOZ9kzKIDgFlWdUjJExWojAmKAuU6j45AiJH6d0Neq_2cXpqvJlkyKiBBMPGE",
					"qi": "KG9MehD0D6dZpj4b1ClpsJIqKaOOy3IFkxdulEV7j0o07Sqavnwcp5USvBP29zfi3Xibrh397zj0CsmVkAJDo9M2IUc0kXPE4IQsTg8ocVwgJ4OkJkMq7wHTeIwBNNNvEcZeJ6LEbwXfW1E6MpfVnYNadH9Y2agaAgZ0mpkWcUY"
				}
			]
		}
	`

	ClientFedID   = "https://50.19.156.19"
	ClientFedJWKS = `
		{
			"keys": [
				{
					"kty": "EC",
					"d": "KiNS6fScsAuphhFQbPKw5YjXu1Nvz7gi47at_f8KSow",
					"use": "sig",
					"crv": "P-256",
					"kid": "cW6BPniOmyVMvwIlTlh2SanDl3KmferQuT8LS7CIB9U",
					"x": "1Mlnn7kLJJgWELLdF-pqw2j6CGYRY0lJbu8m4i-esdM",
					"y": "QCezZwp5knqiRivSjDNPfPNHR79KAvFQbPcE4rKvnLo",
					"alg": "ES256"
				}
			]
		}
	`
)

func main() {
	// Get the path to the source file.
	_, filename, _, _ := runtime.Caller(0)
	workingDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(workingDir, "../templates")
	jwksFilePath := filepath.Join(workingDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(workingDir, "../keys/server.crt")
	serverCertKeyFilePath := filepath.Join(workingDir, "../keys/server.key")
	clientJWKSFilePath := filepath.Join(workingDir, "../keys/client_one.jwks")

	// Set up federation JWKS's.
	var opFedJWKS goidc.JSONWebKeySet
	_ = json.Unmarshal([]byte(OPFedJWKS), &opFedJWKS)

	var clientFedJWKS goidc.JSONWebKeySet
	_ = json.Unmarshal([]byte(ClientFedJWKS), &clientFedJWKS)

	// Set up federation URL's.
	opFedURL, _ := url.Parse(OPFedID)
	clientFedURL, _ := url.Parse(ClientFedID)

	// Create and configure the openid provider and a client.
	client, clientJWKS := authutil.ClientPrivateKeyJWT(ClientFedID, clientJWKSFilePath)

	op, err := provider.New(
		goidc.ProfileOpenID,
		OPFedID,
		authutil.PrivateJWKSFunc(jwksFilePath),
		provider.WithOpenIDFederation(
			func(ctx context.Context) (goidc.JSONWebKeySet, error) {
				return opFedJWKS, nil
			},
			[]string{TrustAnchorFedID},
			[]string{"https://authority.pr-2721.ci.raidiam.io/authority/0535f73a-57e0-46aa-b07d-f88e39c4bb70", TrustAnchorFedID},
		),
		provider.WithOpenIDFederationSignatureAlgs(goidc.RS256, goidc.ES256),
		provider.WithScopes(authutil.Scopes...),
		provider.WithIDTokenSignatureAlgs(goidc.RS256),
		provider.WithTokenAuthnMethods(
			goidc.ClientAuthnSecretBasic,
			goidc.ClientAuthnSecretPost,
			goidc.ClientAuthnPrivateKeyJWT,
		),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.RS256),
		provider.WithAuthorizationCodeGrant(),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(authutil.IssueRefreshToken, 600),
		provider.WithJAR(goidc.RS256, goidc.PS256),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicy(authutil.Policy(templatesDirPath)),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Set up the server.
	mux := http.NewServeMux()

	mux.Handle(opFedURL.Hostname()+"/", op.Handler())

	mux.HandleFunc("GET "+clientFedURL.Hostname()+"/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.WriteHeader(http.StatusOK)

		claims := map[string]any{
			"iss": ClientFedID,
			"sub": ClientFedID,
			"iat": timeutil.TimestampNow(),
			"exp": timeutil.TimestampNow() + 600,
			"metadata": map[string]any{
				"openid_relying_party": client.ClientMeta,
			},
			"jwks":            clientFedJWKS.Public(),
			"authority_hints": []string{TrustAnchorFedID},
		}

		opts := (&jose.SignerOptions{}).WithHeader("typ", "entity-statement+jwt")
		jwk := clientFedJWKS.Keys[0]
		signer, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
			Key:       jwk,
		}, opts)
		jws, _ := jwt.Signed(signer).Claims(claims).Serialize()

		_, _ = w.Write([]byte(jws))
	})

	log.Println(authReqURL(clientJWKS))
	if err := http.ListenAndServeTLS(authutil.Port, serverCertFilePath, serverCertKeyFilePath, mux); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func authReqURL(clientJWKS goidc.JSONWebKeySet) string {
	jarOpts := (&jose.SignerOptions{}).WithHeader("typ", "JWT")
	jwk := clientJWKS.Keys[0]
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}, jarOpts)
	jar, _ := jwt.Signed(signer).Claims(map[string]any{
		"iss":           ClientFedID,
		"aud":           OPFedID,
		"iat":           timeutil.TimestampNow(),
		"exp":           timeutil.TimestampNow() + 600,
		"client_id":     ClientFedID,
		"redirect_uri":  "http://localhost/callback",
		"scope":         "openid",
		"response_type": "code id_token",
		"nonce":         "random_nonce",
	}).Serialize()

	return fmt.Sprintf("%s/authorize?client_id=%s&response_type=code id_token&scope=openid&request=%s\n", OPFedID, ClientFedID, jar)
}
