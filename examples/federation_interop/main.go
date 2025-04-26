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

	OPFedID   = "https://ec2-50-19-156-19.compute-1.amazonaws.com"
	OPFedJWKS = `
		{
			"keys": [
				{
					"kty": "EC",
					"d": "YXKf56d43zlKJwkyjN6HQkT4AxHb3x5jRee8rfQJGpw",
					"use": "sig",
					"crv": "P-256",
					"kid": "nY_XVvKp4QD6MpStDMulpmpMGgemytcspMR-Xwwvy5c",
					"x": "zYH3xU7ODP-eD_gKPifdIoVorJivCp2Boo0ptzcU8OQ",
					"y": "FNycPxscW7vVipjEaSPVGroEzX0_ZPC5N8y1O8aubug",
					"alg": "ES256"
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
	serverCertFilePath := filepath.Join(workingDir, "../keys/7GIzGiS15jp-WVQLbwv9KKdUY5gRSREI4J8yvBMCZA0.pem")
	serverCertKeyFilePath := filepath.Join(workingDir, "../keys/6a81a0b2-a6f7-479d-9f8e-76add4dd629f-resource_server_signing.key")
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
