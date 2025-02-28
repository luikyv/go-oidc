package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const (
	clientID      = "https://fed-client.localhost"
	trustAnchorID = "https://fed-trust-anchor.localhost"
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(sourceDir, "../templates")

	jwksFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	serverCertKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	jwks, _ := authutil.PrivateJWKSFunc(jwksFilePath)(nil)

	// Create and configure the OpenID provider.
	op, err := provider.New(
		goidc.ProfileOpenID,
		authutil.Issuer,
		authutil.PrivateJWKSFunc(jwksFilePath),
		provider.WithOpenIDFederation(
			func(ctx context.Context) (goidc.JSONWebKeySet, error) {
				return jwks, nil
			},
			[]string{trustAnchorID},
			[]string{"https://intermediate-authority"},
		),
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
		provider.WithJAR(jose.RS256),
		provider.WithClaims(authutil.Claims[0], authutil.Claims...),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		provider.WithHTTPClientFunc(httpClientFunc()),
		provider.WithPolicy(authutil.Policy(templatesDirPath)),
		provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	hostURL, _ := url.Parse(authutil.Issuer)
	mux.Handle(hostURL.Hostname()+"/", op.Handler())

	var clientJWKS jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(`
		{
			"keys": [
				{
					"p": "-hIelluZM_zjt65GJ0EtJyzxYiZfMCHlT3MNout0D19veSvYyWVFjSqfGqvn4bTFd-66DGgRM6h0Msmul-2CsdPveVA1aZIXQkhFAV1aROaTpnIhfWfKkAULdAI2qIWH0nFzZ3-_zNdacmJZsyx12jb2B99mNs2JjHuRCZfQDZM",
					"kty": "RSA",
					"q": "hODSkomXcQq0V1GkDY0Kk5O7Bvr9itANCtwlKO6N-QTswCDhvhAH6Fd4koMMm8EF1K8j0S7bakdMoO-HJmb4QJ3VjA1UGIlGZS5A6oGK3xAsUlUmPkhy7dyAc7ggQoQwObFKVEKGIWQq5GV_TvFPEr_fLfFzkq5sH1UmKtQhMS8",
					"d": "HdVU4ViZJ9tyoEu-OXYTCD6xDJnPBjdIk8s8kBKE0I-zD0bvFcCkUEAVoqwBEzSm8mt-atH1QxXFrYDj-bRuerHlpoMRGInIKuMEYi5okj5miN_FIGC4yGW29T6qD_R687Cx93setUAxdmZLQKvqKSZS39qKAewZ9af6KFjvUsxYp5XYah6f62n3fQklC_c3LQb6kdpHpXohRxm2cEPJeQ97jD__E9NASBxTplImfIjkRBf0G6Xsg6JICsMja7K1uLZQE4YIvOAnKOtCDTlui98tEiAz8KzZ7zNY2wldMeaCFVpVij5AGV9BSUzL4oYonp5i2v4cs5bIsX7XM1oYZQ",
					"e": "AQAB",
					"use": "sig",
					"kid": "bHQnO_cSrz5OIf_kgxJvMuOCvdDG8AxPK0OtXL-64-c",
					"qi": "YsT-bMrcCyWD3x5T04KFfjMGZeYC0svP9TibqR18T1XGR99OhdZfo-Yy4IVBa-o_eRqCC1dx1FuOce59p0CceZ3jLun-5SqtlMK2R5IIMDQkRiTU_lF3T-pGv_6eLfKmIns3meh_Eg6c2xHYVii55pWlgWjOEybnWYpf2qHc2qs",
					"dp": "TkOjfQ1X6nRoVJFfdWOpnQws07oMqoTBPtdUWjv0i-cjfTni1E00slS3jOJmZTZtYva9FarwT0mWbFrAoN39vGgHF-GphcvqKZ1ys1WjLdM4PKyVnKkCNYbOqdUThDSeaJeHNco-nf58WTY8up3cmJoA8D_Tvq0fMm9t2iHARK8",
					"alg": "RS256",
					"dq": "f9LWPejmKfQmL6l1qyN2fSirzbc8l4A0S7IifRGeuWInbVs0TWWWdcdPUYGHa31vYn1ocx4kLESSTm6dEDAVt_MdLjDUKRZFBahNAknDkXk5aapHs7p19KMdXjRNtC79RUJrQksMRKrbKAMLSKGRc3Pn-YY_q2bm0-1RXfnaRDk",
					"n": "gcz1UkyfjzrCy62Dg1PhT9stHEcaFpMxUlbIs9zNA_f4xs-NdqOzIOSERSopN5ZCByVAOwOWYAHHzSAyfHJHiQoVheJRzwAhhqx9YKpoVAHZRbyhdS4PWUjhv2lXjaGFiOzOdjQlDlejyyysuPZpbEBPgch1AN5dRBlakso0TpYgm2QMQfNx_lRhtzyeKUQSC2eFnI76D7xSEhDzao6C6JDaAKq-_utDFtzRV-kIL_MvD8XWcdus5uDS24Jt59CK3YUzN0QAf9K34bPXliV_a7CStbqN71_IFVX_QYG7sY8wwhiWok0tKN21a3rOeRpHRfrhPJms9gcuXF__Lb6g_Q"
				}
			]
		}
	`), &clientJWKS)
	client := goidc.Client{
		ClientMetaInfo: goidc.ClientMetaInfo{
			GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantImplicit},
			RedirectURIs:  []string{"http://localhost/callback"},
			ScopeIDs:      "openid",
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCodeAndIDToken},
			PublicJWKS:    oidctest.RawJWKS(clientJWKS.Keys[0].Public()),
		},
	}
	var clientOpenIDFedJWKS jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(`
		{
			"keys": [
				{
					"p": "_j6sFKtYLlGDcJ7ePg_nYah0-R2_6MCGuXtcf_fKzT3_pXXhaph6QDGskaTO7hGSLsjdq_gafhRT9eKmTGoVoOnhWQ2GQpufivnTRgdnjnVG1U6hEoXDHkdlVizmPNgmdNkBHKQm0CheZtPhDZknpM9aCf9bv3UDNboJmHV4Yhs",
					"kty": "RSA",
					"q": "qXd5PfdVGLKSmBQO0rR0j0I5dyRpcq6br3gJ86oMLcGZ2Sxj2yq-HSfSVrex8AusTqMYEmPNPuYMu4Y9w3J3k6hjfAFJWZRp-9lHH09kd7i-nJDXsDDHPmuK6Iw9aOi1ojHf63k8WGvNw-rA6fXNAa71NDQwI9f53fdbLNROdfU",
					"d": "kDFphWmbIiFthvMMvlCx_h04jbvheiFa-WOQe0rgdB4VaIMCWjn0MRzKRwEfBrSTEu1T1e5_6NoEiKOzlAcsOSNrd3cR7fpCvnsXr2HEfvWcD6RQMs2qT8Yu9UofKYtg4kMSzJvq6WBFudBgBoBGX7XJbfM-oCDTCVzI1kJmVrTV4WshY3pEbKrebipMMtQFGXTuWUVft462y9EV5RfitEp3FrLPGm6jGxJt3L7F8VILYbU8WcHwcHnv55ZUoQU8WGB9PXJBC_AhZHv3dR8UXnws5VihhI71JV5-FFpVYX6GkzumGC4hba5iZ3NbJzOFqEuMQ5xTBzZ_szB7bayBoQ",
					"e": "AQAB",
					"use": "sig",
					"kid": "ZcwjzcDikHYiP4ZutjyAQa73p-_9yAC0-BAiKt0Rq2M",
					"qi": "5qLSd781xbQYKs_TIr-hmD954BAAZty6_uawe4kyhmhRdRTjkbIXFWi527exr95OUe5bI5DPr_-0QFW1olsgvIQ_fvJLCq_UI4CRIHwr_gvZL1MlbbeKCeTMjkIagUrtl4Av_a0o3b6FkPI5RREfUvG3gT4YtT53CPbVxkb-aoE",
					"dp": "Mr0hLHLRg1TjLVuXML2NyLCMv5aPUQzzFhsnZ6Z1A6bG2SeAV_ycESmYrew9G8fH66xMiOBXsSevZdfYplFZhaaHQXVwgOR734lh_4zEvupqu3EYthCZ0vYepCcLv8LHUfRow2WDFXGo_U51kHgrMDntVyduEPRyMouxFIsE_lc",
					"alg": "RS256",
					"dq": "LbBVUryNB8SVO0UlHe-jAUCkh5ecilvDA5LEdBojgG6S0Pdj0KH8cZXb4p9R7Nro0KauBb88hbm2MxSlMD17OacLc1JReUJHNKxGvY1FE_YOBd4TGKB-BzktUTcGE3OyDJGPwkeEWn5uEmUHL8yiQdLuru1nETLYXdyjizmOEcU",
					"n": "qE4HJMygndknDFl0H94UYlVFxZ-qdP0DmvUe6EnOWleMChsBLD7gMIQqHAc_4p4XRM_dlRoyjSrKoYMzoRFrADxHGl1h51yrCOiFG9GfFtMhmWW_Egb0HZ63Htg1MoLiK8BpHp1sjjsMiedHP7R7gR9RqpjHPfNI3myF8z-dfGtFcJevT-nX_9VgvHMH4_c7soA5SEnAYg0L3BxARFzFG3119Uc2wj5H1k1S-V391GdFr85qJtzcRDIdurJBnEqEWX_R21xS61eELtgQ1NRrkbpuXCsnoGuobDGIZcJbtVCgx70Xc6bdDm-cFLjGmjPBjpnkRLFAF1KRxs4osUY61w"
				}
			]
		}
	`), &clientOpenIDFedJWKS)

	clientHost, _ := url.Parse(clientID)
	mux.HandleFunc("GET "+clientHost.Hostname()+"/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		var publicJWKS jose.JSONWebKeySet
		for _, jwk := range clientOpenIDFedJWKS.Keys {
			publicJWKS.Keys = append(publicJWKS.Keys, jwk.Public())
		}

		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.WriteHeader(http.StatusOK)

		claims := map[string]any{
			"iss": clientID,
			"sub": clientID,
			"iat": timeutil.TimestampNow(),
			"exp": timeutil.TimestampNow() + 600,
			"metadata": map[string]any{
				"federation_entity":    map[string]any{},
				"openid_provider":      map[string]any{},
				"openid_relying_party": client.ClientMetaInfo,
			},
			"jwks":            publicJWKS,
			"authority_hints": []string{trustAnchorID},
		}

		opts := (&jose.SignerOptions{})
		opts = opts.WithHeader("kid", "ZcwjzcDikHYiP4ZutjyAQa73p-_9yAC0-BAiKt0Rq2M")
		opts = opts.WithHeader("alg", "RS256")
		opts = opts.WithHeader("typ", "entity-statement+jwt")
		signer, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: "RS256",
			Key:       clientOpenIDFedJWKS.Key("ZcwjzcDikHYiP4ZutjyAQa73p-_9yAC0-BAiKt0Rq2M")[0],
		}, opts)
		jws, _ := jwt.Signed(signer).Claims(claims).Serialize()

		_, _ = w.Write([]byte(jws))
	})

	var trustAnchorJWKS jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(`
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
	`), &trustAnchorJWKS)

	trustAnchorHost, _ := url.Parse(trustAnchorID)
	mux.HandleFunc("GET "+trustAnchorHost.Hostname()+"/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		var publicJWKS jose.JSONWebKeySet
		for _, jwk := range trustAnchorJWKS.Keys {
			publicJWKS.Keys = append(publicJWKS.Keys, jwk.Public())
		}

		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.WriteHeader(http.StatusOK)

		claims := map[string]any{
			"iss": trustAnchorID,
			"sub": trustAnchorID,
			"iat": timeutil.TimestampNow(),
			"exp": timeutil.TimestampNow() + 600,
			"metadata": map[string]any{
				"federation_entity": map[string]any{
					"federation_fetch_endpoint": trustAnchorID + "/fetch",
				},
				"openid_provider":      map[string]any{},
				"openid_relying_party": map[string]any{},
			},
			"jwks":            publicJWKS,
			"authority_hints": []string{trustAnchorID},
		}

		opts := (&jose.SignerOptions{})
		opts = opts.WithHeader("kid", "inskvmBn2eANKit1dw-OC_oJHlqQZblzkrT79iVvBAk")
		opts = opts.WithHeader("alg", "RS256")
		opts = opts.WithHeader("typ", "entity-statement+jwt")
		signer, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: "RS256",
			Key:       trustAnchorJWKS.Key("inskvmBn2eANKit1dw-OC_oJHlqQZblzkrT79iVvBAk")[0],
		}, opts)
		jws, _ := jwt.Signed(signer).Claims(claims).Serialize()

		_, _ = w.Write([]byte(jws))
	})

	mux.HandleFunc("GET "+trustAnchorHost.Hostname()+"/fetch", func(w http.ResponseWriter, r *http.Request) {
		var publicJWKS jose.JSONWebKeySet
		for _, jwk := range clientOpenIDFedJWKS.Keys {
			publicJWKS.Keys = append(publicJWKS.Keys, jwk.Public())
		}

		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		w.WriteHeader(http.StatusOK)

		claims := map[string]any{
			"iss":             trustAnchorID,
			"sub":             clientID,
			"iat":             timeutil.TimestampNow(),
			"exp":             timeutil.TimestampNow() + 600,
			"metadata_policy": map[string]any{},
			"metadata": map[string]any{
				"federation_entity":    map[string]any{},
				"openid_provider":      map[string]any{},
				"openid_relying_party": client.ClientMetaInfo,
			},
			"jwks": publicJWKS,
		}

		opts := (&jose.SignerOptions{})
		opts = opts.WithHeader("kid", "inskvmBn2eANKit1dw-OC_oJHlqQZblzkrT79iVvBAk")
		opts = opts.WithHeader("alg", "RS256")
		opts = opts.WithHeader("typ", "entity-statement+jwt")
		signer, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: "RS256",
			Key:       trustAnchorJWKS.Key("inskvmBn2eANKit1dw-OC_oJHlqQZblzkrT79iVvBAk")[0],
		}, opts)
		jws, _ := jwt.Signed(signer).Claims(claims).Serialize()

		_, _ = w.Write([]byte(jws))
	})

	jarOpts := (&jose.SignerOptions{})
	jarOpts = jarOpts.WithHeader("kid", clientJWKS.Keys[0].KeyID)
	jarOpts = jarOpts.WithHeader("alg", "RS256")
	jarOpts = jarOpts.WithHeader("typ", "JWT")
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: "RS256",
		Key:       clientJWKS.Keys[0].Key,
	}, jarOpts)
	jar, _ := jwt.Signed(signer).Claims(map[string]any{
		"iss":           clientID,
		"aud":           authutil.Issuer,
		"iat":           timeutil.TimestampNow(),
		"exp":           timeutil.TimestampNow() + 600,
		"client_id":     clientID,
		"redirect_uri":  "http://localhost/callback",
		"scope":         "openid",
		"response_type": "code id_token",
		"nonce":         "random_nonce",
	}).Serialize()
	log.Printf("%s/authorize?client_id=%s&response_type=code id_token&scope=openid&request=%s\n", authutil.Issuer, clientID, jar)

	if err := http.ListenAndServeTLS(authutil.Port, serverCertFilePath, serverCertKeyFilePath, mux); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func httpClientFunc() goidc.HTTPClientFunc {
	trustAnchorIDURL, _ := url.Parse(trustAnchorID)
	clientIDURL, _ := url.Parse(clientID)
	return func(ctx context.Context) *http.Client {
		return &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Dial: func(network, addr string) (net.Conn, error) {
					if addr == clientIDURL.Hostname()+":443" || addr == trustAnchorIDURL.Hostname()+":443" {
						addr = "127.0.0.1:443"
					}
					return net.Dial(network, addr)
				},
			},
		}
	}
}
