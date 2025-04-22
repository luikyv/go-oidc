package main

import (
	"context"
	"crypto/tls"
	"fmt"
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
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const (
	TrustAnchorFedID = "https://fed-trust-anchor.localhost"

	OPFedID   = "https://auth.localhost"
	OPFedJWKS = `
		{
			"keys": [
				{
					"p": "46PyozYJwEv280wQj2dR9riqweBLLqXaA1aLwEvZpZL_srNvipRsdnNvX3Vl3FIS4mXZcrAwi2xnA-Coe0-c8k9FbJpt3cMUTO9cfvYQ3atbNzTqyBuredj4-OutW7CSxFpPDbIfmSNifi4rzb4rAKMIvmU_CcDl4vyFpBEFBBE",
					"kty": "RSA",
					"q": "r7eIJ5DxlLlLmsM1F1MXW5O0yKLJTBiW_zxKG0GpjC4OlJWYUf4ETrIAnkHKLUnSAh3hUaKNfkX1lUqnlKXwBoravi8NTGR0SHDIRDCa-cTp6NUbQ2yKRg_eMm2EI1T_5YKNYiB2edkFjA5UulwMa5tOBs8uaCognZP3WX0L9sE",
					"d": "EaZlBbzQ324H-4512YsZ-RCmA8ptHkNtP6nY9pjLVufKGuDp44d0klUvteUQNKAdwbS3dm-I1-eAhFO0YDoZZobyl3tRxBoGbp4pWziVzHr3pro89xiZ1QFnniFaCRFpos5T3LfWpS909xkhjOC7SR_0QJXIU-9f5ry1jcnC-pRJFkFaztdxaZwl9_hnbG2AamjQU9BeAhr4km2axuk7ObttCx5ExMgAMauWWcJTn_Rye3F5u0VouCu2LGwGSf2YIY7I1tEBVSncDDYqC1dgF3S5qIrFxhxTF8pbK1Cqgr7lu6G1MNJEsXSAcZFV16iERiUdl_LxOCSI4W9GGNAkAQ",
					"e": "AQAB",
					"use": "sig",
					"kid": "AnXYaDOohNaXNckR0GYLCS3AXs6woEV0dVYgXJdQySU",
					"qi": "LB_QKVCsDAlAmqwMIb23mFj85Yf28Q-T4kD-KLp6JGv6Z5Tk8fCYRSLxUR1vuoLJvx_5ROXfIW5mqV4bVoxrkrnmjX8y1NHsd7VMaetA2U1v0MW6JewmGTxq6mL4sFgVyKlTyEDsh66gXrKQCRQyL5Y4tmPIRppxAS0ZPgXJswI",
					"dp": "YF8LHL-G10sRrCSaqitCjuHVIKj1CzWZm2orVeiGpssZxyyh3xhA5tCt6MrJqcFxTzlxGlWu54eoAQM-MJ4ewpJ-wKCMPKMW2A9JqFJCB6ZAwpl7f-X-7WHG3ZLg3H1fVRMqfpDXQbyyONsRHlQQ3n8m93vjeRyZ9kOTzEaMShE",
					"alg": "RS256",
					"dq": "Ssn9A4onqLttOIPZdwIAsROfIL5YmzDkI-KPUCaUeXuo7Qj2-f756lzM8o7h9IC1B_2bx1k-i_5O1qodxaETFlXHYKc6K8edzq9iLdPaQnDTdiwuHHZ4K_XZBvGiCj_FYvQ8JQXYJ2h9ee0nluJSzwIdJbzM7bzwgOFXqBkXHIE",
					"n": "nEBGIkxgARGUyTSB4oBG9xCrrFSL3iE_6HQ2YEOReFhI2YwLFMKfenECxO212TYzcyKWHpqM3KLR5e8Ub0v17JPnvUGketKu7kfbh910ZoX4Pk90ngSqd_fcS_jzh-rKuAlcH83EWW3MbMs3x13kVKCAYbnVP6cNmBJoLIQf03DhAmpVfJuNfhG_RZxtdPiVWNSEntZvjl-sjQgt8QkhMFLyncOPoclLpz7RduQlfZqg8Lnfs8fBM4j6I0MnXunk8Fuo0cZqypZsS9olclBAqVJWwT8UT75H4mO0EZI_IZANTNklQCdC3tjE55lf62gk_u6AOAICS38nlmgoIGtm0Q"
				}
			]
		}
	`

	ClientFedID   = "https://fed-client.localhost"
	ClientFedJWKS = `
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
	`
)

func main() {
	// Get the path to the source file.
	_, filename, _, _ := runtime.Caller(0)
	workingDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(workingDir, "../templates")
	jwksFilePath := filepath.Join(workingDir, "../keys/server.jwks")
	serverCertFilePath := filepath.Join(workingDir, "../keys/server.cert")
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
			[]string{TrustAnchorFedID},
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
		provider.WithJAR(goidc.RS256, goidc.PS256),
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

func httpClientFunc() goidc.HTTPClientFunc {
	trustAnchorIDURL, _ := url.Parse(TrustAnchorFedID)
	clientIDURL, _ := url.Parse(ClientFedID)
	return func(ctx context.Context) *http.Client {
		return &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Dial: func(network, addr string) (net.Conn, error) {
					// Forward requests to localhost.
					if addr == clientIDURL.Hostname()+":443" || addr == trustAnchorIDURL.Hostname()+":443" {
						addr = "127.0.0.1:443"
					}
					return net.Dial(network, addr)
				},
			},
		}
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
