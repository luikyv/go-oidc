package main

import (
	"log"
	"path/filepath"
	"runtime"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/examples/authutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

func main() {
	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(sourceDir, "../templates")

	jwksFilePath := filepath.Join(sourceDir, "../keys/server.jwks")
	certFilePath := filepath.Join(sourceDir, "../keys/server.cert")
	certKeyFilePath := filepath.Join(sourceDir, "../keys/server.key")

	serverKeyID := "rs256_key"
	// Create and configure the OpenID provider.
	op, err := provider.New(
		goidc.ProfileOpenID,
		authutil.Issuer,
		authutil.PrivateJWKS(jwksFilePath),
		provider.WithScopes(authutil.Scopes...),
		provider.WithUserInfoSignatureKeyIDs(serverKeyID),
		provider.WithPAR(),
		provider.WithJAR(),
		provider.WithJARM(serverKeyID),
		provider.WithPrivateKeyJWTAuthn(jose.RS256),
		provider.WithBasicSecretAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(),
		provider.WithShouldIssueRefreshTokenFunc(authutil.IssueRefreshToken),
		provider.WithRefreshTokenLifetimeSecs(6000),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(authutil.DCRFunc),
		provider.WithTokenOptions(authutil.TokenOptionsFunc(serverKeyID)),
		provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicy(authutil.Policy(templatesDirPath)),
		provider.WithHandleErrorFunc(authutil.ErrorLoggingFunc),
		provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := op.RunTLS(provider.TLSOptions{
		TLSAddress: authutil.Port,
		ServerCert: certFilePath,
		ServerKey:  certKeyFilePath,
	}); err != nil {
		log.Fatal(err)
	}
}
