package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	formPostParamID            = "client_id"
	formPostParamSecret        = "client_secret"
	formPostParamAssertion     = "client_assertion"
	formPostParamAssertionType = "client_assertion_type"

	headerAttestion    = "OAuth-Client-Attestation"
	headerAttestionPoP = "OAuth-Client-Attestation-PoP"
)

var allAsymmetricAlgs = []goidc.SignatureAlgorithm{
	goidc.RS256, goidc.RS384, goidc.RS512,
	goidc.ES256, goidc.ES384, goidc.ES512,
	goidc.PS256, goidc.PS384, goidc.PS512,
}

type AuthnContext string

const (
	AuthnContextToken              AuthnContext = "token"
	AuthnContextPAR                AuthnContext = "par"
	AuthnContextDeviceAuth         AuthnContext = "device_auth"
	AuthnContextCIBA               AuthnContext = "ciba"
	AuthnContextTokenIntrospection AuthnContext = "token_introspection"
	AuthnContextTokenRevocation    AuthnContext = "token_revocation"
)

// ExtractID extracts a client ID from a authenticated request.
// It looks to all places where an ID can be informed such as the basic
// authentication header and the post form field 'client_id'.
// If different client IDs are found in the request, it returns an error.
func ExtractID(ctx oidc.Context) (string, error) {
	ids := []string{}

	if postID := ctx.Request.PostFormValue(formPostParamID); postID != "" {
		ids = append(ids, postID)
	}

	if basicID, _, _ := ctx.Request.BasicAuth(); basicID != "" {
		ids = append(ids, basicID)
	}

	if assertion := ctx.Request.PostFormValue(formPostParamAssertion); assertion != "" {
		parsed, err := jwt.ParseSigned(assertion, ctx.TokenAuthnSigAlgs())
		if err != nil {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
		}

		var claims map[string]any
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
		}

		// The issuer claim is supposed to be the client ID.
		clientID, ok := claims[goidc.ClaimIssuer]
		if !ok {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the iss claim is required in the client assertion"))
		}

		if _, ok := clientID.(string); !ok {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the iss claim in the client assertion must be a string"))
		}

		ids = append(ids, clientID.(string))
	}

	if attestation, ok := ctx.Header(headerAttestion); ok {
		parsed, err := jwt.ParseSigned(attestation, allAsymmetricAlgs)
		if err != nil {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				fmt.Errorf("could not parse attestation: %w", err))
		}

		var claims map[string]any
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
		}

		clientID, ok := claims[goidc.ClaimSubject]
		if !ok {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the sub claim is required in the client attestation"))
		}

		if _, ok := clientID.(string); !ok {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the sub claim in the client attestation must be a string"))
		}

		ids = append(ids, clientID.(string))
	}

	if len(ids) == 0 {
		return "", ErrClientNotIdentified
	}

	// All the client IDs present must be equal.
	for _, id := range ids {
		if id != ids[0] {
			return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the request contains conflicting client identifiers"))
		}
	}

	return ids[0], nil
}

// Authenticated fetches a client associated to the request and returns it
// if the client is authenticated according to its authentication method.
func Authenticated(ctx oidc.Context, authnCtx AuthnContext) (*goidc.Client, error) {
	id, err := ExtractID(ctx)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	c, err := Client(ctx, id)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
		}
		return nil, fmt.Errorf("could not load the client: %w", err)
	}

	if err := Authenticate(ctx, c, authnCtx); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	return c, nil
}

func Authenticate(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	if !slices.Contains(ctx.AuthnMethods, c.TokenAuthnMethod) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client's authentication method is not supported"))
	}

	switch c.TokenAuthnMethod {
	case goidc.AuthnMethodNone:
		return nil
	case goidc.AuthnMethodSecretPost:
		return authenticateSecretPost(ctx, c)
	case goidc.AuthnMethodSecretBasic:
		return authenticateSecretBasic(ctx, c)
	case goidc.AuthnMethodPrivateKeyJWT:
		return authenticatePrivateKeyJWT(ctx, c, authnCtx)
	case goidc.AuthnMethodSecretJWT:
		return authenticateSecretJWT(ctx, c, authnCtx)
	case goidc.AuthnMethodSelfSignedTLS:
		return authenticateSelfSignedTLSCert(ctx, c)
	case goidc.AuthnMethodTLS:
		return authenticateTLSCert(ctx, c)
	case goidc.AuthnMethodAttestationJWT:
		return authenticateAttestationJWT(ctx, c, authnCtx)
	default:
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client's authentication method is not supported"))
	}
}

func authenticateSecretPost(ctx oidc.Context, c *goidc.Client) error {
	if c.ID != ctx.Request.PostFormValue(formPostParamID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	secret := ctx.Request.PostFormValue(formPostParamSecret)
	if secret == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client_secret is required"))
	}

	if err := ctx.VerifyClientSecret(c.Secret, secret); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client secret", err)
	}

	if c.SecretExpiresAt != 0 && timeutil.TimestampNow() >= c.SecretExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("client_secret is expired"))
	}

	return nil
}

func authenticateSecretBasic(ctx oidc.Context, c *goidc.Client) error {
	id, secret, ok := ctx.Request.BasicAuth()
	if !ok {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client basic authentication is required"))
	}

	if c.ID != id {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	if err := ctx.VerifyClientSecret(c.Secret, secret); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client secret", err)
	}

	if c.SecretExpiresAt != 0 && timeutil.TimestampNow() >= c.SecretExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("client_secret is expired"))
	}

	return nil
}

func authenticatePrivateKeyJWT(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := authnSigAlgs(c, authnCtx, ctx.AuthnMethodPrivateKeyJWTSigAlgs)
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if len(parsedAssertion.Headers) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client assertion must contain exactly one JOSE header"))
	}

	jwk, err := JWKMatchingHeader(ctx, c, parsedAssertion.Headers[0])
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if !jwk.IsPublic() {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client assertion key must be public"))
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims(jwk.Key, &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	return areClaimsValid(ctx, claims, c, authnCtx)
}

func JWKMatchingHeader(ctx oidc.Context, c *goidc.Client, header jose.Header) (goidc.JSONWebKey, error) {
	if header.KeyID != "" {
		jwk, err := JWKByKeyID(ctx, c, header.KeyID)
		if err != nil {
			return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk used to sign the assertion that matches the 'kid' header: %w", err)
		}
		return jwk, nil
	}

	jwk, err := JWKByAlg(ctx, c, header.Algorithm)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk used to sign the assertion that matches the 'alg' header: %w", err)
	}
	return jwk, nil
}

func authenticateSecretJWT(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	assertion, err := assertion(ctx)
	if err != nil {
		return err
	}

	sigAlgs := authnSigAlgs(c, authnCtx, ctx.AuthnMethodSecretJWTSigAlgs)
	parsedAssertion, err := jwt.ParseSigned(assertion, sigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	claims := jwt.Claims{}
	if err := parsedAssertion.Claims([]byte(c.Secret), &claims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if c.SecretExpiresAt != 0 && timeutil.TimestampNow() >= c.SecretExpiresAt {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", errors.New("client_secret is expired"))
	}

	if err := areClaimsValid(ctx, claims, c, authnCtx); err != nil {
		return err
	}

	return nil
}

func authnSigAlgs(c *goidc.Client, authnCtx AuthnContext, algs []goidc.SignatureAlgorithm) []goidc.SignatureAlgorithm {
	var clientAlg goidc.SignatureAlgorithm
	switch authnCtx {
	case AuthnContextToken, AuthnContextPAR, AuthnContextDeviceAuth, AuthnContextCIBA:
		clientAlg = c.TokenAuthnSigAlg
	case AuthnContextTokenIntrospection:
		clientAlg = c.TokenIntrospectionAuthnSigAlg
	case AuthnContextTokenRevocation:
		clientAlg = c.TokenRevocationAuthnSigAlg
	}
	if clientAlg != "" && slices.Contains(algs, clientAlg) {
		return []goidc.SignatureAlgorithm{clientAlg}
	}
	return algs
}

func assertion(ctx oidc.Context) (string, error) {
	assertionType := ctx.Request.PostFormValue(formPostParamAssertionType)
	if assertionType != string(goidc.AssertionTypeJWTBearer) {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
	}

	assertion := ctx.Request.PostFormValue(formPostParamAssertion)
	if assertion == "" {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("client_assertion is required"))
	}

	return assertion, nil
}

func areClaimsValid(ctx oidc.Context, claims jwt.Claims, client *goidc.Client, _ AuthnContext) error {
	if claims.Expiry == nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the exp claim is required in the client assertion"))
	}

	if claims.ID == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the jti claim is required in the client assertion"))
	}

	if ctx.Profile == goidc.ProfileFAPI2 && len(claims.Audience) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the audience claim is invalid"))
	}

	if err := ctx.ConsumeJTI(claims.ID); err != nil && !errors.Is(err, goidc.ErrNotFound) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	secsToExpiry := int(claims.Expiry.Time().Sub(timeutil.Now()).Seconds())
	if secsToExpiry > ctx.JWTLifetimeSecs {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client assertion lifetime exceeds the allowed maximum"))
	}

	audiences := []string{ctx.Issuer()}
	if ctx.Profile != goidc.ProfileFAPI2 {
		audiences = append(audiences, ctx.TokenURL(), ctx.RequestURL())
		if ctx.MTLSIsEnabled {
			audiences = append(audiences, ctx.TokenMTLSURL(), ctx.RequestMTLSURL())
		}
	}

	err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.ID,
		Subject:     client.ID,
		AnyAudience: audiences,
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}
	return nil
}

func authenticateSelfSignedTLSCert(ctx oidc.Context, c *goidc.Client) error {
	if c.ID != ctx.Request.PostFormValue(formPostParamID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	jwk, err := func() (goidc.JSONWebKey, error) {
		jwks, err := JWKS(ctx, c)
		if err != nil {
			return goidc.JSONWebKey{}, fmt.Errorf("could not load the client JWKS: %w", err)
		}

		certSHA256 := sha256.Sum256(cert.Raw)
		certSHA1 := sha1.Sum(cert.Raw) //nolint:gosec
		for _, key := range jwks.Keys {
			if string(key.CertificateThumbprintSHA256) == string(certSHA256[:]) {
				return key, nil
			}
			if string(key.CertificateThumbprintSHA1) == string(certSHA1[:]) {
				return key, nil
			}
		}

		return goidc.JSONWebKey{}, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("no client JWK matches the presented client certificate"))
	}()
	if err != nil {
		return err
	}

	if !comparePublicKeys(jwk.Key, cert.PublicKey) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the public key in the client certificate does not match the client JWKS"))
	}

	return nil
}

func authenticateTLSCert(ctx oidc.Context, c *goidc.Client) error {
	if c.ID != ctx.Request.PostFormValue(formPostParamID) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client_id does not match the authenticated client"))
	}

	cert, err := ctx.ClientCert()
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	switch {
	case c.TLSSubjectDistinguishedName != "":
		if c.TLSSubjectDistinguishedName != cert.Subject.String() {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the client certificate subject distinguished name does not match"))
		}
	case c.TLSSubjectAlternativeName != "":
		if !slices.Contains(cert.DNSNames, c.TLSSubjectAlternativeName) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the client certificate subject alternative name does not match"))
		}
	default:
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client is missing TLS authentication metadata"))
	}

	return nil
}

func authenticateAttestationJWT(ctx oidc.Context, c *goidc.Client, authnCtx AuthnContext) error {
	attestationValues := ctx.Request.Header[http.CanonicalHeaderKey(headerAttestion)]
	if len(attestationValues) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("there must be precisely one "+headerAttestion+" header"))
	}
	attestationJWS := attestationValues[0]

	// Find the attestation issuer and verify the attestation JWT.
	var issuerClaims struct {
		Issuer string `json:"iss"`
	}
	// Parse with all asymmetric algorithms to extract the issuer claim.
	parsedAttestation, err := jwt.ParseSigned(attestationJWS, allAsymmetricAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not parse attestation: %w", err))
	}
	if err := parsedAttestation.UnsafeClaimsWithoutVerification(&issuerClaims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	issuer, err := func() (goidc.AttestationIssuer, error) {
		for _, issuer := range ctx.AuthnMethodAttestationJWTIssuers {
			if issuer.Issuer == issuerClaims.Issuer {
				return issuer, nil
			}
		}
		return goidc.AttestationIssuer{}, goidc.WrapError(goidc.ErrorCodeInvalidClient,
			"invalid client", errors.New("unknown attestation issuer"))
	}()
	if err != nil {
		return err
	}

	// Re-parse with the issuer's allowed algorithms if configured.
	sigAlgs := allAsymmetricAlgs
	if len(issuer.SigAlgs) > 0 {
		sigAlgs = issuer.SigAlgs
	}
	parsedAttestation, err = jwt.ParseSigned(attestationJWS, sigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not parse attestation: %w", err))
	}

	if len(parsedAttestation.Headers) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client attestation must have exactly one JOSE header"))
	}

	if parsedAttestation.Headers[0].ExtraHeaders["typ"] != "oauth-client-attestation+jwt" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("invalid client attestation type header"))
	}

	// Fetch the issuer's JWKS and find the verification key.
	resp, err := ctx.HTTPClient().Get(issuer.JWKSURI)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not fetch attestation issuer JWKS: %w", err))
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("fetching attestation issuer JWKS returned status %d", resp.StatusCode))
	}

	if resp.ContentLength > maxResponseByteSize {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("attestation issuer JWKS exceeds max size of %d bytes", maxResponseByteSize))
	}

	var issuerJWKS goidc.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseByteSize+1)).Decode(&issuerJWKS); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not decode attestation issuer JWKS: %w", err))
	}

	issuerJWK, err := func() (goidc.JSONWebKey, error) {
		if parsedAttestation.Headers[0].KeyID != "" {
			jwk, err := issuerJWKS.Key(parsedAttestation.Headers[0].KeyID)
			if err != nil {
				return goidc.JSONWebKey{}, goidc.WrapError(goidc.ErrorCodeInvalidClient,
					"invalid client", fmt.Errorf("could not find attestation issuer key matching kid: %w", err))
			}
			return jwk, nil
		}

		jwk, err := issuerJWKS.KeyByAlg(parsedAttestation.Headers[0].Algorithm)
		if err != nil {
			return goidc.JSONWebKey{}, goidc.WrapError(goidc.ErrorCodeInvalidClient,
				"invalid client", fmt.Errorf("could not find attestation issuer key matching alg: %w", err))
		}
		return jwk, nil
	}()
	if err != nil {
		return err
	}

	// Verify the attestation JWT signature and extract claims.
	var attestationClaims jwt.Claims
	var cnfClaims struct {
		Confirmation struct {
			JWK goidc.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}
	if err := parsedAttestation.Claims(issuerJWK.Key, &attestationClaims, &cnfClaims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not verify attestation signature: %w", err))
	}

	// Validate attestation claims.
	if attestationClaims.Expiry == nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the exp claim is required in the client attestation"))
	}

	secsToExpiry := int(attestationClaims.Expiry.Time().Sub(timeutil.Now()).Seconds())
	if secsToExpiry > ctx.JWTLifetimeSecs {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the client attestation lifetime exceeds the allowed maximum"))
	}

	if attestationClaims.Subject != c.ID {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the attestation sub claim does not match the client ID"))
	}

	if err := attestationClaims.ValidateWithLeeway(jwt.Expected{
		Issuer: issuer.Issuer,
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	// Validate the confirmation key.
	cnfJWK := cnfClaims.Confirmation.JWK
	if !cnfJWK.Valid() || !cnfJWK.IsPublic() {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the attestation cnf.jwk must be a valid public key"))
	}

	// Validate the PoP JWT.
	popValues := ctx.Request.Header[http.CanonicalHeaderKey(headerAttestionPoP)]
	if len(popValues) == 0 {
		// [Draft §5.2]: the DPoP proof can replace the attestation PoP when
		// no OAuth-Client-Attestation-PoP header is present. This is only
		// allowed at endpoints where the DPoP proof is always fully validated
		// downstream (token endpoint and PAR).
		if !ctx.DPoPIsEnabled || (authnCtx != AuthnContextToken && authnCtx != AuthnContextPAR) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New(headerAttestionPoP+" header is missing"))
		}

		dpopJWT, ok := dpop.JWT(ctx)
		if !ok {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New(headerAttestionPoP+" or DPoP header is required"))
		}

		// Only verify the key match here. The full DPoP validation
		// (signature, claims, jti) is handled by the existing DPoP flow
		// to avoid consuming the jti twice.
		parsedDPoP, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSigAlgs)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				fmt.Errorf("could not parse DPoP proof: %w", err))
		}

		if len(parsedDPoP.Headers) == 0 || parsedDPoP.Headers[0].JSONWebKey == nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the DPoP key is missing"))
		}

		if !comparePublicKeys(parsedDPoP.Headers[0].JSONWebKey.Key, cnfJWK.Key) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
				errors.New("the DPoP key does not match the attestation confirmation jwk"))
		}

		return nil
	}

	if len(popValues) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("there must be precisely one "+headerAttestionPoP+" header"))
	}
	attestationPopJWS := popValues[0]

	parsedPoP, err := jwt.ParseSigned(attestationPopJWS, allAsymmetricAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not parse attestation PoP: %w", err))
	}

	if len(parsedPoP.Headers) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the attestation PoP must have exactly one JOSE header"))
	}

	if parsedPoP.Headers[0].ExtraHeaders["typ"] != "oauth-client-attestation-pop+jwt" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("invalid attestation PoP type header"))
	}

	var popClaims jwt.Claims
	if err := parsedPoP.Claims(cnfJWK.Key, &popClaims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			fmt.Errorf("could not verify attestation PoP signature: %w", err))
	}

	if popClaims.Expiry == nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the exp claim is required in the attestation PoP"))
	}

	if popClaims.IssuedAt == nil || int(timeutil.Now().Sub(popClaims.IssuedAt.Time()).Seconds()) > ctx.JWTLifetimeSecs {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the attestation PoP issuance time is invalid"))
	}

	if popClaims.ID == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client",
			errors.New("the jti claim is required in the attestation PoP"))
	}

	if err := ctx.ConsumeJTI(popClaims.ID); err != nil && !errors.Is(err, goidc.ErrNotFound) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	if err := popClaims.ValidateWithLeeway(jwt.Expected{
		Issuer:      c.ID,
		AnyAudience: []string{ctx.Issuer()},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client", err)
	}

	return nil
}

func comparePublicKeys(k1 any, k2 any) bool {
	key2, ok := k2.(crypto.PublicKey)
	if !ok {
		return false
	}

	switch key1 := k1.(type) {
	case ed25519.PublicKey:
		return key1.Equal(key2)
	case *ecdsa.PublicKey:
		return key1.Equal(key2)
	case *rsa.PublicKey:
		return key1.Equal(key2)
	default:
		return false
	}
}
