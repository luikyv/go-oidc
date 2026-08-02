package dpop

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JWKThumbprint string
	NonceScope    goidc.DPoPNonceScope
}

type Claims struct {
	HTTPMethod      string `json:"htm"`
	HTTPURI         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
	Nonce           string `json:"nonce"`
}

// JWKThumbprint generates a JWK thumbprint for a valid DPoP JWT.
func JWKThumbprint(dpopJWT string, algs []goidc.SignatureAlgorithm) string {
	// TODO: handle the error
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, algs)
	if err != nil {
		return ""
	}
	jkt, err := parsedDPoPJWT.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(jkt)
}

// JWT gets the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func JWT(ctx oidc.Context) (string, bool) {
	// To access the dpop jwts from the field Header, we need to use the
	// canonical version of the header "DPoP" which is "Dpop".
	dpopJWTs := ctx.Request.Header[http.CanonicalHeaderKey(goidc.HeaderDPoP)]
	if len(dpopJWTs) != 1 {
		return "", false
	}
	return dpopJWTs[0], true
}

func ValidateJWT(ctx oidc.Context, dpopJWT string, opts ValidationOptions) error {
	parsed, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSigAlgs)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	if len(parsed.Headers) != 1 {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the DPoP proof must contain exactly one JOSE header"))
	}

	if parsed.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the typ header must be dpop+jwt"))
	}

	jwk := parsed.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the jwk header must contain a valid public key"))
	}

	var claims jwt.Claims
	var dpopClaims Claims
	if err := parsed.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil ||
		int(timeutil.Now().Sub(claims.IssuedAt.Time()).Seconds()) > ctx.JWTLifetimeSecs {
		return goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the DPoP proof issuance time is invalid"))
	}

	if claims.ID == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the jti claim is required"))
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the htm claim does not match the request method"))
	}

	httpURI, err := strutil.NormalizeURL(dpopClaims.HTTPURI)
	auds := []string{ctx.BaseURL() + ctx.Request.RequestURI}
	if ctx.MTLSEnabled {
		auds = append(auds, ctx.MTLSBaseURL()+ctx.Request.RequestURI)
	}
	if err != nil || !slices.Contains(auds, httpURI) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the htu claim does not match the request URI"))
	}

	if opts.AccessToken != "" && dpopClaims.AccessTokenHash != hashutil.Thumbprint(opts.AccessToken) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the ath claim does not match the access token"))
	}

	if opts.JWKThumbprint != "" && JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs) != opts.JWKThumbprint {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the DPoP key thumbprint does not match the expected binding"))
	}

	if err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	if ctx.DPoPNonceManager != nil {
		if opts.NonceScope == "" {
			return errors.New("a DPoP nonce scope is required when nonce validation is enabled")
		}
		if err := validateNonce(ctx, opts.NonceScope, dpopClaims.Nonce); err != nil {
			return err
		}
	}

	if err := ctx.ConsumeJTI(claims.ID); err != nil && !errors.Is(err, goidc.ErrNotFound) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	return nil
}

func validateNonce(ctx oidc.Context, scope goidc.DPoPNonceScope, nonce string) error {
	if scope != goidc.DPoPNonceScopeAuthorizationServer && scope != goidc.DPoPNonceScopeResourceServer {
		return fmt.Errorf("invalid DPoP nonce scope %q", scope)
	}
	if ctx.Response == nil {
		return errors.New("cannot use DPoP nonces without a response writer")
	}

	if !validNonce(nonce) {
		return nonceChallenge(ctx, scope)
	}

	validation, err := ctx.ValidateDPoPNonce(scope, nonce)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return nonceChallenge(ctx, scope)
		}
		return fmt.Errorf("could not validate DPoP nonce: %w", err)
	}
	if validation.NextNonce == "" {
		return nil
	}
	return setNonceHeader(ctx, validation.NextNonce)
}

func nonceChallenge(ctx oidc.Context, scope goidc.DPoPNonceScope) error {
	if _, err := issueNonce(ctx, scope); err != nil {
		return err
	}

	description := "authorization server requires a fresh nonce in the DPoP proof"
	status := http.StatusBadRequest
	if scope == goidc.DPoPNonceScopeResourceServer {
		description = "resource server requires a fresh nonce in the DPoP proof"
		status = http.StatusUnauthorized
		challenge := "DPoP error=" + strconv.Quote(string(goidc.ErrorCodeUseDPoPNonce)) +
			", error_description=" + strconv.Quote(description)
		if len(ctx.DPoPSigAlgs) != 0 {
			algs := make([]string, len(ctx.DPoPSigAlgs))
			for i, alg := range ctx.DPoPSigAlgs {
				algs[i] = string(alg)
			}
			challenge += ", algs=" + strconv.Quote(strings.Join(algs, " "))
		}
		ctx.Response.Header().Add("WWW-Authenticate", challenge)
	}

	return goidc.NewError(goidc.ErrorCodeUseDPoPNonce, description).WithStatusCode(status)
}

func issueNonce(ctx oidc.Context, scope goidc.DPoPNonceScope) (string, error) {
	nonce, err := ctx.IssueDPoPNonce(scope)
	if err != nil {
		return "", fmt.Errorf("could not issue DPoP nonce: %w", err)
	}
	if err := setNonceHeader(ctx, nonce); err != nil {
		return "", err
	}
	return nonce, nil
}

func setNonceHeader(ctx oidc.Context, nonce string) error {
	if !validNonce(nonce) {
		return errors.New("DPoP nonce manager issued an invalid DPoP nonce")
	}
	// Set, rather than Add, guarantees that the response never contains more
	// than one DPoP-Nonce field value as required by RFC 9449 Section 8.
	ctx.Response.Header().Set(goidc.HeaderDPoPNonce, nonce)
	ctx.Response.Header().Set("Cache-Control", "no-store")
	return nil
}

func validNonce(nonce string) bool {
	if nonce == "" {
		return false
	}

	for i := range len(nonce) {
		c := nonce[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) {
			continue
		}
		return false
	}
	return true
}
