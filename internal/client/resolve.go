package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	maxResponseByteSize int64 = 1_000_000 // 1 MB.
)

func Resolve(ctx oidc.Context, c *Meta) (err error) {
	if ctx.RPMetadataChoicesIsEnabled {
		c.SubIdentifierType, err = resolveChoice(c.SubIdentifierTypes, c.SubIdentifierType, ctx.SubIdentifierTypes, "subject_types_supported")
		if err != nil {
			return err
		}

		c.IDTokenSigAlg, err = resolveChoice(c.IDTokenSigAlgs, c.IDTokenSigAlg, ctx.IDTokenSigAlgs, "id_token_signing_alg_values_supported")
		if err != nil {
			return err
		}

		if ctx.IDTokenEncIsEnabled {
			c.IDTokenKeyEncAlg, err = resolveChoice(c.IDTokenKeyEncAlgs, c.IDTokenKeyEncAlg, ctx.IDTokenKeyEncAlgs, "id_token_encryption_alg_values_supported")
			if err != nil {
				return err
			}

			c.IDTokenContentEncAlg, err = resolveChoice(c.IDTokenContentEncAlgs, c.IDTokenContentEncAlg, ctx.IDTokenContentEncAlgs, "id_token_encryption_enc_values_supported")
			if err != nil {
				return err
			}
		} else {
			c.IDTokenKeyEncAlgs = nil
			c.IDTokenContentEncAlgs = nil
		}

		c.UserInfoSigAlg, err = resolveChoice(c.UserInfoSigAlgs, c.UserInfoSigAlg, ctx.UserInfoSigAlgs, "userinfo_signing_alg_values_supported")
		if err != nil {
			return err
		}

		if ctx.UserInfoEncIsEnabled {
			c.UserInfoKeyEncAlg, err = resolveChoice(c.UserInfoKeyEncAlgs, c.UserInfoKeyEncAlg, ctx.UserInfoKeyEncAlgs, "userinfo_encryption_alg_values_supported")
			if err != nil {
				return err
			}

			c.UserInfoContentEncAlg, err = resolveChoice(c.UserInfoContentEncAlgs, c.UserInfoContentEncAlg, ctx.UserInfoContentEncAlgs, "userinfo_encryption_enc_values_supported")
			if err != nil {
				return err
			}
		} else {
			c.UserInfoKeyEncAlgs = nil
			c.UserInfoContentEncAlgs = nil
		}

		if ctx.JARIsEnabled {
			c.JARSigAlg, err = resolveChoice(c.JARSigAlgs, c.JARSigAlg, ctx.JARSigAlgs, "request_object_signing_alg_values_supported")
			if err != nil {
				return err
			}

			if ctx.JAREncIsEnabled {
				c.JARKeyEncAlg, err = resolveChoice(c.JARKeyEncAlgs, c.JARKeyEncAlg, ctx.JARKeyEncAlgs, "request_object_encryption_alg_values_supported")
				if err != nil {
					return err
				}

				c.JARContentEncAlg, err = resolveChoice(c.JARContentEncAlgs, c.JARContentEncAlg, ctx.JARContentEncAlgs, "request_object_encryption_enc_values_supported")
				if err != nil {
					return err
				}
			} else {
				c.JARKeyEncAlgs = nil
				c.JARContentEncAlgs = nil
			}

		} else {
			c.JARSigAlgs = nil
			c.JARKeyEncAlgs = nil
			c.JARContentEncAlgs = nil
		}

		c.TokenAuthnMethod, err = resolveChoice(c.TokenAuthnMethods, c.TokenAuthnMethod, ctx.AuthnMethods, "token_endpoint_auth_methods_supported")
		if err != nil {
			return err
		}

		tokenAuthnSigAlgs := slices.Concat(ctx.AuthnMethodPrivateKeyJWTSigAlgs, ctx.AuthnMethodSecretJWTSigAlgs)
		c.TokenAuthnSigAlg, err = resolveChoice(c.TokenAuthnSigAlgs, c.TokenAuthnSigAlg, tokenAuthnSigAlgs, "token_endpoint_auth_signing_alg_values_supported")
		if err != nil {
			return err
		}

		if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
			c.CIBAJARSigAlg, err = resolveChoice(c.CIBAJARSigAlgs, c.CIBAJARSigAlg, ctx.CIBAJARSigAlgs, "backchannel_authentication_request_signing_alg_values_supported")
			if err != nil {
				return err
			}
		} else {
			c.CIBAJARSigAlgs = nil
		}

		if ctx.JARMIsEnabled {
			c.JARMSigAlg, err = resolveChoice(c.JARMSigAlgs, c.JARMSigAlg, ctx.JARMSigAlgs, "authorization_signing_alg_values_supported")
			if err != nil {
				return err
			}

			if ctx.JARMEncIsEnabled {
				c.JARMKeyEncAlg, err = resolveChoice(c.JARMKeyEncAlgs, c.JARMKeyEncAlg, ctx.JARMKeyEncAlgs, "authorization_encryption_alg_values_supported")
				if err != nil {
					return err
				}

				c.JARMContentEncAlg, err = resolveChoice(c.JARMContentEncAlgs, c.JARMContentEncAlg, ctx.JARMContentEncAlgs, "authorization_encryption_enc_values_supported")
				if err != nil {
					return err
				}
			} else {
				c.JARMKeyEncAlgs = nil
				c.JARMContentEncAlgs = nil
			}

		} else {
			c.JARMSigAlgs = nil
			c.JARMKeyEncAlgs = nil
			c.JARMContentEncAlgs = nil
		}
	}

	for scopeID := range strings.FieldsSeq(c.ScopeIDs) {
		if !slices.ContainsFunc(ctx.Scopes, func(s goidc.Scope) bool { return s.ID == scopeID }) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("scope %s is not allowed", scopeID))
		}
	}

	if ctx.OpenIDIsRequired && c.ScopeIDs != "" && !strutil.ContainsOpenID(c.ScopeIDs) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			errors.New("scope openid is required"))
	}

	// [OIDC DCR 1.0 §2] grant_types defaults to ["authorization_code"] if omitted.
	if len(c.GrantTypes) == 0 && slices.Contains(ctx.GrantTypes, goidc.GrantAuthorizationCode) {
		c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	}
	// [OIDC DCR 1.0 §2] response_types defaults to ["code"] if omitted.
	if len(c.ResponseTypes) == 0 && slices.Contains(ctx.ResponseTypes, goidc.ResponseTypeCode) && slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	}

	if c.TokenAuthnMethod == "" {
		if ctx.AuthnMethodDefault == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata", errors.New("token_endpoint_auth_method is required"))
		}
		c.TokenAuthnMethod = ctx.AuthnMethodDefault
	}

	if !slices.Contains(ctx.AuthnMethods, c.TokenAuthnMethod) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("token_endpoint_auth_method %s is not allowed", c.TokenAuthnMethod))
	}

	switch c.TokenAuthnMethod {
	case goidc.AuthnMethodPrivateKeyJWT:
		if c.TokenAuthnSigAlg != "" && !slices.Contains(ctx.AuthnMethodPrivateKeyJWTSigAlgs, c.TokenAuthnSigAlg) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("token_endpoint_auth_signing_alg %s is not allowed", c.TokenAuthnSigAlg))
		}

		if c.JWKS == nil && c.JWKSURI == "" && (!ctx.OpenIDFedIsEnabled || c.SignedJWKSURI == "") {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("jwks or jwks_uri is required for private_key_jwt"))
		}
	case goidc.AuthnMethodSecretJWT:
		if c.TokenAuthnSigAlg != "" && !slices.Contains(ctx.AuthnMethodSecretJWTSigAlgs, c.TokenAuthnSigAlg) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("token_endpoint_auth_signing_alg %s is not allowed", c.TokenAuthnSigAlg))
		}
	case goidc.AuthnMethodSelfSignedTLS:
		if c.JWKSURI == "" && c.JWKS == nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("jwks or jwks_uri is required for self_signed_tls_client_auth"))
		}
		c.TokenAuthnSigAlg = ""
	case goidc.AuthnMethodTLS:
		numberOfIdentifiers := 0
		if c.TLSSubjectDistinguishedName != "" {
			numberOfIdentifiers++
		}
		if c.TLSSubjectAlternativeName != "" {
			numberOfIdentifiers++
		}
		if c.TLSSubjectAlternativeNameIP != "" {
			numberOfIdentifiers++
		}
		if numberOfIdentifiers != 1 {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("exactly one TLS client authentication identifier must be configured"))
		}
	}

	if c.TokenAuthnMethod != goidc.AuthnMethodPrivateKeyJWT && c.TokenAuthnMethod != goidc.AuthnMethodSecretJWT {
		c.TokenAuthnSigAlg = ""
	}

	if c.TokenAuthnMethod != goidc.AuthnMethodTLS {
		c.TLSSubjectDistinguishedName = ""
		c.TLSSubjectAlternativeName = ""
		c.TLSSubjectAlternativeNameIP = ""
	}

	if ctx.TokenIntrospectionIsEnabled {
		if c.TokenIntrospectionAuthnMethod != "" {
			if c.TokenIntrospectionAuthnMethod != c.TokenAuthnMethod {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("introspection_endpoint_auth_method must match token_endpoint_auth_method"))
			}

			switch c.TokenIntrospectionAuthnMethod {
			case goidc.AuthnMethodPrivateKeyJWT:
				if c.TokenIntrospectionAuthnSigAlg != "" && !slices.Contains(ctx.AuthnMethodPrivateKeyJWTSigAlgs, c.TokenIntrospectionAuthnSigAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("introspection_endpoint_auth_signing_alg %s is not allowed", c.TokenIntrospectionAuthnSigAlg))
				}
			case goidc.AuthnMethodSecretJWT:
				if c.TokenIntrospectionAuthnSigAlg != "" && !slices.Contains(ctx.AuthnMethodSecretJWTSigAlgs, c.TokenIntrospectionAuthnSigAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("introspection_endpoint_auth_signing_alg %s is not allowed", c.TokenIntrospectionAuthnSigAlg))
				}
			}

			if c.TokenIntrospectionAuthnMethod != goidc.AuthnMethodPrivateKeyJWT && c.TokenIntrospectionAuthnMethod != goidc.AuthnMethodSecretJWT {
				c.TokenIntrospectionAuthnSigAlg = ""
			}
		}
	} else {
		c.TokenIntrospectionAuthnMethod = ""
		c.TokenIntrospectionAuthnSigAlg = ""
	}

	if ctx.TokenRevocationIsEnabled {
		if c.TokenRevocationAuthnMethod != "" {
			if c.TokenRevocationAuthnMethod != c.TokenAuthnMethod {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("revocation_endpoint_auth_method must match token_endpoint_auth_method"))
			}

			switch c.TokenRevocationAuthnMethod {
			case goidc.AuthnMethodPrivateKeyJWT:
				if c.TokenRevocationAuthnSigAlg != "" && !slices.Contains(ctx.AuthnMethodPrivateKeyJWTSigAlgs, c.TokenRevocationAuthnSigAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("revocation_endpoint_auth_signing_alg %s is not allowed", c.TokenRevocationAuthnSigAlg))
				}
			case goidc.AuthnMethodSecretJWT:
				if c.TokenRevocationAuthnSigAlg != "" && !slices.Contains(ctx.AuthnMethodSecretJWTSigAlgs, c.TokenRevocationAuthnSigAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("revocation_endpoint_auth_signing_alg %s is not allowed", c.TokenRevocationAuthnSigAlg))
				}
			}

			if c.TokenRevocationAuthnMethod != goidc.AuthnMethodPrivateKeyJWT && c.TokenRevocationAuthnMethod != goidc.AuthnMethodSecretJWT {
				c.TokenRevocationAuthnSigAlg = ""
			}
		}
	} else {
		c.TokenRevocationAuthnMethod = ""
		c.TokenRevocationAuthnSigAlg = ""
	}

	for _, gt := range c.GrantTypes {
		if !slices.Contains(ctx.GrantTypes, gt) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("grant_type %s is not allowed", gt))
		}
	}

	if slices.Contains(c.GrantTypes, goidc.GrantClientCredentials) && c.TokenAuthnMethod == goidc.AuthnMethodNone {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			errors.New("client_credentials is not allowed for public clients"))
	}

	// [OIDC DCR 1.0 §2] application_type defaults to web.
	if c.ApplicationType == "" {
		c.ApplicationType = goidc.ApplicationTypeWeb
	}

	if !ctx.PARIsEnabled {
		c.PARIsRequired = false
	}

	if c.DefaultMaxAgeSecs != nil && *c.DefaultMaxAgeSecs < 0 {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			errors.New("default_max_age must not be negative"))
	}

	if c.IDTokenSigAlg == "" {
		c.IDTokenSigAlg = ctx.IDTokenDefaultSigAlg
	}
	if !slices.Contains(ctx.IDTokenSigAlgs, c.IDTokenSigAlg) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("id_token_signed_response_alg %s is not allowed", c.IDTokenSigAlg))
	}

	if ctx.IDTokenEncIsEnabled {
		if c.IDTokenContentEncAlg != "" && c.IDTokenKeyEncAlg == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("id_token_encrypted_response_alg is required when id_token_encrypted_response_enc is set"))
		}

		if c.IDTokenKeyEncAlg != "" {
			if !slices.Contains(ctx.IDTokenKeyEncAlgs, c.IDTokenKeyEncAlg) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("id_token_encrypted_response_alg %s is not allowed", c.IDTokenKeyEncAlg))
			}

			if c.IDTokenContentEncAlg == "" {
				c.IDTokenContentEncAlg = ctx.IDTokenDefaultContentEncAlg
			}

			if !slices.Contains(ctx.IDTokenContentEncAlgs, c.IDTokenContentEncAlg) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("id_token_encrypted_response_enc %s is not allowed", c.IDTokenContentEncAlg))
			}
		}
	} else {
		c.IDTokenKeyEncAlg = ""
		c.IDTokenContentEncAlg = ""
	}

	if c.UserInfoSigAlg != "" && !slices.Contains(ctx.UserInfoSigAlgs, c.UserInfoSigAlg) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("userinfo_signed_response_alg %s is not allowed", c.UserInfoSigAlg))
	}

	if ctx.UserInfoEncIsEnabled {
		if c.UserInfoContentEncAlg != "" && c.UserInfoKeyEncAlg == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("userinfo_encrypted_response_alg is required when userinfo_encrypted_response_enc is set"))
		}

		if c.UserInfoKeyEncAlg != "" {
			if !slices.Contains(ctx.UserInfoKeyEncAlgs, c.UserInfoKeyEncAlg) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("userinfo_encrypted_response_alg %s is not allowed", c.UserInfoKeyEncAlg))
			}

			if c.UserInfoContentEncAlg == "" {
				c.UserInfoContentEncAlg = ctx.UserInfoDefaultContentEncAlg
			}

			if !slices.Contains(ctx.UserInfoContentEncAlgs, c.UserInfoContentEncAlg) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("userinfo_encrypted_response_enc %s is not allowed", c.UserInfoContentEncAlg))
			}
		}
	} else {
		c.UserInfoKeyEncAlg = ""
		c.UserInfoContentEncAlg = ""
	}

	if ctx.JARIsEnabled {
		if c.JARSigAlg != "" && !slices.Contains(ctx.JARSigAlgs, c.JARSigAlg) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("request_object_signing_alg %s is not allowed", c.JARSigAlg))
		}

		if ctx.JAREncIsEnabled {
			if c.JARContentEncAlg != "" && c.JARKeyEncAlg == "" {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("request_object_encryption_alg is required when request_object_encryption_enc is set"))
			}

			if c.JARKeyEncAlg != "" {
				if !slices.Contains(ctx.JARKeyEncAlgs, c.JARKeyEncAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("request_object_encryption_alg %s is not allowed", c.JARKeyEncAlg))
				}

				if c.JARContentEncAlg != "" && !slices.Contains(ctx.JARContentEncAlgs, c.JARContentEncAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("request_object_encryption_enc %s is not allowed", c.JARContentEncAlg))
				}
			}
		} else {
			c.JARKeyEncAlg = ""
			c.JARContentEncAlg = ""
		}
	} else {
		c.JARIsRequired = false
		c.JARSigAlg = ""
		c.JARKeyEncAlg = ""
		c.JARContentEncAlg = ""
	}

	if ctx.JARMIsEnabled {
		if c.JARMSigAlg != "" && !slices.Contains(ctx.JARMSigAlgs, c.JARMSigAlg) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("authorization_signed_response_alg %s is not allowed", c.JARMSigAlg))
		}

		if ctx.JARMEncIsEnabled {
			if c.JARMContentEncAlg != "" && c.JARMKeyEncAlg == "" {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("authorization_encrypted_response_alg is required when authorization_encrypted_response_enc is set"))
			}

			if c.JARMKeyEncAlg != "" {
				if !slices.Contains(ctx.JARMKeyEncAlgs, c.JARMKeyEncAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("authorization_encrypted_response_alg %s is not allowed", c.JARMKeyEncAlg))
				}

				if c.JARMContentEncAlg == "" {
					c.JARMContentEncAlg = ctx.JARMContentEncAlgDefault
				}

				if !slices.Contains(ctx.JARMContentEncAlgs, c.JARMContentEncAlg) {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						fmt.Errorf("authorization_encrypted_response_enc %s is not allowed", c.JARMContentEncAlg))
				}
			}
		} else {
			c.JARMKeyEncAlg = ""
			c.JARMContentEncAlg = ""
		}
	} else {
		c.JARMSigAlg = ""
		c.JARMKeyEncAlg = ""
		c.JARMContentEncAlg = ""
	}

	for _, uri := range c.RedirectURIs {
		parsedURI, err := url.Parse(uri)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("a redirect_uri is invalid"))
		}

		if parsedURI.Fragment != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("redirect_uris must not contain fragments"))
		}

		switch c.ApplicationType {
		case goidc.ApplicationTypeNative:
			// RFC 8252: Native apps can use http loopback or private-use URI schemes.
			switch parsedURI.Scheme {
			case "http": // Loopback interface redirection.
				if ctx.LocalhostRedirectURIIsEnabled && parsedURI.Hostname() == "localhost" {
					continue
				} else if !strings.HasPrefix(parsedURI.Host, "127.") && parsedURI.Hostname() != "::1" {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						errors.New("http redirect_uris for native applications must use loopback addresses"))
				}
			case "https": // Claimed HTTPS URI Redirection.
				if strings.HasPrefix(parsedURI.Host, "127.") || parsedURI.Hostname() == "::1" {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						errors.New("https redirect_uris for native applications must not use loopback addresses"))
				}
			default: // Private-use URI Scheme Redirection.
				if !strings.Contains(parsedURI.Scheme, ".") {
					return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
						errors.New("custom redirect URI schemes must use reverse-domain notation"))
				}
			}
		default: // Default as web application type.
			if parsedURI.Scheme != "https" {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("redirect_uris for web applications must use https"))
			}
		}
	}

	if ctx.JARByReferenceIsEnabled {
		for _, ru := range c.RequestURIs {
			if err := validateURL("request_uri", ru); err != nil {
				return err
			}
		}
	} else {
		c.RequestURIs = nil
	}

	for _, rt := range c.ResponseTypes {
		if !slices.Contains(ctx.ResponseTypes, rt) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("response_type %s is not allowed", rt))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantImplicit) && rt.IsImplicit() {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("implicit response types require the implicit grant type"))
		}

		if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) && rt.Contains(goidc.ResponseTypeCode) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("code response types require the authorization_code grant type"))
		}
	}

	if c.JWKS != nil {
		if c.JWKSURI != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("jwks and jwks_uri must not both be present"))
		}
		for _, jwk := range c.JWKS.Keys {
			if !jwk.IsPublic() || !jwk.Valid() {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("the jwk with id %s is invalid", jwk.KeyID))
			}
		}
	}

	if c.JWKSURI != "" {
		if c.JWKS != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("jwks and jwks_uri must not both be present"))
		}
		if err := validateURL("jwks_uri", c.JWKSURI); err != nil {
			return err
		}
	}

	if c.SignedJWKSURI != "" {
		if err := validateURL("signed_jwks_uri", c.SignedJWKSURI); err != nil {
			return err
		}
	}

	if ctx.RARIsEnabled {
		for _, dt := range c.AuthDetailTypes {
			if !slices.Contains(ctx.RARDetailTypes, dt) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("authorization_detail type %s is not allowed", dt))
			}
		}
	} else {
		c.AuthDetailTypes = nil
	}

	if !ctx.DPoPIsEnabled {
		c.DPoPTokenBindingIsRequired = false
	}

	if !ctx.MTLSIsEnabled {
		c.TLSSubjectDistinguishedName = ""
		c.TLSSubjectAlternativeName = ""
		c.TLSSubjectAlternativeNameIP = ""
		c.TLSTokenBindingIsRequired = false
	}

	if !ctx.VCIsEnabled {
		c.CredentialOfferEndpoint = ""
	}

	if c.LogoURI != "" {
		if err := validateURL("logo_uri", c.LogoURI); err != nil {
			return err
		}
	}

	if c.PolicyURI != "" {
		if err := validateURL("policy_uri", c.PolicyURI); err != nil {
			return err
		}
	}

	if c.TermsOfServiceURI != "" {
		if err := validateURL("tos_uri", c.TermsOfServiceURI); err != nil {
			return err
		}
	}

	if ctx.LogoutIsEnabled {
		for _, uri := range c.PostLogoutRedirectURIs {
			if err := validateURL("post_logout_redirect_uris", uri); err != nil {
				return err
			}
		}
	} else {
		c.PostLogoutRedirectURIs = nil
	}

	if c.SubIdentifierType == "" {
		c.SubIdentifierType = ctx.SubIdentifierTypeDefault
	}
	if !slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("subject_type %s is not allowed", c.SubIdentifierType))
	}

	if c.SubIdentifierType == goidc.SubIdentifierPairwise {
		// When the sector identifier uri is not provided, and the client is using
		// the authorization code or implicit grant types, it is necessary to enforce
		// restrictions on redirect uris.
		//
		// The logic performs the following steps:
		// 1. Check if sector_identifier_uri is empty and if the client uses the authorization code or implicit grant type.
		// 2. Extract the host component of each redirect uri, ensuring no duplicates.
		// 3. Verify that all redirect uris share the same host as this violates the requirements for pairwise sub identifiers without a sector identifier uri.
		if c.SectorIdentifierURI == "" && slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
			return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
		}) {
			var hosts []string
			for _, ru := range c.RedirectURIs {
				if parsed, _ := url.Parse(ru); !slices.Contains(hosts, parsed.Host) {
					hosts = append(hosts, parsed.Host)
				}
			}
			if len(hosts) != 1 {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("all redirect_uris must share the same host when using pairwise subject identifiers without sector_identifier_uri"))
			}
		}
	}

	if slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
		if c.TokenAuthnMethod == goidc.AuthnMethodNone {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("token_endpoint_auth_method none is not allowed for ciba"))
		}

		if c.CIBATokenDeliveryMode == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				errors.New("backchannel_token_delivery_mode is required"))
		}

		if !slices.Contains(ctx.CIBATokenDeliveryModes, c.CIBATokenDeliveryMode) {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("backchannel_token_delivery_mode %s is not allowed", c.CIBATokenDeliveryMode))
		}

		if c.CIBATokenDeliveryMode.IsNotificationMode() {
			if c.CIBANotificationEndpoint == "" {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("backchannel_client_notification_endpoint is required for ping and push delivery modes"))
			}

			if err := validateURL("backchannel_client_notification_endpoint", c.CIBANotificationEndpoint); err != nil {
				return err
			}
		} else {
			c.CIBANotificationEndpoint = ""
		}

		if !ctx.CIBAUserCodeIsEnabled {
			c.CIBAUserCodeIsEnabled = false
		}

		if ctx.CIBAJARIsEnabled {
			if c.CIBAJARSigAlg != "" && !slices.Contains(ctx.CIBAJARSigAlgs, c.CIBAJARSigAlg) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("backchannel_authentication_request_signing_alg %s is not allowed", c.CIBAJARSigAlg))
			}
		} else {
			c.CIBAJARSigAlg = ""
		}

		// For pairwise subjects, if the CIBA grant type is used with non-push modes, jwks_uri is required.
		// Also, make sure jwks_uri ownership will be validated at the /bc-authorize
		// endpoint via one of these methods:
		//    - private_key_jwt for token authentication.
		//    - self_signed_tls_client_auth for token authentication.
		//    - Usage of signed request objects.
		if c.SubIdentifierType == goidc.SubIdentifierPairwise && c.CIBATokenDeliveryMode != goidc.CIBADeliveryModePush {
			if c.JWKSURI == "" {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("jwks_uri is required for ciba with non-push delivery modes when using pairwise subject identifiers"))
			}

			jwksURIOwnershipIsGuaranteed := func() bool {
				if c.TokenAuthnMethod == goidc.AuthnMethodPrivateKeyJWT {
					return true
				}

				if c.TokenAuthnMethod == goidc.AuthnMethodSelfSignedTLS {
					return true
				}

				if c.CIBAJARSigAlg != "" {
					return true
				}

				return false
			}()
			if !jwksURIOwnershipIsGuaranteed {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					errors.New("the client must demonstrate control of jwks_uri when using pairwise subject identifiers"))
			}
		}
	} else {
		c.CIBATokenDeliveryMode = ""
		c.CIBANotificationEndpoint = ""
		c.CIBAJARSigAlg = ""
		c.CIBAUserCodeIsEnabled = false
		c.CIBAJARSigAlgs = nil
	}

	if c.SectorIdentifierURI != "" {
		if err := validateURL("sector_identifier_uri", c.SectorIdentifierURI); err != nil {
			return err
		}

		resp, err := ctx.HTTPClient().Get(c.SectorIdentifierURI)
		if err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata", err)
		}
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("fetching sector_identifier_uri returned status %d", resp.StatusCode))
		}

		var uris []string
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseByteSize)).Decode(&uris); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata", err)
		}

		var wantedURIs []string
		if slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
			return gt == goidc.GrantAuthorizationCode || gt == goidc.GrantImplicit
		}) {
			wantedURIs = append(wantedURIs, c.RedirectURIs...)
		}

		if slices.Contains(c.GrantTypes, goidc.GrantCIBA) {
			if c.CIBATokenDeliveryMode == goidc.CIBADeliveryModePush {
				wantedURIs = append(wantedURIs, c.CIBANotificationEndpoint)
			} else if c.JWKSURI != "" {
				wantedURIs = append(wantedURIs, c.JWKSURI)
			}
		}

		for _, uri := range wantedURIs {
			if !slices.Contains(uris, uri) {
				return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
					fmt.Errorf("the uri %s is not listed in sector_identifier_uri", uri))
			}
		}
	}

	return nil
}

// resolveChoice resolves a choices list against a current singular value and server-supported values.
// If both choices and current are set, current must be in the choices list.
// If only choices are set, returns the first value from choices that the server supports.
// If no overlap is found and the server supports the feature (non-empty supported), returns an error.
func resolveChoice[T comparable](choices []T, current T, supported []T, fieldName string) (T, error) {
	var zero T
	if len(choices) == 0 {
		return current, nil
	}

	if current != zero {
		if !slices.Contains(choices, current) {
			return zero, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
				fmt.Errorf("%s is not in the client's declared list", fieldName))
		}
		if slices.Contains(supported, current) {
			return current, nil
		}
	}

	for _, choice := range choices {
		if slices.Contains(supported, choice) {
			return choice, nil
		}
	}

	return zero, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
		fmt.Errorf("no allowed value found in %s", fieldName))
}

func validateURL(field, s string) error {
	parsedRU, err := url.Parse(s)
	if err != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("could not parse %s", field))
	}

	if parsedRU.Scheme != "https" || parsedRU.Host == "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid client metadata",
			fmt.Errorf("%s with value %s is invalid", field, s))
	}

	return nil
}
