package token

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidatePoP_NoConfirmation(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{}

	// When.
	err := ValidatePoP(ctx, "random_token", cnf)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateTLSPoP_NoThumbprint(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{}

	// When.
	err := validateTLSPoP(ctx, cnf)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateTLSPoP_NoCert(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
		return nil, errors.New("no cert")
	}
	cnf := goidc.TokenConfirmation{
		CertThumbprint: "random_thumbprint",
	}

	// When.
	err := validateTLSPoP(ctx, cnf)

	// Then.
	if err == nil {
		t.Fatal("expected error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidToken {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
	}
}

func TestValidateTLSPoP_ThumbprintMismatch(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	certRaw := []byte("test_cert_raw_data")
	ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
		return &x509.Certificate{Raw: certRaw}, nil
	}
	cnf := goidc.TokenConfirmation{
		CertThumbprint: "wrong_thumbprint",
	}

	// When.
	err := validateTLSPoP(ctx, cnf)

	// Then.
	if err == nil {
		t.Fatal("expected error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidToken {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
	}
}

func TestValidateTLSPoP_ValidCert(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	certRaw := []byte("test_cert_raw_data")
	ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
		return &x509.Certificate{Raw: certRaw}, nil
	}
	cnf := goidc.TokenConfirmation{
		CertThumbprint: hashutil.Thumbprint(string(certRaw)),
	}

	// When.
	err := validateTLSPoP(ctx, cnf)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateDPoP_NoThumbprint(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{}

	// When.
	err := validateDPoP(ctx, "random_token", cnf)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateDPoP_MissingHeader(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	cnf := goidc.TokenConfirmation{
		JWKThumbprint: "random_thumbprint",
	}

	// When.
	err := validateDPoP(ctx, "random_token", cnf)

	// Then.
	if err == nil {
		t.Fatal("expected error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeUnauthorizedClient {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeUnauthorizedClient)
	}
}
