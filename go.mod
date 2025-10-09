module github.com/luikyv/go-oidc

go 1.24.0

toolchain go1.24.2

require (
	github.com/go-jose/go-jose/v4 v4.1.3
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	golang.org/x/crypto v0.42.0
)

// TODO: remove examples/cli, that brings this dependency in,
// once device auth grant is merged, since a sample of the
// code is already included in README.md
require golang.org/x/oauth2 v0.32.0 // indirect
